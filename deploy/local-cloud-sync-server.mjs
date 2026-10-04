#!/usr/bin/env node
import { randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import { accountPayload, buildPlan, buildState, configFingerprint, fingerprint,
  groupPayload, isSyncTransition, selectAccounts } from './sync-local-to-cloud-core.mjs'
import { Client, perform, readState, saveState } from './sync-local-to-cloud.mjs'

const host = '127.0.0.1'
const port = 8769
const localBase = 'http://127.0.0.1:8080'
const cloudBase = 'https://api.zynexus.top'
const allowedOrigins = new Set(['http://127.0.0.1:8080', 'http://localhost:8080'])
let applying = false
const previews = new Map()
const previewTTL = 10 * 60 * 1000
const localAccountFields = new Set([
  'credentials.model_mapping', 'groups', 'extra.auto_reset_credit_enabled',
  'extra.auto_reset_credit_5h_threshold', 'extra.auto_reset_credit_7d_threshold'
])

function reply(response, status, data, origin) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Vary': 'Origin',
    ...(origin ? { 'Access-Control-Allow-Origin': origin } : {})
  })
  response.end(JSON.stringify(data))
}

async function readBody(request) {
  let content = ''
  for await (const chunk of request) {
    content += chunk
    if (content.length > 16384) throw new Error('Request is too large')
  }
  return JSON.parse(content)
}

function validateInput(body, apply) {
  const ids = body?.accountIds
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > 100 ||
      ids.some(id => !Number.isSafeInteger(id) || id < 1) ||
      new Set(ids).size !== ids.length) {
    throw new Error('Select 1 to 100 distinct local account IDs')
  }
  if (!apply && (typeof body.cloudEmail !== 'string' || body.cloudEmail.length > 254 ||
      typeof body.cloudPassword !== 'string' || !body.cloudPassword ||
      body.cloudPassword.length > 4096 ||
      !/^\d{6}$/.test(body.cloudCode ?? ''))) {
    throw new Error('Cloud administrator email, password, and six-digit 2FA code are required')
  }
  if (apply && (!/^[a-f0-9]{64}$/.test(body.expectedPlan ?? '') ||
      !/^[0-9a-f-]{36}$/.test(body.previewTicket ?? ''))) {
    throw new Error('A valid preview is required before syncing')
  }
  for (const field of ['localCode', 'expectedPlan']) {
    if (body[field] !== undefined && typeof body[field] !== 'string') {
      throw new Error(`Invalid ${field}`)
    }
  }
  if (body.localCode && !/^\d{6}$/.test(body.localCode)) {
    throw new Error('Local 2FA code must have six digits')
  }
  if (body.takeLocal === true) {
    throw new Error('Conflict override is disabled for Web sync. Resolve conflicts before syncing')
  }
  return ids
}

function makePrompt(body) {
  return async label => {
    if (label.includes('email')) return body.cloudEmail.trim()
    if (label.includes('password')) return body.cloudPassword
    if (label.includes('2FA code')) return body.cloudCode
    throw new Error('Unexpected cloud login prompt')
  }
}

function planDigest(plan) {
  return fingerprint(plan.map(row => ({
    kind: row.kind, identity: row.item.identity, action: row.action,
    localId: row.item.id, remoteId: row.remote?.id ?? null,
    localHash: row.sourceHash, remoteHash: row.remoteHash ?? null
  })))
}

function groupNames(identities = []) {
  return identities.map(identity => identity.split('\u0000').slice(1).join(' / '))
}

function safeSettingDifferences(row) {
  if (row.kind !== 'accounts' || !row.remote) return []
  const details = []
  if (row.differences.includes('credentials.model_mapping')) {
    const local = row.item.config.credentials?.model_mapping ?? {}
    const cloud = row.remote.config.credentials?.model_mapping ?? {}
    for (const model of new Set([...Object.keys(local), ...Object.keys(cloud)])) {
      if (fingerprint(local[model]) !== fingerprint(cloud[model])) {
        details.push({ field: `model_mapping.${model}`,
          local: local[model] ?? null, cloud: cloud[model] ?? null })
      }
    }
  }
  for (const field of ['auto_reset_credit_enabled', 'auto_reset_credit_5h_threshold',
    'auto_reset_credit_7d_threshold']) {
    if (row.differences.includes(`extra.${field}`)) {
      details.push({ field, local: row.item.config.extra?.[field] ?? null,
        cloud: row.remote.config.extra?.[field] ?? null })
    }
  }
  return details
}

function buildWebPlan(source, target, state) {
  return buildPlan(source, target, state).map(row =>
    row.kind === 'accounts' && row.action === 'conflict' &&
      row.differences.length > 0 &&
      row.differences.every(field => localAccountFields.has(field))
      ? { ...row, action: 'update' } : row)
}

async function rollbackCreates(cloud, before, attempted, created) {
  const beforeIdentities = Object.fromEntries(['groups', 'accounts'].map(kind =>
    [kind, new Set(before[kind].map(item => item.identity))]))
  const sourceIdentities = Object.fromEntries(['groups', 'accounts'].map(kind =>
    [kind, new Set(attempted.filter(item => item.kind === kind).map(item => item.identity))]))
  let current
  try {
    current = await cloud.snapshot()
  } catch {
    current = null
  }
  const ids = { groups: new Set(), accounts: new Set() }
  for (const entry of created) ids[entry.kind].add(entry.id)
  if (current) {
    for (const kind of ['groups', 'accounts']) {
      for (const item of current[kind]) {
        if (sourceIdentities[kind].has(item.identity) &&
            !beforeIdentities[kind].has(item.identity)) ids[kind].add(item.id)
      }
    }
  }
  const failures = []
  for (const kind of ['accounts', 'groups']) {
    for (const id of ids[kind]) {
      try { await cloud.delete(`/admin/${kind}/${id}`) }
      catch { failures.push(`${kind} ${id}`) }
    }
  }
  if (failures.length) throw new Error(`Rollback could not remove ${failures.join(', ')}`)
  const after = await cloud.snapshot()
  for (const kind of ['groups', 'accounts']) {
    if (after[kind].some(item => sourceIdentities[kind].has(item.identity) &&
        !beforeIdentities[kind].has(item.identity))) {
      throw new Error('Rollback verification found newly created records')
    }
  }
}

async function rollbackUpdates(cloud, updated) {
  const failures = []
  for (const row of [...updated].reverse()) {
    try {
      // Re-read runtime values; never restore a pre-sync OAuth token snapshot.
      const current = await cloud.snapshot()
      const remote = current[row.kind].find(item => item.id === row.remote.id &&
        item.identity === row.remote.identity)
      if (!remote) throw new Error('record was removed or replaced')
      const hash = configFingerprint(row.kind, remote.config)
      const beforeHash = configFingerprint(row.kind, row.remote.config)
      if (hash === beforeHash) continue
      if (!isSyncTransition(row.kind, remote.config, row.remote.config, row.item.config)) {
        throw new Error('configuration changed independently; automatic restore stopped')
      }
      const payload = row.kind === 'groups' ? groupPayload(row.remote.config)
        : accountPayload(row.remote.config,
          new Map(current.groups.map(item => [item.identity, item])), remote)
      if (row.kind === 'accounts' && row.remote.config.status === remote.config.status) {
        delete payload.status
      }
      await cloud.put(`/admin/${row.kind}/${row.remote.id}`, payload)
    } catch (error) {
      failures.push(`${row.kind} ${row.remote.id}: ${error.message}`)
    }
  }
  const after = await cloud.snapshot()
  for (const row of updated) {
    const restored = after[row.kind].find(item => item.id === row.remote.id &&
      item.identity === row.remote.identity)
    if (!restored || configFingerprint(row.kind, restored.config) !==
        configFingerprint(row.kind, row.remote.config)) {
      failures.push(`${row.kind} ${row.remote.id}: restore verification failed`)
    }
  }
  if (failures.length) throw new Error(failures.join('; '))
}

export async function syncRequest(body, localToken, apply = false,
  stateStore = { read: readState, save: saveState }) {
  const ids = validateInput(body, apply)
  const local = new Client(localBase, 'Local', async () => {
    if (!body.localCode) throw new Error('Local account export needs a fresh 2FA code')
    return body.localCode
  },
    { includeOAuth: true, includeKeys: false })
  local.token = localToken
  const user = await local.get('/auth/me')
  if (user?.role !== 'admin') throw new Error('Local administrator session required')

  const cloud = new Client(cloudBase, 'Cloud', makePrompt(body),
    { includeOAuth: true, includeKeys: false })
  let session
  if (apply) {
    session = previews.get(body.previewTicket)
    if (!session || session.expiresAt < Date.now() ||
        session.localTokenHash !== fingerprint(localToken) ||
        session.digest !== body.expectedPlan ||
        session.ids.length !== ids.length ||
        session.ids.some((id, index) => id !== ids[index])) {
      throw new Error('Preview expired or does not match this session. Preview again before syncing')
    }
    previews.delete(body.previewTicket)
    cloud.token = session.cloudToken
  } else {
    await cloud.login()
  }
  await cloud.verifyCloudProtection()
  const source = selectAccounts(await local.snapshot(), ids)
  const target = await cloud.snapshot()
  const state = await stateStore.read()
  const plan = buildWebPlan(source, target, state)
  const digest = planDigest(plan)
  const rows = plan.map(row => ({
    kind: row.kind, action: row.action, label: row.item.label,
    localId: row.item.id, differences: row.differences, ignored: row.ignored,
    settingDifferences: safeSettingDifferences(row),
    ...(row.kind === 'accounts' && row.remote && row.differences.includes('groups')
      ? { groupDifference: {
        local: groupNames(row.item.config.groups),
        cloud: groupNames(row.remote.config.groups)
      } } : {})
  }))
  if (!apply) {
    const previewTicket = randomUUID()
    for (const [ticket, saved] of previews) {
      if (saved.expiresAt < Date.now()) previews.delete(ticket)
    }
    previews.set(previewTicket, { cloudToken: cloud.token,
      localTokenHash: fingerprint(localToken), ids, digest,
      expiresAt: Date.now() + previewTTL })
    return { plan: rows, digest, cloud: cloudBase,
      previewTicket }
  }
  if (!/^[a-f0-9]{64}$/.test(body.expectedPlan ?? '') || body.expectedPlan !== digest) {
    throw new Error('Configuration changed since preview. Preview again before syncing')
  }
  if (plan.some(row => row.action === 'conflict')) {
    throw new Error('Sync cancelled: unsupported account or group configuration conflict. No changes were written')
  }
  const freshTarget = await cloud.snapshot()
  const freshPlan = buildWebPlan(source, freshTarget, state)
  if (planDigest(freshPlan) !== digest) {
    throw new Error('Cloud configuration changed during sync. No changes were written; preview again')
  }
  const created = []
  const updated = []
  const attempted = []
  try {
    await perform(cloud, freshPlan, freshTarget, entry => created.push(entry),
      row => updated.push(row), entry => attempted.push(entry))
    const verified = await cloud.snapshot()
    await cloud.verifyCloudProtection()
    const nextState = buildState(source, verified)
    const expected = source.groups.length + source.accounts.length
    const actual = Object.keys(nextState.groups).length + Object.keys(nextState.accounts).length
    if (actual !== expected) {
      const differences = buildPlan(source, verified, state)
        .filter(row => row.action !== 'skip')
        .slice(0, 8)
        .map(row => `${row.kind} ${row.item.label}: ${row.differences.join(', ') || row.action}`)
      throw new Error(`Cloud verification differs for ${expected - actual} record(s): ${differences.join('; ')}`)
    }
    const selected = new Set(source.accounts.map(item => item.identity))
    const privacy = {}
    for (const account of verified.accounts.filter(item => selected.has(item.identity))) {
      if (account.config.platform !== 'openai' || account.config.type !== 'oauth') continue
      const status = account.runtimeExtra.privacy_mode ?? 'unknown'
      privacy[status] = (privacy[status] ?? 0) + 1
    }
    await stateStore.save({ version: 1,
      groups: { ...state.groups, ...nextState.groups },
      accounts: { ...state.accounts, ...nextState.accounts },
      keys: state.keys ?? {},
      lastSync: { at: new Date().toISOString(),
        groupsCreated: freshPlan.filter(row => row.kind === 'groups' && row.action === 'create').length,
        accountsCreated: freshPlan.filter(row => row.kind === 'accounts' && row.action === 'create').length,
        privacy } })
    return { plan: rows, cloud: cloudBase, verified: true, privacy }
  } catch (error) {
    try {
      // Restore existing group bindings before removing new groups/accounts.
      // If independent changes prevent restoration, retain dependencies and
      // report the unresolved rollback instead of deleting them.
      await rollbackUpdates(cloud, updated)
      await rollbackCreates(cloud, freshTarget, attempted, created)
    } catch (rollbackError) {
      throw new Error(`${error.message}; rollback needs attention: ${rollbackError.message}`)
    }
    throw new Error(`${error.message}; ${updated.length ? 'updated and newly created' : 'newly created'} cloud records were rolled back and verified`)
  }
}

export function createSyncServer() {
  return createServer(async (request, response) => {
    const origin = request.headers.origin
    if (request.headers.host !== `${host}:${request.socket.localPort}`) {
      reply(response, 403, { error: 'Invalid host' })
      return
    }
    if (request.method === 'GET' && request.url === '/health') {
      reply(response, 200, { status: 'ok', service: 'sub2api-local-cloud-sync' })
      return
    }
    if (!allowedOrigins.has(origin)) {
      reply(response, 403, { error: 'This operation is available only from the local Web UI' })
      return
    }
    if (request.method === 'OPTIONS') {
      response.writeHead(204, { 'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        'Cache-Control': 'no-store', 'Vary': 'Origin' })
      response.end()
      return
    }
    if (request.method !== 'POST' || !['/preview', '/apply'].includes(request.url) ||
        !request.headers['content-type']?.startsWith('application/json')) {
      reply(response, 404, { error: 'Unknown operation' }, origin)
      return
    }
    const localToken = request.headers.authorization?.match(/^Bearer (\S+)$/)?.[1]
    if (!localToken) {
      reply(response, 401, { error: 'Local administrator login required' }, origin)
      return
    }
    if (request.url === '/apply' && applying) {
      reply(response, 409, { error: 'A sync is already running' }, origin)
      return
    }
    const isApply = request.url === '/apply'
    if (isApply) applying = true
    try {
      const result = await syncRequest(await readBody(request), localToken, isApply)
      reply(response, 200, result, origin)
    } catch (error) {
      reply(response, 400, { error: error.message }, origin)
    } finally {
      if (isApply) applying = false
    }
  })
}

if (process.argv[1] && process.argv[1].toLowerCase().endsWith('local-cloud-sync-server.mjs')) {
  createSyncServer().listen(port, host, () => {
    console.log(`Local cloud sync ready on http://${host}:${port}`)
  })
}
