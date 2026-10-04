#!/usr/bin/env node
import { readFile, rename, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { buildPlan, buildState, normalizeSnapshot, accountPayload,
  groupPayload, keyPayload, selectAccounts } from './sync-local-to-cloud-core.mjs'

const statePath = fileURLToPath(new URL('./.sync-state.json', import.meta.url))
const args = process.argv.slice(2)
const apply = args.includes('--apply')
const includeOAuth = args.includes('--include-oauth')
const onlyAccountID = args.includes('--only-account-id') ? Number(option('--only-account-id')) : null
const onlyAccountIDs = args.includes('--only-account-ids')
  ? option('--only-account-ids').split(',').map(Number) : null
if (onlyAccountID !== null && (!Number.isSafeInteger(onlyAccountID) || onlyAccountID < 1)) {
  throw new Error('--only-account-id requires a positive integer')
}
if (onlyAccountIDs && (onlyAccountID !== null || !onlyAccountIDs.length ||
    onlyAccountIDs.some(id => !Number.isSafeInteger(id) || id < 1) ||
    new Set(onlyAccountIDs).size !== onlyAccountIDs.length)) {
  throw new Error('--only-account-ids requires distinct positive integers and cannot be combined with --only-account-id')
}
const localURL = option('--local', 'http://127.0.0.1:8080')
const cloudURL = option('--cloud', 'https://api.zynexus.top')

function option(name, fallback) {
  const index = args.indexOf(name)
  if (index < 0) return fallback
  if (!args[index + 1]) throw new Error(`${name} requires a URL`)
  return args[index + 1]
}

function validateURL(value, cloud) {
  const url = new URL(value)
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('URLs must contain only a scheme, host, and optional port')
  }
  if (cloud ? url.protocol !== 'https:' :
    (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))) {
    throw new Error(cloud ? 'Cloud URL must use HTTPS' : 'Local URL must use loopback HTTP')
  }
  return url.origin
}

let inputInterface
let writeToOutput

export function ask(label, hidden = false) {
  if (!process.stdin.isTTY) throw new Error('Run this command in an interactive terminal')
  if (!inputInterface) {
    inputInterface = createInterface({ input: process.stdin, output: process.stdout,
      crlfDelay: Infinity })
    writeToOutput = inputInterface._writeToOutput.bind(inputInterface)
  }
  return new Promise(resolve => {
    if (hidden) {
      process.stdout.write(label)
      inputInterface._writeToOutput = function (text) {
        if (text === '\r\n' || text === '\n') process.stdout.write(text)
      }
    } else {
      inputInterface._writeToOutput = writeToOutput
    }
    inputInterface.question(hidden ? '' : label, answer => {
      if (hidden) process.stdout.write('\n')
      resolve(answer.trim())
    })
  })
}

function closeInput() {
  inputInterface?.close()
  inputInterface = undefined
}

export class Client {
  constructor(base, name, prompt = ask, options = {}) {
    this.base = base
    this.name = name
    this.token = ''
    this.prompt = prompt
    this.includeOAuth = options.includeOAuth ?? includeOAuth
    this.includeKeys = options.includeKeys ?? true
  }

  async request(method, path, body) {
    const response = await fetch(`${this.base}/api/v1${path}`, {
      method, redirect: 'error', signal: AbortSignal.timeout(30000),
      headers: { ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body)
    })
    const result = await response.json().catch(() => null)
    if (!response.ok || result?.code !== 0) {
      const error = new Error(`${this.name} ${method} ${path.split('?')[0]}: HTTP ${response.status}`)
      error.status = response.status
      throw error
    }
    return result.data
  }

  get(path) { return this.request('GET', path) }
  post(path, body) { return this.request('POST', path, body) }
  put(path, body) { return this.request('PUT', path, body) }
  delete(path) { return this.request('DELETE', path) }

  async login() {
    const email = await this.prompt(`${this.name} admin email: `)
    const password = await this.prompt(`${this.name} password: `, true)
    let result = await this.post('/auth/login', { email, password })
    if (this.name === 'Cloud' && !result.requires_2fa) {
      throw new Error('Cloud administrator TOTP login is required before sync')
    }
    if (result.requires_2fa) {
      const totpCode = await this.prompt(`${this.name} login 2FA code: `, true)
      result = await this.post('/auth/login/2fa', { temp_token: result.temp_token, totp_code: totpCode })
    }
    if (result.user?.role !== 'admin' || !result.access_token) throw new Error(`${this.name} administrator login required`)
    this.token = result.access_token
    return result.user
  }

  async stepUp() {
    const code = await this.prompt(`${this.name} fresh step-up 2FA code: `, true)
    const result = await this.post('/user/totp/step-up', { code })
    if (result?.verified !== true) throw new Error(`${this.name} step-up 2FA was not verified`)
  }

  async verifyCloudProtection() {
    const [settings, status] = await Promise.all([
      this.get('/admin/settings'), this.get('/user/totp/status')
    ])
    if (settings?.totp_enabled !== true || settings?.step_up_enabled !== true ||
        settings?.totp_encryption_key_configured !== true ||
        status?.enabled !== true || status?.feature_enabled !== true) {
      throw new Error('Cloud administrator TOTP or sensitive-operation protection is disabled; sync stopped')
    }
  }

  async exportAccounts() {
    const path = `/admin/accounts/data?include_proxies=false${this.includeOAuth ? '' : '&type=apikey'}`
    try {
      return await this.get(path)
    } catch (error) {
      if (error.status !== 403) throw error
      await this.stepUp()
      return this.get(path)
    }
  }

  async pages(path) {
    const items = []
    for (let page = 1; ; page++) {
      const separator = path.includes('?') ? '&' : '?'
      const data = await this.get(`${path}${separator}page=${page}&page_size=100`)
      items.push(...data.items)
      if (items.length >= data.total) return items
      if (page > 1000 || data.items.length === 0) throw new Error(`Pagination failed for ${path}`)
    }
  }

  async snapshot() {
    const groups = await this.get('/admin/groups/all?include_inactive=true')
    const accounts = await this.pages('/admin/accounts')
    const keys = this.includeKeys ? await this.pages('/keys') : []
    const accountData = await this.exportAccounts()
    return { ...normalizeSnapshot({ groups, accounts, accountData, keys }),
      skippedOAuth: this.includeOAuth ? 0 : accounts.filter(account => account.type === 'oauth').length }
  }
}

export async function readState() {
  try {
    const state = JSON.parse(await readFile(statePath, 'utf8'))
    if (state.version !== 1) throw new Error('Unsupported sync state version')
    return state
  } catch (error) {
    if (error.code === 'ENOENT') return {}
    throw error
  }
}

export async function saveState(state) {
  const temp = `${statePath}.tmp`
  await writeFile(temp, JSON.stringify(state, null, 2), { mode: 0o600 })
  await rename(temp, statePath)
}

function showPlan(plan, source) {
  for (const kind of ['groups', 'accounts', 'keys']) {
    const rows = plan.filter(row => row.kind === kind)
    const counts = Object.fromEntries(['create', 'update', 'skip', 'conflict'].map(action =>
      [action, rows.filter(row => row.action === action).length]))
    console.log(`${kind}: ${JSON.stringify(counts)}`)
    for (const row of rows.filter(row => row.action !== 'skip')) {
      console.log(`  ${row.action}: ${row.item.label}`)
    }
  }
  if (source.skippedShadows) console.log(`Skipped shadow accounts: ${source.skippedShadows}`)
  if (source.skippedOAuth) console.log(`OAuth accounts excluded by default: ${source.skippedOAuth}`)
  const proxyCount = source.accounts.filter(account => account.localProxyIgnored).length
  if (proxyCount) console.log(`Machine-specific local proxy bindings ignored: ${proxyCount}`)
}

export async function perform(client, plan, target, onCreated = () => {},
  onUpdating = () => {}, onCreating = () => {}) {
  if (plan.some(row => row.action === 'conflict')) {
    throw new Error('Configuration conflicts; sync cancelled before any write')
  }
  const groups = new Map(target.groups.map(item => [item.identity, item]))
  for (const row of plan.filter(row => row.kind === 'groups' && row.action !== 'skip')) {
    const payload = groupPayload(row.item.config)
    if (row.action === 'update') onUpdating(row)
    if (row.action === 'create') onCreating({ kind: row.kind, identity: row.item.identity })
    const result = row.action === 'create'
      ? await client.post('/admin/groups', payload)
      : await client.put(`/admin/groups/${row.remote.id}`, payload)
    if (row.action === 'create') onCreated({ kind: 'groups', id: result.id })
    if (row.action === 'create' && payload.status === 'inactive') {
      await client.put(`/admin/groups/${result.id}`, { status: 'inactive' })
    }
    groups.set(row.item.identity, { id: result.id })
    console.log(`Synced group: ${row.item.label}`)
  }
  for (const row of plan.filter(row => row.kind === 'accounts' && row.action !== 'skip')) {
    const payload = accountPayload(row.item.config, groups, row.remote)
    if (row.action === 'create' || row.item.config.status === row.remote.config.status) {
      delete payload.status
    }
    if (row.action === 'update') onUpdating(row)
    if (row.action === 'create') onCreating({ kind: row.kind, identity: row.item.identity })
    const result = row.action === 'create'
      ? await client.post('/admin/accounts', payload)
      : await client.put(`/admin/accounts/${row.remote.id}`, payload)
    if (row.action === 'create') onCreated({ kind: 'accounts', id: result.id })
    if (row.action === 'create' && row.item.config.status === 'inactive') {
      await client.put(`/admin/accounts/${result.id}`, { status: 'inactive' })
    }
    console.log(`Synced upstream account: ${row.item.label}`)
  }
  for (const row of plan.filter(row => row.kind === 'keys' && row.action !== 'skip')) {
    const payload = keyPayload(row.item.config, groups)
    if (row.action === 'create' ? row.item.config.status === 'active' :
      row.item.config.status === row.remote.config.status) {
      delete payload.status
    }
    let id = row.remote?.id
    if (row.action === 'create') {
      const result = await client.post('/keys', { ...payload, custom_key: row.item.config.key,
        status: undefined, expires_at: undefined })
      id = result.id
    }
    await client.put(`/keys/${id}`, payload)
    if (row.action === 'create' || row.item.config.group !== row.remote.config.group) {
      const group = row.item.config.group && groups.get(row.item.config.group)
      await client.put(`/admin/api-keys/${id}`, { group_id: group?.id ?? 0 })
    }
    console.log(`Synced API Key: ${row.item.label}`)
  }
}

async function main() {
  if (args.includes('--help')) {
    console.log('node deploy/sync-local-to-cloud.mjs [--apply] [--include-oauth] [--only-account-id ID | --only-account-ids ID,ID] [--cloud https://host]')
    console.log('Default: preview only. Conflicts cancel the entire sync before any write.')
    return
  }
  if (args.includes('--take-local')) {
    throw new Error('--take-local is disabled; resolve cloud conflicts before syncing')
  }
  const local = new Client(validateURL(localURL, false), 'Local')
  const cloud = new Client(validateURL(cloudURL, true), 'Cloud')
  await local.login()
  await cloud.login()
  await cloud.verifyCloudProtection()
  const localSnapshot = await local.snapshot()
  const selectedIDs = onlyAccountIDs ?? (onlyAccountID === null ? null : [onlyAccountID])
  const source = selectedIDs === null ? localSnapshot : selectAccounts(localSnapshot, selectedIDs)
  const target = await cloud.snapshot()
  const state = await readState()
  const plan = buildPlan(source, target, state)
  showPlan(plan, source)
  if (!apply) { console.log('Preview only. Run with --apply to write cloud configuration.'); return }
  if (plan.some(row => row.action === 'conflict')) {
    throw new Error('Cloud configuration conflicts with local; sync cancelled before any write')
  }
  const freshTarget = await cloud.snapshot()
  const freshPlan = buildPlan(source, freshTarget, state)
  if (freshPlan.some(row => row.action === 'conflict')) {
    throw new Error('Cloud configuration developed a conflict; sync cancelled before any write')
  }
  if (freshPlan.some((row, index) => row.action !== plan[index].action ||
    row.remoteHash !== plan[index].remoteHash)) {
    throw new Error('Cloud configuration changed during preview; run sync again')
  }
  await perform(cloud, freshPlan, freshTarget)
  const verified = await cloud.snapshot()
  await cloud.verifyCloudProtection()
  const nextState = buildState(source, verified)
  const expected = source.groups.length + source.accounts.length + source.keys.length
  const actual = ['groups', 'accounts', 'keys']
    .reduce((sum, kind) => sum + Object.keys(nextState[kind]).length, 0)
  if (actual !== expected) throw new Error('Cloud verification differs from local; sync state was not saved')
  const mergedState = selectedIDs === null ? nextState : {
    version: 1,
    groups: { ...state.groups, ...nextState.groups },
    accounts: { ...state.accounts, ...nextState.accounts },
    keys: { ...state.keys, ...nextState.keys }
  }
  await saveState(mergedState)
  console.log('Cloud configuration verified; sync state saved. Cloud usage and balances were not changed.')
}

if (process.argv[1] && fileURLToPath(import.meta.url).toLowerCase() ===
    process.argv[1].toLowerCase()) {
  main().catch(error => {
    const status = Number.isInteger(error?.status) ? ` HTTP ${error.status}` : ''
    console.error(`Local-to-cloud sync stopped${status}; inspect the configuration and retry.`)
    process.exitCode = 1
  })
    .finally(closeInput)
}
