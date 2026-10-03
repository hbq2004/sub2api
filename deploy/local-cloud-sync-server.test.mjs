import test from 'node:test'
import assert from 'node:assert/strict'
import { createSyncServer, syncRequest } from './local-cloud-sync-server.mjs'
import { Client } from './sync-local-to-cloud.mjs'
import { normalizeSnapshot } from './sync-local-to-cloud-core.mjs'

test('sync preview selects an upstream account and its group without writing or copying keys', async () => {
  const previousFetch = global.fetch
  const calls = []
  global.fetch = async (url, options = {}) => {
    const target = new URL(url)
    const cloud = target.hostname === 'api.zynexus.top'
    const path = target.pathname + target.search
    calls.push({ cloud, path, method: options.method })
    let data
    if (path === '/api/v1/auth/me') data = { role: 'admin' }
    else if (path === '/api/v1/auth/login') data = { requires_2fa: true, temp_token: 'temp' }
    else if (path === '/api/v1/auth/login/2fa') data = {
      access_token: 'cloud-token', user: { role: 'admin' }
    }
    else if (path === '/api/v1/admin/settings') data = {
      totp_enabled: true, step_up_enabled: true, totp_encryption_key_configured: true
    }
    else if (path === '/api/v1/user/totp/status') data = { enabled: true, feature_enabled: true }
    else if (path === '/api/v1/admin/groups/all?include_inactive=true') data = cloud ? [] : [{
      id: 101, name: 'Web sync test group', platform: 'openai',
      status: 'active', rate_multiplier: 1
    }]
    else if (path.startsWith('/api/v1/admin/accounts?page=')) data = cloud
      ? { items: [], total: 0 }
      : { items: [{ id: 202, name: 'Web sync test account', platform: 'openai',
        type: 'oauth', group_ids: [101], status: 'active' }], total: 1 }
    else if (path === '/api/v1/admin/accounts/data?include_proxies=false') data = {
      accounts: cloud ? [] : [{ name: 'Web sync test account', platform: 'openai',
        type: 'oauth', credentials: { refresh_token: 'private-upstream-token' },
        extra: {}, concurrency: 1, priority: 1 }]
    }
    else throw new Error(`Unexpected API path ${path}`)
    return { ok: true, status: 200, json: async () => ({ code: 0, data }) }
  }
  try {
    const preview = await syncRequest({ accountIds: [202], cloudEmail: 'admin@example.com',
      cloudPassword: 'test-password', cloudCode: '123456' }, 'local-admin-token')
    assert.deepEqual(preview.plan.map(row => [row.kind, row.action]), [
      ['groups', 'create'], ['accounts', 'create']
    ])
    assert.match(preview.digest, /^[a-f0-9]{64}$/)
    assert.match(preview.previewTicket, /^[0-9a-f-]{36}$/)
    assert.doesNotMatch(JSON.stringify(preview), /private-upstream-token|test-password/)
    assert.equal(calls.some(call => call.path.startsWith('/api/v1/keys')), false)
    assert.equal(calls.some(call => call.cloud &&
      ['/api/v1/admin/groups', '/api/v1/admin/accounts'].includes(call.path) &&
      ['POST', 'PUT'].includes(call.method)), false)
  } finally {
    global.fetch = previousFetch
  }
})

test('local sync server rejects other origins and missing administrator authorization', async () => {
  const server = createSyncServer()
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${server.address().port}`
  try {
    const blocked = await fetch(`${base}/preview`, {
      method: 'POST', headers: { Origin: 'https://api.zynexus.top',
        'Content-Type': 'application/json' }, body: '{}'
    })
    assert.equal(blocked.status, 403)
    const unauthenticated = await fetch(`${base}/preview`, {
      method: 'POST', headers: { Origin: 'http://127.0.0.1:8080',
        'Content-Type': 'application/json' }, body: '{}'
    })
    assert.equal(unauthenticated.status, 401)
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
  }
})

test('preview session avoids a second TOTP login and conflicts cancel before writes', async () => {
  const source = normalizeSnapshot({
    groups: [
      { id: 11, name: 'Web test new group', platform: 'openai', rate_multiplier: 1 },
      { id: 12, name: 'Web test conflicting group', platform: 'openai', rate_multiplier: 1 }
    ],
    accounts: [{ id: 21, name: 'Web test new account', platform: 'openai',
      type: 'oauth', group_ids: [11, 12], status: 'active' }],
    accountData: { accounts: [{ name: 'Web test new account', platform: 'openai',
      type: 'oauth', credentials: { refresh_token: 'private' }, extra: {},
      concurrency: 1, priority: 1 }] },
    keys: []
  })
  const conflictingTarget = normalizeSnapshot({
    groups: [{ id: 31, name: 'Web test conflicting group', platform: 'openai',
      rate_multiplier: 2 }],
    accounts: [], accountData: { accounts: [] }, keys: []
  })
  const emptyTarget = { groups: [], accounts: [], keys: [] }
  const originals = Object.fromEntries(['get', 'login', 'verifyCloudProtection',
    'snapshot', 'post', 'put'].map(name => [name, Client.prototype[name]]))
  const writes = []
  let logins = 0
  let currentTarget = emptyTarget
  Client.prototype.get = async () => ({ role: 'admin' })
  Client.prototype.login = async function () { logins++; this.token = 'cloud-token';
    return { role: 'admin' } }
  Client.prototype.verifyCloudProtection = async () => {}
  Client.prototype.snapshot = async function () { return this.name === 'Local' ? source : currentTarget }
  Client.prototype.post = async function (path) { writes.push(path); throw new Error('Unexpected write') }
  Client.prototype.put = async function (path) { writes.push(path); throw new Error('Unexpected write') }
  const input = { accountIds: [21], cloudEmail: 'admin@example.com',
    cloudPassword: 'test-password', cloudCode: '123456' }
  try {
    const preview = await syncRequest(input, 'local-token')
    assert.deepEqual(preview.plan.map(row => row.action), ['create', 'create', 'create'])
    currentTarget = conflictingTarget
    await assert.rejects(syncRequest({ accountIds: [21], expectedPlan: preview.digest,
      previewTicket: preview.previewTicket },
      'local-token', true), /Configuration changed since preview/)
    assert.equal(logins, 1)
    await assert.rejects(syncRequest({ accountIds: [21], expectedPlan: preview.digest,
      previewTicket: preview.previewTicket }, 'local-token', true), /Preview expired/)
    await assert.rejects(syncRequest({ ...input, takeLocal: true }, 'local-token'),
      /Conflict override is disabled/)
    const groupPreview = await syncRequest(input, 'local-token')
    assert.equal(groupPreview.plan[1].action, 'conflict')
    await assert.rejects(syncRequest({ accountIds: [21], expectedPlan: groupPreview.digest,
      previewTicket: groupPreview.previewTicket },
      'local-token', true), /unsupported account or group configuration conflict/)
    assert.deepEqual(writes, [])
  } finally {
    Object.assign(Client.prototype, originals)
  }
})

test('local-owned account differences preview as updates and retain cloud OAuth runtime', async () => {
  const group = (id, name) => ({ id, name, platform: 'openai', rate_multiplier: 1 })
  const makeSnapshot = (groupIds, accountId, mapping, boundGroup, resetConfig, token,
    usage, owner = 'same-user') => normalizeSnapshot({
    groups: [group(groupIds[0], 'Web resolution A'), group(groupIds[1], 'Web resolution B')],
    accounts: [{ id: accountId, name: 'Web resolution OAuth', platform: 'openai',
      type: 'oauth', group_ids: [boundGroup], status: 'active' }],
    accountData: { accounts: [{ name: 'Web resolution OAuth', platform: 'openai',
      type: 'oauth', credentials: { access_token: token, refresh_token: token,
        chatgpt_account_id: owner, model_mapping: { 'gpt-test': mapping } },
      extra: { ...resetConfig, codex_5h_used_percent: usage },
      concurrency: 1, priority: 1 }] }, keys: []
  })
  const localReset = { auto_reset_credit_enabled: false,
    auto_reset_credit_5h_threshold: 1, auto_reset_credit_7d_threshold: 1 }
  const source = makeSnapshot([1, 2], 3, 'local-model', 1, localReset, 'local-token', 90)
  let target = makeSnapshot([11, 12], 13, 'cloud-model', 12, {}, 'cloud-token', 5)
  const originals = Object.fromEntries(['get', 'login', 'verifyCloudProtection',
    'snapshot', 'post', 'put'].map(name => [name, Client.prototype[name]]))
  const writes = []
  Client.prototype.get = async () => ({ role: 'admin' })
  Client.prototype.login = async function () { this.token = 'cloud-admin-token'; return { role: 'admin' } }
  Client.prototype.verifyCloudProtection = async () => {}
  Client.prototype.snapshot = async function () { return this.name === 'Local' ? source : target }
  Client.prototype.post = async path => { writes.push(path); throw new Error('Unexpected create') }
  Client.prototype.put = async (path, body) => {
    writes.push(path)
    assert.equal(path, '/admin/accounts/13')
    assert.deepEqual(body.group_ids, [11])
    assert.deepEqual(body.credentials.model_mapping, { 'gpt-test': 'local-model' })
    assert.equal(body.credentials.access_token, undefined)
    assert.equal(body.credentials.refresh_token, undefined)
    assert.equal(body.extra.auto_reset_credit_enabled, false)
    assert.equal(body.extra.auto_reset_credit_5h_threshold, 1)
    assert.equal(body.extra.auto_reset_credit_7d_threshold, 1)
    assert.equal(body.extra.codex_5h_used_percent, 5)
    target = makeSnapshot([11, 12], 13, 'local-model', 11, localReset, 'cloud-token', 5)
    return { id: 13 }
  }
  const input = { accountIds: [3], cloudEmail: 'admin@example.com',
    cloudPassword: 'test-password', cloudCode: '123456' }
  let savedState = {}
  const stateStore = { read: async () => savedState,
    save: async state => { savedState = state } }
  try {
    const preview = await syncRequest(input, 'local-admin-token', false, stateStore)
    assert.deepEqual(preview.plan.map(row => row.action), ['skip', 'update'])
    assert.deepEqual(preview.plan[1].differences,
      ['credentials.model_mapping', 'groups'])
    assert.deepEqual(preview.plan[1].settingDifferences, [
      { field: 'model_mapping.gpt-test', local: 'local-model', cloud: 'cloud-model' }
    ])
    assert.doesNotMatch(JSON.stringify(preview), /local-token|cloud-token/)
    assert.match(preview.previewTicket, /^[0-9a-f-]{36}$/)
    assert.deepEqual(writes, [])
    const result = await syncRequest({ accountIds: [3], expectedPlan: preview.digest,
      previewTicket: preview.previewTicket },
    'local-admin-token', true, stateStore)
    assert.equal(result.verified, true)
    assert.equal(Object.keys(savedState.accounts).length, 1)
    assert.deepEqual(writes, ['/admin/accounts/13'])

    target = makeSnapshot([11, 12], 13, 'local-model', 11, localReset,
      'cloud-token', 5, 'different-user')
    const identityPreview = await syncRequest(input, 'local-admin-token', false, stateStore)
    assert.equal(identityPreview.plan[1].action, 'conflict')
    assert.deepEqual(identityPreview.plan[1].differences,
      ['credentials.chatgpt_account_id'])
    await assert.rejects(syncRequest({ accountIds: [3], expectedPlan: identityPreview.digest,
      previewTicket: identityPreview.previewTicket }, 'local-admin-token', true,
    stateStore), /unsupported account or group configuration conflict/)
    assert.deepEqual(writes, ['/admin/accounts/13'])
  } finally {
    Object.assign(Client.prototype, originals)
  }
})

test('cloud configuration changes after preview stop before writes', async () => {
  const makeSnapshot = (id, rate) => normalizeSnapshot({
    groups: [{ id, name: 'Web stale group', platform: 'openai', rate_multiplier: 1 }],
    accounts: [{ id: id + 1, name: 'Web stale account', platform: 'openai',
      type: 'apikey', group_ids: [id], status: 'active' }],
    accountData: { accounts: [{ name: 'Web stale account', platform: 'openai',
      type: 'apikey', credentials: { api_key: 'same' }, extra: {},
      concurrency: rate, priority: 1 }] }, keys: [] })
  const source = makeSnapshot(1, 3)
  let target = makeSnapshot(10, 1)
  const originals = Object.fromEntries(['get', 'login', 'verifyCloudProtection',
    'snapshot', 'post', 'put'].map(name => [name, Client.prototype[name]]))
  const writes = []
  Client.prototype.get = async () => ({ role: 'admin' })
  Client.prototype.login = async function () { this.token = 'cloud-admin-token'; return { role: 'admin' } }
  Client.prototype.verifyCloudProtection = async () => {}
  Client.prototype.snapshot = async function () { return this.name === 'Local' ? source : target }
  Client.prototype.post = async path => { writes.push(path) }
  Client.prototype.put = async path => { writes.push(path) }
  try {
    const preview = await syncRequest({ accountIds: [2], cloudEmail: 'admin@example.com',
      cloudPassword: 'test-password', cloudCode: '123456' }, 'local-admin-token')
    assert.equal(preview.plan[1].action, 'conflict')
    target = makeSnapshot(10, 2)
    await assert.rejects(syncRequest({ accountIds: [2], expectedPlan: preview.digest,
      previewTicket: preview.previewTicket },
    'local-admin-token', true), /Configuration changed since preview/)
    assert.deepEqual(writes, [])
  } finally {
    Object.assign(Client.prototype, originals)
  }
})

test('failed create-only sync removes the group it created and verifies the baseline', async () => {
  const source = normalizeSnapshot({
    groups: [{ id: 1, name: 'Rollback test group', platform: 'openai',
      status: 'active', rate_multiplier: 1 }],
    accounts: [{ id: 2, name: 'Rollback test account', platform: 'openai',
      type: 'oauth', group_ids: [1], status: 'active' }],
    accountData: { accounts: [{ name: 'Rollback test account', platform: 'openai',
      type: 'oauth', credentials: { refresh_token: 'private' }, extra: {},
      concurrency: 1, priority: 1 }] }, keys: []
  })
  const target = { groups: [], accounts: [], keys: [] }
  const originals = Object.fromEntries(['get', 'login', 'verifyCloudProtection',
    'snapshot', 'post', 'put', 'delete'].map(name => [name, Client.prototype[name]]))
  const calls = []
  Client.prototype.get = async () => ({ role: 'admin' })
  Client.prototype.login = async function () { this.token = 'cloud-token'; return { role: 'admin' } }
  Client.prototype.verifyCloudProtection = async () => {}
  Client.prototype.snapshot = async function () { return this.name === 'Local' ? source : target }
  Client.prototype.post = async path => {
    calls.push(`POST ${path}`)
    if (path === '/admin/groups') {
      target.groups.push({ ...source.groups[0], id: 31 })
      return { id: 31 }
    }
    throw new Error('Simulated account creation failure')
  }
  Client.prototype.put = async () => { throw new Error('Unexpected update') }
  Client.prototype.delete = async path => {
    calls.push(`DELETE ${path}`)
    if (path !== '/admin/groups/31') throw new Error('Unexpected rollback target')
    target.groups.length = 0
  }
  const input = { accountIds: [2], cloudEmail: 'admin@example.com',
    cloudPassword: 'test-password', cloudCode: '123456' }
  try {
    const preview = await syncRequest(input, 'local-token')
    await assert.rejects(syncRequest({ accountIds: [2],
      expectedPlan: preview.digest, previewTicket: preview.previewTicket },
    'local-token', true), /rolled back and verified/)
    assert.deepEqual(calls, [
      'POST /admin/groups', 'POST /admin/accounts', 'DELETE /admin/groups/31'
    ])
    assert.deepEqual(target.groups, [])
    assert.deepEqual(target.accounts, [])
  } finally {
    Object.assign(Client.prototype, originals)
  }
})
