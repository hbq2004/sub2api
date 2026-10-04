import test from 'node:test'
import assert from 'node:assert/strict'
import { buildPlan, buildState, fingerprint, normalizeSnapshot,
  accountPayload, keyPayload, portableAccountExtra, selectAccount,
  selectAccounts } from './sync-local-to-cloud-core.mjs'

const group = (id, rate = 1) => ({ id, name: 'Primary', platform: 'openai',
  description: '', rate_multiplier: rate, status: 'active' })
const account = (id, token = 'secret') => ({ id, name: 'Upstream', platform: 'openai',
  type: 'apikey', credentials: { api_key: token }, extra: {}, concurrency: 3,
  priority: 50, rate_multiplier: 1, status: 'active', group_ids: [id],
  proxy_key: 'local-proxy' })
const key = (id, groupID, used = 0) => ({ id, user_id: 1, key: 'sk-test-1234567890123456',
  name: 'My Key', group_id: groupID, status: 'active', quota: 10, quota_used: used,
  ip_whitelist: [], ip_blacklist: [], rate_limit_5h: 0, rate_limit_1d: 0,
  rate_limit_7d: 0 })

function snapshot(groupID = 1, accountID = 1, keyID = 1, token = 'secret', used = 0, rate = 1) {
  const listed = account(accountID, token)
  listed.group_ids = [groupID]
  return normalizeSnapshot({ groups: [group(groupID, rate)], accounts: [listed],
    accountData: { accounts: [listed] }, keys: [key(keyID, groupID, used)] })
}

test('maps group IDs and excludes cloud usage and local proxy', () => {
  const local = snapshot()
  const cloud = snapshot(8, 9, 10, 'secret', 5)
  assert.deepEqual(buildPlan(local, cloud).map(row => row.action), ['skip', 'skip', 'skip'])
  assert.equal(local.accounts[0].localProxyIgnored, true)
  assert.equal(accountPayload(local.accounts[0].config,
    new Map([[local.groups[0].identity, { id: 8 }]])).group_ids[0], 8)
  assert.equal(keyPayload(local.keys[0].config,
    new Map([[local.groups[0].identity, { id: 8 }]])).group_id, undefined)
})

test('account selection includes only its required groups and no API keys', () => {
  const source = snapshot()
  source.groups.push({ id: 2, identity: 'gemini\u0000Other', config: {}, label: 'Other' })
  const selected = selectAccount(source, 1)
  assert.deepEqual(selected.accounts.map(item => item.id), [1])
  assert.deepEqual(selected.groups.map(item => item.id), [1])
  assert.deepEqual(selected.keys, [])
  assert.throws(() => selectAccount(source, 9), /was not exported/)
})

test('multiple account selection deduplicates shared groups and rejects missing IDs', () => {
  const source = snapshot()
  source.accounts.push({ ...source.accounts[0], id: 2, identity: 'openai\u0000apikey\u0000Second',
    label: 'Second' })
  source.groups.push({ id: 3, identity: 'gemini\u0000Other', config: {}, label: 'Other' })
  const selected = selectAccounts(source, [1, 2])
  assert.deepEqual(selected.accounts.map(item => item.id), [1, 2])
  assert.deepEqual(selected.groups.map(item => item.id), [1])
  assert.deepEqual(selected.keys, [])
  assert.throws(() => selectAccounts(source, [1, 9]), /was not exported/)
  assert.throws(() => selectAccounts(source, [1, 1]), /distinct IDs/)
})

test('first run refuses to overwrite differing cloud configuration', () => {
  const plan = buildPlan(snapshot(), snapshot(8, 9, 10, 'new-cloud-token'))
  assert.equal(plan.find(row => row.kind === 'accounts').action, 'conflict')
})

test('baseline permits local update but detects later cloud edit', () => {
  const original = snapshot()
  const baseline = buildState(original, snapshot(8, 9, 10))
  const changedLocal = snapshot(1, 1, 1, 'rotated-local-token')
  assert.equal(buildPlan(changedLocal, snapshot(8, 9, 10), baseline)
    .find(row => row.kind === 'accounts').action, 'update')
  assert.equal(buildPlan(changedLocal, snapshot(8, 9, 10, 'rotated-cloud-token'), baseline)
    .find(row => row.kind === 'accounts').action, 'conflict')
})

test('group changes are detected and identical snapshots stay stable', () => {
  const local = snapshot(1, 1, 1, 'secret', 0, 2)
  const cloud = snapshot(8, 9, 10)
  const baseline = buildState(snapshot(), cloud)
  assert.equal(buildPlan(local, cloud, baseline)[0].action, 'update')
  assert.equal(fingerprint({ a: 1, b: 2 }), fingerprint({ b: 2, a: 1 }))
})

test('account extra excludes cloud-owned usage and billing snapshots', () => {
  assert.deepEqual(portableAccountExtra({ quota_used: 5, quota_daily_start: 'today',
    grok_billing_snapshot: { paid: 1 }, base_url: 'https://provider.example' }),
  { base_url: 'https://provider.example' })
  const local = snapshot()
  const cloud = snapshot(8, 9, 10)
  local.accounts[0].config.extra = portableAccountExtra({ quota_used: 1, model: 'a' })
  cloud.accounts[0].config.extra = portableAccountExtra({ quota_used: 9, model: 'a' })
  assert.equal(buildPlan(local, cloud).find(row => row.kind === 'accounts').action, 'skip')
})

test('unset OpenAI automatic reset defaults equal explicit disabled defaults', () => {
  const local = { groups: [], keys: [], accounts: [{ id: 1,
    identity: 'openai\u0000oauth\u0000reset-defaults', label: 'reset-defaults',
    config: { platform: 'openai', type: 'oauth', credentials: {}, groups: [],
      extra: { auto_reset_credit_enabled: false,
        auto_reset_credit_5h_threshold: 1, auto_reset_credit_7d_threshold: 1 } },
    runtimeExtra: {} }] }
  const cloud = structuredClone(local)
  cloud.accounts[0].id = 2
  cloud.accounts[0].config.extra = {}
  assert.equal(buildPlan(local, cloud)[0].action, 'skip')
  assert.equal(Object.keys(buildState(local, cloud).accounts).length, 1)
  cloud.accounts[0].config.extra.auto_reset_credit_enabled = true
  assert.deepEqual(buildPlan(local, cloud)[0].differences,
    ['extra.auto_reset_credit_enabled'])
  cloud.accounts[0].config.extra = { auto_reset_credit_5h_threshold: 0.5 }
  assert.deepEqual(buildPlan(local, cloud)[0].differences,
    ['extra.auto_reset_credit_5h_threshold'])
})

test('OAuth token rotation and Codex usage changes do not create conflicts', () => {
  const local = normalizeSnapshot({
    groups: [group(1)],
    accounts: [{ id: 2, name: 'OAuth account', platform: 'openai', type: 'oauth',
      group_ids: [1], status: 'active' }],
    accountData: { accounts: [{ name: 'OAuth account', platform: 'openai', type: 'oauth',
      credentials: { access_token: 'local-access', refresh_token: 'local-refresh',
        expires_at: '2026-10-01', chatgpt_account_id: 'same-user',
        model_mapping: { one: 'two' } },
      extra: { codex_5h_used_percent: 90, codex_credits_snapshot: { count: 1 },
        upstream_model_metadata: { generated_at: 'local' },
        privacy_mode: true }, concurrency: 3, priority: 1 }] }, keys: []
  })
  const cloud = normalizeSnapshot({
    groups: [group(8)],
    accounts: [{ id: 9, name: 'OAuth account', platform: 'openai', type: 'oauth',
      group_ids: [8], status: 'active' }],
    accountData: { accounts: [{ name: 'OAuth account', platform: 'openai', type: 'oauth',
      credentials: { access_token: 'cloud-access', refresh_token: 'cloud-refresh',
        expires_at: '2026-10-02', chatgpt_account_id: 'same-user',
        model_mapping: { one: 'two' } },
      extra: { codex_5h_used_percent: 5, codex_credits_snapshot: { count: 5 },
        upstream_model_metadata: { generated_at: 'cloud' },
        privacy_mode: true }, concurrency: 3, priority: 1 }] }, keys: []
  })
  const accountPlan = buildPlan(local, cloud).find(row => row.kind === 'accounts')
  assert.equal(accountPlan.action, 'skip')
  assert.deepEqual(accountPlan.ignored, ['oauth_tokens', 'runtime_usage'])
  assert.equal(buildState(local, cloud).accounts[local.accounts[0].identity].remoteHash,
    accountPlan.remoteHash)
  const localChanged = structuredClone(local)
  localChanged.accounts[0].config.credentials.model_mapping.one = 'three'
  const conflict = buildPlan(localChanged, cloud).find(row => row.kind === 'accounts')
  assert.equal(conflict.action, 'conflict')
  assert.deepEqual(conflict.differences, ['credentials.model_mapping'])
  const wrongIdentity = structuredClone(cloud)
  wrongIdentity.accounts[0].config.credentials.chatgpt_account_id = 'another-user'
  assert.equal(buildPlan(local, wrongIdentity).find(row => row.kind === 'accounts').action,
    'conflict')
  const payload = accountPayload(localChanged.accounts[0].config,
    new Map([[local.groups[0].identity, { id: 8 }]]), cloud.accounts[0])
  assert.equal(payload.credentials.access_token, undefined)
  assert.equal(payload.credentials.refresh_token, undefined)
  assert.deepEqual(payload.credentials.model_mapping, { one: 'three' })
  assert.equal(payload.extra, undefined)
  localChanged.accounts[0].config.extra.privacy_mode = false
  const extraPayload = accountPayload(localChanged.accounts[0].config,
    new Map([[local.groups[0].identity, { id: 8 }]]), cloud.accounts[0])
  assert.equal(extraPayload.extra.codex_5h_used_percent, 5)
  assert.deepEqual(extraPayload.extra.upstream_model_metadata, { generated_at: 'cloud' })
  assert.equal(extraPayload.extra.privacy_mode, false)
})

test('asynchronous OAuth privacy result is observed separately from synced config', () => {
  const local = normalizeSnapshot({ groups: [group(1)],
    accounts: [{ id: 2, name: 'Privacy account', platform: 'openai', type: 'oauth',
      group_ids: [1], status: 'active' }],
    accountData: { accounts: [{ name: 'Privacy account', platform: 'openai', type: 'oauth',
      credentials: { access_token: 'token', chatgpt_account_id: 'same' },
      extra: { privacy_mode: 'training_set_failed' }, concurrency: 2, priority: 1 }] },
    keys: [] })
  const cloud = normalizeSnapshot({ groups: [group(9)],
    accounts: [{ id: 10, name: 'Privacy account', platform: 'openai', type: 'oauth',
      group_ids: [9], status: 'active' }],
    accountData: { accounts: [{ name: 'Privacy account', platform: 'openai', type: 'oauth',
      credentials: { access_token: 'other', chatgpt_account_id: 'same' },
      extra: { privacy_mode: 'training_off' }, concurrency: 2, priority: 1 }] },
    keys: [] })
  const row = buildPlan(local, cloud).find(item => item.kind === 'accounts')
  assert.equal(row.action, 'skip')
  assert.deepEqual(row.ignored, ['oauth_tokens', 'runtime_usage'])
  assert.equal(Object.keys(buildState(local, cloud).accounts).length, 1)
  assert.equal(accountPayload(local.accounts[0].config,
    new Map([[local.groups[0].identity, { id: 9 }]]), cloud.accounts[0]).extra,
  undefined)
})

test('unsupported cross-instance references stop before writing', () => {
  assert.throws(() => normalizeSnapshot({ groups: [{ ...group(1), fallback_group_id: 2 }],
    accounts: [], accountData: { accounts: [] }, keys: [] }), /cross-instance ID/)
  assert.throws(() => normalizeSnapshot({ groups: [{ ...group(1),
    codex_models_manifest_config: { enabled: true, account_ids: [1] } }],
    accounts: [], accountData: { accounts: [] }, keys: [] }), /cross-instance ID/)
})

test('updating clears nullable settings using the API clearing values', () => {
  const local = snapshot()
  const cloud = snapshot(8, 9, 10)
  Object.assign(cloud.accounts[0].config, {
    expires_at: 1800000000, load_factor: 9, notes: 'old note'
  })
  const payload = accountPayload(local.accounts[0].config,
    new Map([[local.groups[0].identity, { id: 8 }]]), cloud.accounts[0])
  // Simulate Go pointer binding: null is omitted; zero/empty clears.
  const persisted = structuredClone(cloud.accounts[0].config)
  for (const field of ['expires_at', 'load_factor', 'notes']) {
    if (payload[field] != null) persisted[field] = payload[field] || null
  }
  assert.deepEqual(persisted, local.accounts[0].config)
})
