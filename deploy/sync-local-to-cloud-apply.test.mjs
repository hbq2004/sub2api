import test from 'node:test'
import assert from 'node:assert/strict'
import { perform } from './sync-local-to-cloud.mjs'
import { buildPlan, normalizeSnapshot } from './sync-local-to-cloud-core.mjs'

test('apply creates group, upstream account, and key in dependency order', async () => {
  const source = normalizeSnapshot({
    groups: [{ id: 1, name: 'Primary', platform: 'openai', status: 'active',
      rate_multiplier: 1 }],
    accounts: [{ id: 2, name: 'Upstream', platform: 'openai', type: 'apikey',
      group_ids: [1], status: 'active' }],
    accountData: { accounts: [{ name: 'Upstream', platform: 'openai', type: 'apikey',
      credentials: { api_key: 'upstream-secret' }, extra: { quota_used: 99 },
      concurrency: 3, priority: 50, rate_multiplier: 1 }] },
    keys: [{ id: 3, key: 'sk-test-1234567890123456', name: 'Personal', group_id: 1,
      status: 'active', quota: 10, quota_used: 7 }]
  })
  const target = { groups: [], accounts: [], keys: [] }
  const calls = []
  const client = {
    post: async (path, body) => { calls.push({ method: 'POST', path, body });
      return { id: path === '/admin/groups' ? 10 : path === '/admin/accounts' ? 20 : 30 } },
    put: async (path, body) => { calls.push({ method: 'PUT', path, body }); return { id: 30 } }
  }
  await perform(client, buildPlan(source, target), target)
  assert.deepEqual(calls.map(call => `${call.method} ${call.path}`), [
    'POST /admin/groups', 'POST /admin/accounts', 'POST /keys',
    'PUT /keys/30', 'PUT /admin/api-keys/30'
  ])
  assert.deepEqual(calls[1].body.group_ids, [10])
  assert.equal(calls[1].body.extra.quota_used, undefined)
  assert.equal(calls[2].body.custom_key, 'sk-test-1234567890123456')
  assert.equal(calls[4].body.group_id, 10)
  assert.equal(calls.some(call => 'quota_used' in call.body), false)
  assert.equal(calls[1].body.status, undefined)
  assert.equal(calls[3].body.status, undefined)
})

test('creating an inactive upstream account applies its status after creation', async () => {
  const account = { id: 1, identity: 'openai\u0000apikey\u0000Disabled', label: 'Disabled',
    config: { name: 'Disabled', platform: 'openai', type: 'apikey',
      credentials: { api_key: 'secret' }, extra: {}, groups: [], status: 'inactive' } }
  const calls = []
  const client = {
    post: async (path, body) => { calls.push([path, body]); return { id: 4 } },
    put: async (path, body) => { calls.push([path, body]); return { id: 4 } }
  }
  await perform(client, [{ kind: 'accounts', item: account, action: 'create' }],
    { groups: [], accounts: [], keys: [] })
  assert.equal(calls[0][1].status, undefined)
  assert.deepEqual(calls[1], ['/admin/accounts/4', { status: 'inactive' }])
})

test('perform refuses a conflicting plan before creating any other record', async () => {
  const writes = []
  await assert.rejects(perform({ post: async path => writes.push(path),
    put: async path => writes.push(path) }, [
    { kind: 'groups', action: 'create', item: { config: {} } },
    { kind: 'accounts', action: 'conflict' }
  ], { groups: [] }), /cancelled before any write/)
  assert.deepEqual(writes, [])
})
