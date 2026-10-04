import test from 'node:test'
import assert from 'node:assert/strict'
import { syncRequest } from './local-cloud-sync-server.mjs'
import { Client } from './sync-local-to-cloud.mjs'
import { normalizeSnapshot } from './sync-local-to-cloud-core.mjs'

function snapshot(id, mapping, newAccount = false) {
  const group = { id, name: 'Transaction group', platform: 'openai',
    status: 'active', rate_multiplier: 1 }
  const accounts = [{ id: id + 1, name: 'Existing OAuth', platform: 'openai',
    type: 'oauth', group_ids: [id], status: 'error', concurrency: 1, priority: 1,
    credentials: { chatgpt_account_id: 'same-user', model_mapping: { model: mapping },
      access_token: `access-${id}`, refresh_token: `refresh-${id}` },
    extra: { codex_5h_used_percent: id } }]
  if (newAccount) accounts.push({ ...accounts[0], id: id + 2, name: 'New OAuth',
    credentials: { chatgpt_account_id: 'new-user', refresh_token: 'new-private' } })
  return normalizeSnapshot({ groups: [group], accounts,
    accountData: { accounts }, keys: [] })
}

async function harness(run) {
  const originals = Object.fromEntries(['get', 'login', 'verifyCloudProtection',
    'snapshot', 'post', 'put', 'delete'].map(name => [name, Client.prototype[name]]))
  const source = snapshot(1, 'local-model', true)
  const target = snapshot(11, 'cloud-model')
  const writes = []
  let saved = false
  const stateStore = { read: async () => ({}), save: async () => { saved = true } }
  Client.prototype.get = async () => ({ role: 'admin' })
  Client.prototype.login = async function () { this.token = 'cloud-admin-token' }
  Client.prototype.verifyCloudProtection = async () => {}
  Client.prototype.snapshot = async function () { return structuredClone(this.name === 'Local' ? source : target) }
  Client.prototype.put = async (path, body) => {
    writes.push(['PUT', path])
    const account = target.accounts.find(item => path === `/admin/accounts/${item.id}`)
    assert.ok(account)
    assert.equal(body.status, undefined, 'a config edit must not clear runtime errors')
    assert.equal(body.credentials.access_token, undefined)
    assert.equal(body.credentials.refresh_token, undefined)
    const tokens = Object.fromEntries(Object.entries(account.config.credentials)
      .filter(([key]) => ['access_token', 'refresh_token'].includes(key)))
    account.config.credentials = { ...structuredClone(body.credentials), ...tokens }
    account.config.groups = body.group_ids.map(id => target.groups.find(group => group.id === id).identity).sort()
    if (body.extra) account.config.extra = { ...source.accounts[0].config.extra }
    return { id: account.id }
  }
  Client.prototype.post = async () => { throw new Error('Unexpected create') }
  Client.prototype.delete = async path => {
    writes.push(['DELETE', path])
    target.accounts = target.accounts.filter(item => path !== `/admin/accounts/${item.id}`)
    assert.equal(target.accounts.some(item => item.config.groups.some(identity =>
      target.groups.some(group => group.identity === identity && path === `/admin/groups/${group.id}`))),
    false, 'restore group bindings before deleting their dependency')
    target.groups = target.groups.filter(item => path !== `/admin/groups/${item.id}`)
  }
  const preview = () => syncRequest({ accountIds: [2, 3], cloudEmail: 'admin@example.com',
    cloudPassword: 'private-password', cloudCode: '123456' }, 'local-admin-token', false, stateStore)
  const apply = p => syncRequest({ accountIds: [2, 3], expectedPlan: p.digest,
    previewTicket: p.previewTicket }, 'local-admin-token', true, stateStore)
  try { await run({ source, target, writes, preview, apply, saved: () => saved }) }
  finally { Object.assign(Client.prototype, originals) }
}

test('mixed create/update failure restores existing config and removes new records', async () => {
  await harness(async ({ source, target, writes, preview, apply, saved }) => {
    let reads = 0
    const originalSnapshot = Client.prototype.snapshot
    Client.prototype.snapshot = async function () {
      if (this.name === 'Cloud' && ++reads >= 5) {
        target.accounts[0].config.credentials.access_token = 'fresh-cloud-access'
        target.accounts[0].runtimeExtra.codex_5h_used_percent = 75
      }
      return originalSnapshot.call(this)
    }
    Client.prototype.post = async path => {
      writes.push(['POST', path])
      target.accounts.push({ ...structuredClone(source.accounts[1]), id: 99 })
      // Lost response after the server committed the create.
      throw new Error('Simulated response loss')
    }
    const p = await preview()
    assert.deepEqual(p.plan.map(row => row.action), ['skip', 'update', 'create'])
    await assert.rejects(apply(p), /updated and newly created.*rolled back and verified/)
    assert.equal(target.accounts.length, 1)
    assert.equal(target.accounts[0].config.credentials.model_mapping.model, 'cloud-model')
    assert.equal(target.accounts[0].config.credentials.access_token, 'fresh-cloud-access')
    assert.equal(target.accounts[0].runtimeExtra.codex_5h_used_percent, 75)
    assert.equal(saved(), false)
    assert.deepEqual(writes, [['PUT', '/admin/accounts/12'], ['POST', '/admin/accounts'],
      ['PUT', '/admin/accounts/12'], ['DELETE', '/admin/accounts/99']])
  })
})

test('mixed sync verification failure restores updates and successful creates', async () => {
  await harness(async ({ source, target, writes, preview, apply, saved }) => {
    Client.prototype.post = async path => {
      writes.push(['POST', path])
      const created = { ...structuredClone(source.accounts[1]), id: 99 }
      created.config.priority = 999 // Backend did not persist the requested configuration.
      target.accounts.push(created)
      return { id: 99 }
    }
    await assert.rejects(apply(await preview()), /Cloud verification differs.*rolled back and verified/)
    assert.equal(target.accounts.length, 1)
    assert.equal(target.accounts[0].config.credentials.model_mapping.model, 'cloud-model')
    assert.equal(saved(), false)
  })
})

test('rollback reports independent edits without overwriting them', async () => {
  await harness(async ({ target, writes, preview, apply, saved }) => {
    Client.prototype.post = async () => {
      target.accounts[0].config.credentials.model_mapping.model = 'administrator-edit'
      throw new Error('Simulated create failure')
    }
    await assert.rejects(apply(await preview()), /rollback needs attention.*changed independently/)
    assert.equal(target.accounts[0].config.credentials.model_mapping.model, 'administrator-edit')
    assert.deepEqual(writes, [['PUT', '/admin/accounts/12']])
    assert.equal(saved(), false)
  })
})

test('a cloud record replaced after preview cannot reuse the preview ticket', async () => {
  await harness(async ({ target, writes, preview, apply }) => {
    const p = await preview()
    target.accounts[0].id = 88
    await assert.rejects(apply(p), /Configuration changed since preview/)
    assert.deepEqual(writes, [])
  })
})

test('a failed update response is rolled back even when the server already committed', async () => {
  await harness(async ({ target, writes, preview, apply }) => {
    const update = Client.prototype.put
    let first = true
    Client.prototype.put = async (...args) => {
      const result = await update(...args)
      if (first) { first = false; throw new Error('Lost update response') }
      return result
    }
    await assert.rejects(apply(await preview()), /Lost update response.*rolled back and verified/)
    assert.equal(target.accounts[0].config.credentials.model_mapping.model, 'cloud-model')
    assert.deepEqual(writes, [['PUT', '/admin/accounts/12'], ['PUT', '/admin/accounts/12']])
  })
})

test('rollback restores a partial update when settings persist but group binding fails', async () => {
  await harness(async ({ source, target, preview, apply }) => {
    source.accounts[0].config.groups = []
    const update = Client.prototype.put
    let first = true
    Client.prototype.put = async (...args) => {
      const result = await update(...args)
      if (first) {
        first = false
        target.accounts[0].config.groups = [target.groups[0].identity]
        throw new Error('Failed group binding after account settings persisted')
      }
      return result
    }
    await assert.rejects(apply(await preview()), /Failed group binding.*rolled back and verified/)
    assert.equal(target.accounts[0].config.credentials.model_mapping.model, 'cloud-model')
    assert.deepEqual(target.accounts[0].config.groups, [target.groups[0].identity])
  })
})

test('failure before an update is persisted does not issue a spurious restore', async () => {
  await harness(async ({ target, writes, preview, apply }) => {
    Client.prototype.put = async () => { throw new Error('Update rejected') }
    await assert.rejects(apply(await preview()), /Update rejected.*rolled back and verified/)
    assert.equal(target.accounts[0].config.credentials.model_mapping.model, 'cloud-model')
    assert.deepEqual(writes, [])
  })
})

test('rollback leaves concurrently added records whose create was never attempted', async () => {
  await harness(async ({ source, target, writes, preview, apply }) => {
    Client.prototype.put = async () => {
      target.accounts.push({ ...structuredClone(source.accounts[1]), id: 77 })
      throw new Error('Update rejected before create')
    }
    await assert.rejects(apply(await preview()), /rolled back and verified/)
    assert.equal(target.accounts.length, 2)
    assert.equal(target.accounts[1].id, 77)
    assert.deepEqual(writes, [])
  })
})

test('mixed rollback restores old group bindings before removing a new group', async () => {
  await harness(async ({ source, target, writes, preview, apply }) => {
    const newGroup = { id: 4, identity: 'openai\u0000New transaction group',
      label: 'New transaction group', config: { name: 'New transaction group',
        platform: 'openai', status: 'active', rate_multiplier: 1 } }
    source.groups.push(newGroup)
    source.accounts[0].config.groups = [newGroup.identity]
    Client.prototype.post = async path => {
      writes.push(['POST', path])
      if (path === '/admin/groups') {
        target.groups.push({ ...structuredClone(newGroup), id: 44 })
        return { id: 44 }
      }
      throw new Error('Account create failed')
    }
    await assert.rejects(apply(await preview()), /rolled back and verified/)
    assert.equal(target.groups.length, 1)
    assert.deepEqual(target.accounts[0].config.groups, [target.groups[0].identity])
    assert.deepEqual(writes, [['POST', '/admin/groups'], ['PUT', '/admin/accounts/12'],
      ['POST', '/admin/accounts'], ['PUT', '/admin/accounts/12'], ['DELETE', '/admin/groups/44']])
  })
})
