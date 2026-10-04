import test from 'node:test'
import assert from 'node:assert/strict'
import { Client } from './sync-local-to-cloud.mjs'

test('cloud login refuses a password-only administrator session', async () => {
  const client = new Client('https://example.com', 'Cloud', async () => 'input')
  client.post = async () => ({ access_token: 'password-only', user: { role: 'admin' } })
  await assert.rejects(client.login(), /TOTP login is required/)
  assert.equal(client.token, '')
})

test('cloud login and write step-up require separate verified TOTP responses', async () => {
  const prompts = []
  const client = new Client('https://example.com', 'Cloud', async label => {
    prompts.push(label)
    return 'input'
  })
  const calls = []
  client.post = async (path, body) => {
    calls.push({ path, body })
    if (path === '/auth/login') return { requires_2fa: true, temp_token: 'temporary' }
    if (path === '/auth/login/2fa') return { access_token: 'verified', user: { role: 'admin' } }
    if (path === '/user/totp/step-up') return { verified: true }
  }
  await client.login()
  await client.stepUp()
  assert.equal(client.token, 'verified')
  assert.deepEqual(calls.map(call => call.path), [
    '/auth/login', '/auth/login/2fa', '/user/totp/step-up'
  ])
  assert.equal(prompts.filter(prompt => prompt.includes('2FA code')).length, 2)
})

test('unverified step-up stops the operation', async () => {
  const client = new Client('https://example.com', 'Cloud', async () => 'input')
  client.post = async () => ({ verified: false })
  await assert.rejects(client.stepUp(), /not verified/)
})

test('cloud protection requires admin TOTP and server-side security switches', async () => {
  const client = new Client('https://example.com', 'Cloud', async () => 'input')
  const settings = { totp_enabled: true, step_up_enabled: true,
    totp_encryption_key_configured: true }
  const status = { enabled: true, feature_enabled: true }
  client.get = async path => path === '/admin/settings' ? settings : status
  await client.verifyCloudProtection()
  settings.step_up_enabled = false
  await assert.rejects(client.verifyCloudProtection(), /protection is disabled/)
  settings.step_up_enabled = true
  status.enabled = false
  await assert.rejects(client.verifyCloudProtection(), /protection is disabled/)
})
