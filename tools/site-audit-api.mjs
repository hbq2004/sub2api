import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import assert from 'node:assert/strict'

const base = 'http://127.0.0.1:4186/api/v1'
const docker = 'C:/Users/hbq/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
const raw = execFileSync(docker, ['inspect', 'sub2api-email-qa-20261002-app', '--format', '{{json .Config.Env}}'], { encoding: 'utf8', windowsHide: true })
const environment = Object.fromEntries(JSON.parse(raw).map(item => [item.slice(0, item.indexOf('=')), item.slice(item.indexOf('=') + 1)]))
const checks = []
const record = name => { checks.push(name); console.log(`PASS ${name}`) }
async function api(method, path, data, token) {
  const response = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': 'Sub2API-Site-Audit/1.0', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) })
  return { status: response.status, body: await response.json() }
}
async function login(email, password) {
  const response = await api('POST', '/auth/login', { email, password })
  assert.equal(response.status, 200, 'Fixture login')
  return response.body.data
}
let passed = false
try {
  const admin = await login(environment.ADMIN_EMAIL, environment.ADMIN_PASSWORD)
  const compliance = await api('GET', '/admin/compliance', undefined, admin.access_token)
  if (compliance.body.data?.required) {
    assert.equal((await api('POST', '/admin/compliance/accept', { phrase: compliance.body.data.ack_phrase_en, language: 'en' }, admin.access_token)).status, 200)
  }
  const user = await login('qa-user@example.invalid', 'Changed-testing-password-2026')
  const startingBalance = user.user.balance
  assert.equal((await api('GET', '/keys')).status, 401)
  record('Unauthenticated API requests are rejected')
  const group = await api('POST', '/admin/groups', { name: `Audit synthetic group ${Date.now()}`, platform: 'openai', rate_multiplier: 1, is_exclusive: false, subscription_type: 'standard' }, admin.access_token)
  assert.equal(group.status, 200, 'Create synthetic group')
  const groupId = group.body.data.id
  const createdKey = await api('POST', '/keys', { name: 'Synthetic audit key', group_id: groupId, quota: 5 }, user.access_token)
  assert.equal(createdKey.status, 200, 'Create synthetic key')
  const keyId = createdKey.body.data.id
  assert.ok(createdKey.body.data.key)
  record('User can create an API key in an available group')
  const listed = await api('GET', '/keys', undefined, user.access_token)
  assert.ok(listed.body.data.items.some(item => item.id === keyId))
  assert.equal((await api('PUT', `/keys/${keyId}`, { name: 'Updated synthetic key', status: 'inactive' }, user.access_token)).status, 200)
  assert.equal((await api('GET', `/keys/${keyId}`, undefined, user.access_token)).body.data.status, 'inactive')
  record('API key list, rename, and disable work')
  const secondEmail = `qa-owner-${Date.now()}@example.invalid`
  const secondPassword = 'Synthetic-owner-testing-2026'
  assert.equal((await api('POST', '/admin/users', { email: secondEmail, password: secondPassword, role: 'user', balance: 0, concurrency: 2 }, admin.access_token)).status, 200)
  const second = await login(secondEmail, secondPassword)
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const response = await api(method, `/keys/${keyId}`, method === 'PUT' ? { name: 'Forbidden update' } : undefined, second.access_token)
    assert.ok([403, 404].includes(response.status), `Foreign key ${method} must be denied`)
  }
  record('A second user cannot read, update, or delete another user key')
  assert.equal((await api('PUT', '/user', { username: 'Audit profile' }, user.access_token)).status, 200)
  assert.equal((await api('GET', '/user/profile', undefined, user.access_token)).body.data.username, 'Audit profile')
  record('Profile updates are persisted')
  const longChange = await api('PUT', '/user/password', { old_password: 'Changed-testing-password-2026', new_password: 'x'.repeat(73) }, user.access_token)
  assert.equal(longChange.status, 400)
  assert.equal(longChange.body.reason, 'PASSWORD_TOO_LONG')
  assert.equal((await api('GET', '/auth/me', undefined, user.access_token)).status, 200)
  record('Overlong password changes preserve the current password and session')
  const generated = await api('POST', '/admin/redeem-codes/generate', { count: 1, type: 'balance', value: 5 }, admin.access_token)
  assert.equal(generated.status, 200, 'Generate synthetic redeem code')
  const code = generated.body.data[0].code
  assert.ok(code && code !== '********')
  const redeemed = await api('POST', '/redeem', { code }, user.access_token)
  assert.equal(redeemed.status, 200, 'Redeem synthetic code')
  assert.equal((await api('GET', '/auth/me', undefined, user.access_token)).body.data.balance, startingBalance + 5)
  assert.ok((await api('POST', '/redeem', { code }, user.access_token)).status >= 400)
  const history = await api('GET', '/redeem/history', undefined, user.access_token)
  const rows = Array.isArray(history.body.data) ? history.body.data : history.body.data.items
  assert.ok(rows.every(item => item.code !== code && (item.code === '********' || /^.{4}\.\.\..{4}$/.test(item.code))))
  record('Redemption credits once and masks history codes')
  assert.equal((await api('DELETE', `/keys/${keyId}`, undefined, user.access_token)).status, 200)
  assert.equal((await api('GET', `/keys/${keyId}`, undefined, user.access_token)).status, 404)
  record('User can delete their API key')
  const longRegister = await api('POST', '/auth/register', { email: 'qa-long@example.invalid', password: 'x'.repeat(73) })
  assert.equal(longRegister.body.reason, 'PASSWORD_TOO_LONG')
  record('Registration rejects overlong input before asking for email verification')
  passed = true
} catch (error) {
  console.error(error.message)
} finally {
  writeFileSync('D:/Desktop/sub2api/output/site-audit-20261002/round2-api-report.json', JSON.stringify({ passed, checks }, null, 2))
  process.exitCode = passed ? 0 : 1
}
