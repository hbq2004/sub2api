import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, createHmac, randomBytes } from 'node:crypto'
import { originalAPIKey, keyBindingHash } from './key-integrity.mjs'

const ring = { encryption_keys: { test: '01'.repeat(32) }, lookup_key: '02'.repeat(32) }
const raw = 'synthetic-api-key-integrity-fixture'
const legacy = { id: 1, user_id: 7, group_id: 2, status: 'active', key: raw, deleted: false }
function encrypted() {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(ring.encryption_keys.test, 'hex'), nonce)
  cipher.setAAD(Buffer.from('sub2api/oauth-cache/v1/test/downstream-api-key/1'))
  const sealed = Buffer.concat([nonce, cipher.update(raw), cipher.final(), cipher.getAuthTag()])
  const key = 'hmac-sha256:downstream:v1:' + createHmac('sha256', Buffer.from(ring.lookup_key, 'hex'))
    .update('sub2api/downstream-api-key/v1\0').update(raw).digest('hex')
  return { ...legacy, key, key_ciphertext: 'sub2api-credential:v1:' + JSON.stringify({ version:1,key_id:'test',ciphertext:sealed.toString('base64') }) }
}
test('preserves canonical consumers and bindings across protected migration', () => {
  const row = encrypted()
  assert.equal(originalAPIKey(row, ring), raw)
  assert.equal(keyBindingHash([legacy], ring), keyBindingHash([row], ring))
})
test('rejects missing roots, row relocation, wrong lookup and tampering', () => {
  const row = encrypted()
  assert.throws(() => originalAPIKey(row, null))
  assert.throws(() => originalAPIKey({ ...row, id: 2 }, ring))
  assert.throws(() => originalAPIKey({ ...row, key: row.key.slice(0, -1) + (row.key.endsWith('f') ? 'e' : 'f') }, ring))
  assert.throws(() => originalAPIKey({ ...row, key_ciphertext: row.key_ciphertext.slice(0, -8) }, ring))
})
test('still detects ownership, group and status changes', () => {
  for (const change of [{user_id:9},{group_id:3},{status:'inactive'}]) {
    assert.notEqual(keyBindingHash([legacy], ring),keyBindingHash([{...encrypted(),...change}],ring))
  }
})
