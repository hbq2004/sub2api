import { createDecipheriv, createHash, createHmac, timingSafeEqual } from 'node:crypto'

// Verification of the existing Go credentialcrypto cache envelope, using Node's
// standard AES-GCM implementation. Key material stays in the caller's process.
export function originalAPIKey(row, keyring) {
  if (row.deleted) return `deleted:${row.id}`
  if (!row.key.startsWith('hmac-sha256:downstream:v1:')) return row.key
  try {
    if (!Number.isSafeInteger(row.id) || row.id <= 0 || !keyring) throw new Error()
    const prefix = 'sub2api-credential:v1:'
    if (!row.key_ciphertext?.startsWith(prefix)) throw new Error()
    const envelope = JSON.parse(row.key_ciphertext.slice(prefix.length))
    const keyHex = keyring.encryption_keys[envelope.key_id]
    if (envelope.version !== 1 || !/^[0-9a-f]{64}$/i.test(keyHex || '') ||
        !/^[0-9a-f]{64}$/i.test(keyring.lookup_key || '')) throw new Error()
    const sealed = Buffer.from(envelope.ciphertext, 'base64')
    if (sealed.length < 28) throw new Error()
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), sealed.subarray(0, 12))
    decipher.setAAD(Buffer.from(`sub2api/oauth-cache/v1/${envelope.key_id}/downstream-api-key/${row.id}`))
    decipher.setAuthTag(sealed.subarray(-16))
    const raw = Buffer.concat([decipher.update(sealed.subarray(12, -16)), decipher.final()]).toString('utf8')
    const digest = 'hmac-sha256:downstream:v1:' + createHmac('sha256', Buffer.from(keyring.lookup_key, 'hex'))
      .update('sub2api/downstream-api-key/v1\0').update(raw).digest('hex')
    if (digest.length !== row.key.length || !timingSafeEqual(Buffer.from(digest), Buffer.from(row.key))) throw new Error()
    return raw
  } catch { throw new Error('Downstream Key preservation verification failed; publication is blocked') }
}

export function keyBindingHash(rows, keyring) {
  const canonical = rows.map(row => ({ id: row.id, user_id: row.user_id, group_id: row.group_id,
    status: row.status, key: originalAPIKey(row, keyring), deleted: row.deleted }))
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex')
}
