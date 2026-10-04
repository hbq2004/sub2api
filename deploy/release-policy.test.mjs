import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { assertLegacySyncAllowed } from './release-policy.mjs'

test('pool ownership prevents the legacy sync from recreating duplicate owners', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sub2api-pool-policy-'))
  const path = join(directory, 'policy.json')
  try {
    await assert.rejects(assertLegacySyncAllowed(path), /policy; sync is blocked/)
    await writeFile(path, JSON.stringify({ mode: 'separate-pools' }))
    await assert.rejects(assertLegacySyncAllowed(path), { code: 'ACCOUNT_POOL_TRANSFER_REQUIRED' })
    for (const policy of [{}, {mode:'cloud-primary'}, {mode:'legacy-copy'}, {mode:'unknown'}]) {
      await writeFile(path, JSON.stringify(policy))
      await assert.rejects(assertLegacySyncAllowed(path), {code:'ACCOUNT_POOL_TRANSFER_REQUIRED'})
    }
    await writeFile(path, '{invalid')
    await assert.rejects(assertLegacySyncAllowed(path), /policy; sync is blocked/)
  } finally { await rm(directory, { recursive: true, force: true }) }
})
