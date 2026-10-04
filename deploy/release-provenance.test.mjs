import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertReleaseProvenance } from './release-provenance.mjs'

const revision = 'a'.repeat(40)
const labels = { 'org.opencontainers.image.revision': revision,
  'org.opencontainers.image.source': 'https://github.com/hbq2004/sub2api' }
function fixture(options = {}) {
  return endpoint => {
    if (endpoint.endsWith('/protection')) return {
      required_status_checks: { strict: options.strict !== false, contexts: ['release-source', 'secret-gate', 'test'] },
      enforce_admins: { enabled: true }, allow_force_pushes: { enabled: false }, allow_deletions: { enabled: false }
    }
    if (endpoint.includes('/check-runs')) return { check_runs: ['release-source','secret-gate','test'].map((name,id) =>
      ({ name, id, status: 'completed', conclusion: name === 'test' ? options.result || 'success' : 'success' })) }
    if (options.missing) throw new Error('No commit found')
    return { sha: options.sha || revision }
  }
}
test('accepts exact remote revision with required successful checks', () => {
  assert.equal(assertReleaseProvenance(labels, revision, fixture()).requiredChecksPassed, true)
})
test('blocks a locally present revision that is absent remotely', () => {
  assert.throws(() => assertReleaseProvenance(labels, revision, fixture({ missing: true })))
})
test('blocks skipped, failing or pending required checks', () => {
  for (const result of ['skipped','failure','cancelled',null]) {
    assert.throws(() => assertReleaseProvenance(labels, revision, fixture({ result: result === null ? 'neutral' : result })))
  }
})
test('blocks stale labels and protection relaxation', () => {
  assert.throws(() => assertReleaseProvenance(labels, 'b'.repeat(40), fixture()))
  assert.throws(() => assertReleaseProvenance(labels, revision, fixture({ strict: false })))
})
