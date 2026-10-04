import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'

const fork = 'hbq2004/sub2api'
const required = ['release-source', 'secret-gate', 'test']

function ghRead(endpoint) {
  try {
    return JSON.parse(execFileSync('gh', ['api', endpoint], {
      encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000
    }))
  } catch { throw new Error('Release provenance is unavailable; publication is blocked') }
}

// Each read uses the immutable image revision, including check-only and repeat publication.
export function assertReleaseProvenance(labels, expectedRevision, read = ghRead) {
  assert.match(expectedRevision || '', /^[0-9a-f]{40}$/, 'A full tested source revision is required')
  assert.equal(labels['org.opencontainers.image.revision'], expectedRevision, 'Image and local acceptance revisions differ')
  assert.equal(labels['org.opencontainers.image.source'], `https://github.com/${fork}`, 'The image must identify the owned fork')
  const commit = read(`repos/${fork}/commits/${expectedRevision}`)
  assert.equal(commit.sha, expectedRevision, 'The image revision is absent from the owned fork')
  const protection = read(`repos/${fork}/branches/main/protection`)
  const contexts = protection.required_status_checks?.contexts || []
  assert.ok(protection.required_status_checks?.strict && protection.enforce_admins?.enabled,
    'Strict branch protection must apply to administrators')
  assert.ok(!protection.allow_force_pushes?.enabled && !protection.allow_deletions?.enabled,
    'Branch history must be protected')
  assert.ok(required.every(name => contexts.includes(name)), 'A required security check is missing')
  const checks = read(`repos/${fork}/commits/${expectedRevision}/check-runs?per_page=100`)
  const newest = new Map()
  for (const check of checks.check_runs || []) {
    if (!newest.has(check.name) || check.id > newest.get(check.name).id) newest.set(check.name, check)
  }
  for (const name of contexts) {
    const check = newest.get(name)
    assert.ok(check?.status === 'completed' && check.conclusion === 'success',
      `The tested image revision has not passed required check: ${name}`)
  }
  return { sourceRevision: expectedRevision, ownedForkVerified: true, requiredChecksPassed: true }
}
