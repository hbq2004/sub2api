// Read-only database audit. Credentials stay in child-process memory and are
// never printed, saved, or sent between the two installations.
import { execFileSync } from 'node:child_process'
import { buildPlan, normalizeSnapshot, selectAccounts } from './sync-local-to-cloud-core.mjs'
import { readState } from './sync-local-to-cloud.mjs'

const keyIndex = process.argv.indexOf('--ssh-key')
if (keyIndex < 0 || !process.argv[keyIndex + 1]) throw new Error('--ssh-key is required')
const sql = `BEGIN READ ONLY;
SELECT json_build_object(
  'groups', COALESCE((SELECT json_agg(g) FROM groups g WHERE deleted_at IS NULL), '[]'),
  'accounts', COALESCE((SELECT json_agg(a) FROM (
    SELECT id, name, notes, platform, type, credentials, extra, concurrency,
      priority, rate_multiplier, load_factor, status, schedulable,
      CASE WHEN error_message ILIKE '%token_revoked%' OR
        error_message ILIKE '%invalidated oauth token%' THEN 'token_revoked'
        WHEN error_message ILIKE '%account_deactivated%' THEN 'account_deactivated'
        WHEN error_message IS NULL OR error_message = '' THEN NULL ELSE 'other' END AS error_category,
      EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at, auto_pause_on_expired,
      COALESCE((SELECT json_agg(group_id ORDER BY group_id) FROM account_groups
        WHERE account_id = accounts.id), '[]') AS group_ids
    FROM accounts WHERE deleted_at IS NULL AND parent_account_id IS NULL
  ) a), '[]'));
ROLLBACK;`
const docker = 'C:\\Users\\hbq\\AppData\\Local\\Programs\\DockerDesktop\\resources\\bin\\docker.exe'
const psqlArgs = ['exec', '-i', 'sub2api-postgres', 'psql', '-X', '-qAt',
  '-v', 'ON_ERROR_STOP=1', '-U', 'sub2api', '-d', 'sub2api']
const options = { input: sql, encoding: 'utf8', timeout: 30000,
  maxBuffer: 16 * 1024 * 1024, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }
try {
  const local = JSON.parse(execFileSync(docker, psqlArgs, options))
  const cloud = JSON.parse(execFileSync('C:\\Windows\\System32\\OpenSSH\\ssh.exe',
    ['-i', process.argv[keyIndex + 1], '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
      '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes', 'ubuntu@43.165.175.45',
      'sudo docker exec -i sub2api-postgres psql -X -qAt -v ON_ERROR_STOP=1 -U sub2api -d sub2api'], options))
  const normalize = data => normalizeSnapshot({ groups: data.groups,
    accounts: data.accounts, accountData: { accounts: data.accounts }, keys: [] })
  const source = selectAccounts(normalize(local), local.accounts.map(account => account.id))
  const target = normalize(cloud)
  const plan = buildPlan(source, target, await readState())
  const counts = data => Object.fromEntries(['active', 'inactive', 'error'].map(status =>
    [status, data.accounts.filter(account => account.status === status).length]))
  console.log(JSON.stringify({ local: { accounts: local.accounts.length, statuses: counts(local) },
    cloud: { accounts: cloud.accounts.length, statuses: counts(cloud) },
    plan: Object.fromEntries(['create', 'update', 'skip', 'conflict'].map(action =>
      [action, plan.filter(row => row.action === action).length])),
    differences: plan.filter(row => row.action !== 'skip').map(row => ({ kind: row.kind,
      name: row.item.label, localId: row.item.id, cloudId: row.remote?.id ?? null,
      action: row.action, fields: row.differences })),
    errors: { local: local.accounts.filter(account => account.status === 'error').map(account =>
      ({ id: account.id, name: account.name, category: account.error_category })),
    cloud: cloud.accounts.filter(account => account.status === 'error').map(account =>
      ({ id: account.id, name: account.name, category: account.error_category })) }
  }, null, 2))
} catch (error) {
  // Child-process errors may contain output. Do not print those objects.
  const status = Number.isInteger(error?.status) ? `process exit ${error.status}` : 'snapshot validation'
  console.error(`Read-only audit failed (${status}); no source data was printed.`)
  process.exitCode = 1
}
