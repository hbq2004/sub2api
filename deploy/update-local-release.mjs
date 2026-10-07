import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, existsSync, cpSync, rmSync, renameSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyBindingHash } from './key-integrity.mjs'

const deploy = dirname(fileURLToPath(import.meta.url))
const root = dirname(deploy)
const args = process.argv.slice(2)
const option = name => args[args.indexOf(name) + 1]
const image = args.includes('--image') ? option('--image') : ''
const expectedVersion = args.includes('--version') ? option('--version') : ''
assert.ok(image && /^[\w.:/@-]+$/.test(image), 'Provide --image with an existing custom image')
assert.ok(expectedVersion && /^[\w.-]+$/.test(expectedVersion), 'Provide --version')
const docker = process.env.SUB2API_DOCKER || join(process.env.LOCALAPPDATA, 'Programs/DockerDesktop/resources/bin/docker.exe')
const stamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14)
const privateDirectory = join(deploy, 'private-credentials')
const recoveryDirectory = join(deploy, 'tokyo-shared/private-backups/local-releases', stamp)
const work = join(privateDirectory, `release-${stamp}`)
const reportDirectory = join(root, 'output/local-release', stamp)
const releaseFile = join(deploy, '.local-release.json')
const poolPolicyFile = join(deploy, 'upstream-pool-policy.json')
const keyring = join(privateDirectory, 'local-upstream-credential-keyring.json')
const runtimeFile = join(privateDirectory, 'local-runtime.env')
const keyVolume = 'sub2api-local-credential-keys'
const fixtureNetwork = `sub2api-local-qa-${stamp}`
const fixturePG = `${fixtureNetwork}-pg`
const fixtureRedis = `${fixtureNetwork}-redis`
const fixtureApp = `${fixtureNetwork}-app`
const fixtureProxy = `${fixtureNetwork}-proxy`
const fixturePort = 18089
const resources = []
const report = { startedAt: new Date().toISOString(), expectedVersion, checks: [], passed: false }
let networkCreated = false
let writersStopped = false
let migrationCommitted = false
let activated = false

function execute(binary, arguments_, options = {}) {
  try {
    return execFileSync(binary, arguments_, { cwd: root, windowsHide: true,
      maxBuffer: 256 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'], ...options })
  } catch {
    // Commands can carry database credentials in stdin or private files.
    throw new Error(`${binary.split(/[\\/]/).at(-1)} operation failed (${arguments_[0]}); private diagnostic data was not printed`)
  }
}
const d = (arguments_, options) => execute(docker, arguments_, { encoding: 'utf8', ...options }).trim()
const inspect = name => JSON.parse(d(['inspect', name]))[0]
const normalizedBindPath = path => path.replaceAll('\\', '/').toLowerCase()
  .replace(/^\/run\/desktop\/mnt\/host\/([a-z])\//, '$1:/')
const envMap = items => Object.fromEntries(items.map(item => {
  const index = item.indexOf('='); return [item.slice(0, index), item.slice(index + 1)]
}))
function writeEnvironment(path, environment) {
  const lines = Object.entries(environment).map(([key, value]) => {
    assert.ok(!/[\r\n]/.test(String(value)), 'Environment contains unsupported line breaks')
    return `${key}=${value}`
  })
  writeFileSync(path, lines.join('\n') + '\n', { mode: 0o600 })
}
const delay = ms => new Promise(resolve_ => setTimeout(resolve_, ms))
function record(name) { report.checks.push(name); console.log(`PASS ${name}`) }
async function waitHTTP(origin) {
  for (let attempt = 0; attempt < 90; attempt++) {
    try {
      const response = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(2000) })
      if (response.ok && (await response.json()).status === 'ok') return
    } catch {}
    await delay(1000)
  }
  throw new Error(`Application did not become healthy at ${origin}`)
}
const sql = (container, query, user = 'sub2api') => d(['exec', container, 'psql', '-U', user, '-d', 'sub2api', '-X', '-At', '-c', query])
function integrity(container, user = 'sub2api') {
  const result = JSON.parse(sql(container, `SELECT json_build_object(
    'users',(SELECT count(*) FROM users), 'accounts',(SELECT count(*) FROM accounts),
    'groups',(SELECT count(*) FROM groups), 'api_keys',(SELECT count(*) FROM api_keys),
    'redeem_codes',(SELECT count(*) FROM redeem_codes),
    'user_accounting',(SELECT md5(string_agg(id::text || ':' || email || ':' || password_hash || ':' || balance::text,'|' ORDER BY id)) FROM users))`, user))
  const protectedColumns = sql(container, "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='api_keys' AND column_name='key_ciphertext')", user) === 't'
  const rows = JSON.parse(sql(container, `SELECT coalesce(json_agg(r ORDER BY r.id),'[]') FROM
    (SELECT id,user_id,group_id,status,key,deleted_at IS NOT NULL AS deleted,
      ${protectedColumns ? 'key_ciphertext' : "''::text AS key_ciphertext"} FROM api_keys) r`, user))
  const ring = existsSync(keyring) ? JSON.parse(readFileSync(keyring, 'utf8')) : null
  result.key_bindings = keyBindingHash(rows, ring)
  return result
}
function protection(container, user = 'sub2api') {
  return JSON.parse(sql(container, `SELECT json_build_object(
    'accounts',(SELECT count(*) FROM accounts),
    'encrypted_accounts',(SELECT count(*) FROM accounts WHERE credentials ? '__sub2api_credentials'),
    'redeem_codes',(SELECT count(*) FROM redeem_codes),
    'protected_codes',(SELECT count(*) FROM redeem_codes WHERE code_hash IS NOT NULL AND code_key_version = 1))`, user))
}
function encryptRecovery(path) {
  execute(process.env.SUB2API_PWSH || 'pwsh.exe', ['-NoProfile', '-NonInteractive', '-File',
    join(deploy, 'Protect-ReleaseFile.ps1'), '-Source', path])
}
function backup(label) {
  const directory = join(work, label)
  mkdirSync(directory, { recursive: true })
  const dump = execute(docker, ['exec', 'sub2api-postgres', 'pg_dump', '-U', 'sub2api', '-d', 'sub2api', '-Fc'])
  writeFileSync(join(directory, 'database.dump'), dump, { mode: 0o600 })
  execute('tar.exe', ['-czf', join(directory, 'app-state.tgz'), '--exclude=data/logs',
    '--exclude=data/*.dump', '-C', deploy, '.env', 'data'])
  d(['exec', 'sub2api-redis', 'redis-cli', 'SAVE'])
  d(['cp', 'sub2api-redis:/data/dump.rdb', join(directory, 'redis.rdb')])
  const target = join(recoveryDirectory, `${label}.tgz`)
  execute('tar.exe', ['-czf', target, '-C', directory, 'database.dump', 'app-state.tgz', 'redis.rdb'])
  encryptRecovery(target)
  rmSync(target)
  return directory
}
function installKeys(imageID, currentEnvironment) {
  if (!existsSync(runtimeFile)) {
    const pair = {
      REDEEM_CODE_HMAC_KEY: currentEnvironment.REDEEM_CODE_HMAC_KEY || randomBytes(32).toString('hex'),
      REDEEM_CODE_ENCRYPTION_KEY: currentEnvironment.REDEEM_CODE_ENCRYPTION_KEY || randomBytes(32).toString('hex'),
      ACCOUNT_CREDENTIAL_KEYRING_FILE: '/run/sub2api-secrets/upstream-credential-keyring.json',
      ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED: 'true', ACCOUNT_CREDENTIAL_ALLOW_LEGACY: 'false',
    }
    writeEnvironment(runtimeFile, pair)
  }
  if (!existsSync(keyring)) {
    assert.ok(!currentEnvironment.ACCOUNT_CREDENTIAL_KEYRING_FILE,
      'Recover the existing local keyring first; an encrypted installation must not get new roots')
    writeFileSync(keyring, JSON.stringify({ active_key_id: 'local-v1',
      encryption_keys: { 'local-v1': randomBytes(32).toString('hex') },
      lookup_key: randomBytes(32).toString('hex') }), { mode: 0o600 })
  }
  execute('icacls.exe', [privateDirectory, '/inheritance:r', '/grant:r', `${process.env.USERDOMAIN}\\${process.env.USERNAME}:(OI)(CI)F`])
  d(['volume', 'create', keyVolume])
  d(['run', '--rm', '--network', 'none', '--user', '0:0', '--entrypoint', '/bin/sh',
    '-v', `${privateDirectory}:/source:ro`, '-v', `${keyVolume}:/keys`, imageID, '-c',
    'cp /source/local-upstream-credential-keyring.json /keys/upstream-credential-keyring.json && chown 1000:1000 /keys/upstream-credential-keyring.json && chmod 0400 /keys/upstream-credential-keyring.json'])
  const capsule = join(recoveryDirectory, 'local-encryption-roots.tgz')
  execute('tar.exe', ['-czf', capsule, '-C', privateDirectory, 'local-upstream-credential-keyring.json', 'local-runtime.env'])
  encryptRecovery(capsule)
  rmSync(capsule)
}
function migrate(imageID, environment, network, label) {
  const envPath = join(work, `${label}-migration.env`)
  writeEnvironment(envPath, { ...environment, ACCOUNT_CREDENTIAL_ALLOW_LEGACY: 'true' })
  const output = d(['run', '--rm', '--network', network, '--user', '1000:1000',
    '--env-file', envPath, '-v', `${keyVolume}:/run/sub2api-secrets:ro`,
    '--entrypoint', '/app/credential-migrate', imageID, '-mode', 'encrypt',
    '-apply', '-writers-stopped', '-purge-cache'])
  assert.ok(JSON.parse(output), 'Credential migration report is missing')
}
async function api(origin, method, path, data, token) {
  const response = await fetch(`${origin}/api/v1${path}`, {
    method, signal: AbortSignal.timeout(15000), headers: { 'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }) })
  return { status: response.status, body: await response.json() }
}
async function verifyPersonalAPI(origin) {
  const key = sql('sub2api-postgres',
    'SELECT key FROM api_keys WHERE deleted_at IS NULL ORDER BY id LIMIT 1')
  assert.ok(key, 'No local personal API key exists')
  const response = await fetch(`${origin}/v1/models`, {
    headers: { Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(15000) })
  assert.equal(response.status, 200, 'Local personal API key /v1/models check')
  record('Existing personal API key still serves the local /v1 endpoint')
}
function verifyDebugOwnership() {
  const policy = JSON.parse(readFileSync(poolPolicyFile, 'utf8'))
  if (policy.mode !== 'cloud-primary') return false
  assert.equal(policy.local_runtime, 'debug-only', 'Cloud-primary local runtime must remain debug-only')
  const ceiling = policy.local_production_account_id_ceiling
  assert.ok(Number.isSafeInteger(ceiling) && ceiling > 0, 'Local production identity boundary is missing')
  const counts = JSON.parse(sql('sub2api-postgres', `SELECT json_build_object(
    'active',count(*) FILTER (WHERE status='active'),
    'schedulable',count(*) FILTER (WHERE schedulable))
    FROM accounts WHERE deleted_at IS NULL AND id <= ${ceiling}`))
  assert.equal(counts.active, 0, 'Retained production accounts must stay disabled locally')
  assert.equal(counts.schedulable, 0, 'Retained production accounts must stay unschedulable locally')
  report.cloudPrimary = true
  report.localProductionOwnership = counts
  return true
}
async function verifyFixtureAPI(origin) {
  const email = `release-admin-${stamp}@example.invalid`
  const password = randomBytes(24).toString('base64url') + 'aA1!'
  sql(fixturePG, `CREATE EXTENSION IF NOT EXISTS pgcrypto;
    INSERT INTO users(email,password_hash,role,balance,concurrency,status,
      username,notes,created_at,updated_at,totp_enabled,signup_source,restrict_public_groups,
      balance_notify_enabled,balance_notify_threshold_type,balance_notify_extra_emails,total_recharged,rpm_limit,frozen_balance)
    VALUES ('${email}',crypt('${password}',gen_salt('bf',10)),'admin',0,5,'active','','isolated release acceptance',
      NOW(),NOW(),false,'email',false,false,'fixed','[]',0,0,0);
    INSERT INTO settings(key,value) VALUES ('step_up_enabled','false'),('session_binding_enabled','false'),
      ('turnstile_enabled','false'),('tencent_captcha_enabled','false'),('aliyun_captcha_enabled','false')
    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;`, 'postgres')
  d(['restart', fixtureApp])
  await waitHTTP(origin)
  const adminLogin = await api(origin, 'POST', '/auth/login', { email, password })
  assert.equal(adminLogin.status, 200, 'Synthetic administrator login')
  const token = adminLogin.body.data?.access_token
  assert.ok(token, 'Synthetic administrator session is missing')
  assert.equal((await api(origin, 'GET', '/auth/me', undefined, token)).status, 200)
  // This acknowledgement belongs only to the disposable fixture identity.
  const compliance = await api(origin, 'GET', '/admin/compliance', undefined, token)
  if (compliance.body.data?.required) {
    assert.equal((await api(origin, 'POST', '/admin/compliance/accept', {
      phrase: compliance.body.data.ack_phrase_en, language: 'en' }, token)).status, 200)
  }
  for (const path of ['/admin/groups', '/admin/accounts', '/keys', '/admin/redeem-codes']) {
    assert.equal((await api(origin, 'GET', path, undefined, token)).status, 200, `Fixture ${path}`)
  }
  record('Migrated accounts, groups, personal keys and protected redeem codes are readable')
  const userEmail = `local-release-${stamp}@example.invalid`
  const userPassword = randomBytes(24).toString('base64url') + 'aA1!'
  assert.equal((await api(origin, 'POST', '/admin/users', { email: userEmail, password: userPassword, role: 'user', balance: 0, concurrency: 1 }, token)).status, 200)
  const login = await api(origin, 'POST', '/auth/login', { email: userEmail, password: userPassword })
  assert.equal(login.status, 200)
  const userToken = login.body.data.access_token
  assert.ok(userToken)
  assert.equal((await api(origin, 'GET', '/admin/users', undefined, userToken)).status, 403)
  record('Synthetic user login and administrator authorization boundary')
  const generated = await api(origin, 'POST', '/admin/redeem-codes/generate', { count: 1, type: 'balance', value: 1 }, token)
  assert.equal(generated.status, 200)
  const code = generated.body.data[0].code
  assert.ok(code && code !== '********')
  assert.equal((await api(origin, 'POST', '/redeem', { code }, userToken)).status, 200)
  assert.ok((await api(origin, 'POST', '/redeem', { code }, userToken)).status >= 400)
  const history = await api(origin, 'GET', '/redeem/history', undefined, userToken)
  const rows = Array.isArray(history.body.data) ? history.body.data : history.body.data.items
  assert.ok(rows.every(row => row.code !== code))
  record('Synthetic code redemption, replay rejection and masked history')
  return token
}
function cleanupWork() {
  const absolute = resolve(work)
  assert.ok(absolute.startsWith(resolve(privateDirectory) + '\\'), 'Cleanup escaped private staging')
  if (existsSync(absolute)) rmSync(absolute, { recursive: true, force: true })
}

try {
  for (const directory of [privateDirectory, recoveryDirectory, work, reportDirectory]) mkdirSync(directory, { recursive: true })
  const imageInfo = JSON.parse(d(['image', 'inspect', image]))[0]
  const imageID = imageInfo.Id
  const sourceRevision = imageInfo.Config?.Labels?.['org.opencontainers.image.revision'] || ''
  assert.match(sourceRevision, /^[0-9a-f]{40}$/, 'Image must carry the full source revision label')
  const current = inspect('sub2api')
  const currentEnvironment = envMap(current.Config.Env)
  assert.ok(current.Mounts.some(mount => mount.Type === 'bind' && mount.Destination === '/app/data' &&
    normalizedBindPath(mount.Source) === normalizedBindPath(join(deploy, 'data'))), 'Local data owner differs from this checkout')
  report.imageID = imageID
  report.sourceRevision = sourceRevision
  report.previousImageID = current.Image
  const cloudPrimary = verifyDebugOwnership()
  const initial = integrity('sub2api-postgres')
  const baselineDirectory = backup('before-rehearsal')
  installKeys(imageID, currentEnvironment)
  record('Local recovery backup and independent encryption roots encrypted and verified')
  record('Custom image carries an immutable source revision label')
  const securityEnvironment = envMap(readFileSync(runtimeFile, 'utf8').trim().split(/\r?\n/))
  const pgImage = inspect('sub2api-postgres').Image
  const redisImage = inspect('sub2api-redis').Image
  d(['network', 'create', '--internal', fixtureNetwork]); networkCreated = true
  d(['run', '-d', '--rm', '--name', fixturePG, '--network', fixtureNetwork,
    '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_DB=sub2api', pgImage]); resources.push(fixturePG)
  for (let attempt = 0; attempt < 40; attempt++) {
    try { d(['exec', fixturePG, 'pg_isready', '-U', 'postgres', '-d', 'sub2api']); break }
    catch { if (attempt === 39) throw new Error('Fixture PostgreSQL did not start'); await delay(1000) }
  }
  d(['cp', join(baselineDirectory, 'database.dump'), `${fixturePG}:/tmp/database.dump`])
  d(['exec', fixturePG, 'pg_restore', '-U', 'postgres', '-d', 'sub2api', '--no-owner', '--no-privileges', '--exit-on-error', '/tmp/database.dump'])
  d(['run', '-d', '--rm', '--name', fixtureRedis, '--network', fixtureNetwork, redisImage]); resources.push(fixtureRedis)
  const fixtureEnvironment = { ...currentEnvironment, ...securityEnvironment,
    DATABASE_HOST: fixturePG, DATABASE_USER: 'postgres', DATABASE_PASSWORD: 'fixture',
    DATABASE_DBNAME: 'sub2api', REDIS_HOST: fixtureRedis, REDIS_PASSWORD: '',
    TOKEN_REFRESH_ENABLED: 'false', SERVER_HOST: '0.0.0.0', SERVER_PORT: '8080',
    ACCOUNT_CREDENTIAL_MIGRATION_DSN: `postgres://postgres:fixture@${fixturePG}:5432/sub2api?sslmode=disable`,
    ACCOUNT_CREDENTIAL_MIGRATION_REDIS_ADDR: `${fixtureRedis}:6379`,
    ACCOUNT_CREDENTIAL_MIGRATION_REDIS_PASSWORD: '', ACCOUNT_CREDENTIAL_MIGRATION_REDIS_DB: '0' }
  migrate(imageID, fixtureEnvironment, fixtureNetwork, 'fixture')
  const fixtureData = join(work, 'fixture-data')
  cpSync(join(deploy, 'data'), fixtureData, { recursive: true,
    filter: path => !path.includes('\\logs') && !/\.(dump|txt)$/.test(path) })
  const fixtureEnvPath = join(work, 'fixture.env')
  writeEnvironment(fixtureEnvPath, fixtureEnvironment)
  d(['run', '-d', '--rm', '--name', fixtureApp, '--network', fixtureNetwork,
    '--env-file', fixtureEnvPath, '-v', `${fixtureData}:/app/data`,
    '-v', `${keyVolume}:/run/sub2api-secrets:ro`, imageID]); resources.push(fixtureApp)
  // Docker does not publish ports on an internal network. Only this credential-
  // free HTTP relay joins bridge; the application and its database keep no egress.
  const proxyCode = `const http=require('node:http'); http.createServer((req,res)=>{const upstream=http.request({hostname:'${fixtureApp}',port:8080,path:req.url,method:req.method,headers:req.headers},response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res)});upstream.on('error',()=>{res.writeHead(502);res.end()});req.pipe(upstream)}).listen(8080,'0.0.0.0')`
  d(['create', '--name', fixtureProxy, '--network', 'bridge', '-p', `127.0.0.1:${fixturePort}:8080`,
    '--entrypoint', 'node', 'node:24-alpine', '-e', proxyCode]); resources.push(fixtureProxy)
  d(['network', 'connect', fixtureNetwork, fixtureProxy])
  d(['start', fixtureProxy])
  const fixtureOrigin = `http://127.0.0.1:${fixturePort}`
  await waitHTTP(fixtureOrigin)
  const settings = await api(fixtureOrigin, 'GET', '/settings/public')
  assert.equal(settings.body.data.version, expectedVersion)
  assert.deepEqual(integrity(fixturePG, 'postgres'), initial)
  const protectedFixture = protection(fixturePG, 'postgres')
  assert.equal(protectedFixture.encrypted_accounts, protectedFixture.accounts)
  assert.equal(protectedFixture.protected_codes, protectedFixture.redeem_codes)
  record('Isolated schema and encryption migration preserves records, key bindings and balances')
  assert.equal((await api(fixtureOrigin, 'GET', '/admin/accounts')).status, 401)
  const fixtureAdminToken = await verifyFixtureAPI(fixtureOrigin)
  const browserCredentialFile = join(work, 'browser-credential.json')
  writeFileSync(browserCredentialFile, JSON.stringify({ token: fixtureAdminToken }), { mode: 0o600 })
  const browserOutput = execute(process.execPath, [join(deploy, 'verify-local-release.mjs'),
    '--origin', fixtureOrigin, '--version', expectedVersion, '--output', reportDirectory,
    '--credential-file', browserCredentialFile], { encoding: 'utf8' })
  const browserReport = JSON.parse(browserOutput)
  assert.ok(browserReport.passed)
  record('Desktop/mobile public and administrator browser regression')
  if (args.includes('--test-only')) {
    report.passed = true
    report.testOnly = true
  } else {
    d(['stop', '--time', '30', 'sub2api']); writersStopped = true
    const finalIntegrity = integrity('sub2api-postgres')
    backup('before-cutover')
    const runtimeNetwork = Object.keys(current.NetworkSettings.Networks)[0]
    const migrationEnvironment = { ...currentEnvironment, ...securityEnvironment,
      ACCOUNT_CREDENTIAL_MIGRATION_DSN: `postgres://${encodeURIComponent(currentEnvironment.DATABASE_USER)}:${encodeURIComponent(currentEnvironment.DATABASE_PASSWORD)}@${currentEnvironment.DATABASE_HOST}:5432/${currentEnvironment.DATABASE_DBNAME}?sslmode=disable`,
      ACCOUNT_CREDENTIAL_MIGRATION_REDIS_ADDR: `${currentEnvironment.REDIS_HOST}:6379`,
      ACCOUNT_CREDENTIAL_MIGRATION_REDIS_PASSWORD: currentEnvironment.REDIS_PASSWORD || '',
      ACCOUNT_CREDENTIAL_MIGRATION_REDIS_DB: currentEnvironment.REDIS_DB || '0' }
    migrate(imageID, migrationEnvironment, runtimeNetwork, 'live'); migrationCommitted = true
    d(['compose', '--project-directory', deploy, '--env-file', join(deploy, '.env'),
      '-f', join(deploy, 'docker-compose.local.yml'), '-f', join(deploy, 'docker-compose.local-sync.yml'),
      '-f', join(deploy, 'docker-compose.local-release.yml'), 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'sub2api'],
      { env: { ...process.env, SUB2API_LOCAL_IMAGE: imageID,
        JWT_SECRET: securityEnvironment.JWT_SECRET || currentEnvironment.JWT_SECRET,
        TOTP_ENCRYPTION_KEY: securityEnvironment.TOTP_ENCRYPTION_KEY || currentEnvironment.TOTP_ENCRYPTION_KEY,
        REDEEM_CODE_HMAC_KEY: securityEnvironment.REDEEM_CODE_HMAC_KEY,
        REDEEM_CODE_ENCRYPTION_KEY: securityEnvironment.REDEEM_CODE_ENCRYPTION_KEY,
        ACCOUNT_CREDENTIAL_KEYRING_FILE: securityEnvironment.ACCOUNT_CREDENTIAL_KEYRING_FILE,
        ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED: securityEnvironment.ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED,
        ACCOUNT_CREDENTIAL_ALLOW_LEGACY: 'false' } })
    activated = true
    await waitHTTP('http://127.0.0.1:8080')
    assert.equal((await api('http://127.0.0.1:8080', 'GET', '/settings/public')).body.data.version, expectedVersion)
    assert.equal(inspect('sub2api').Image, imageID)
    assert.deepEqual(integrity('sub2api-postgres'), finalIntegrity)
    const protectedLive = protection('sub2api-postgres')
    assert.equal(protectedLive.encrypted_accounts, protectedLive.accounts)
    assert.equal(protectedLive.protected_codes, protectedLive.redeem_codes)
    report.protection = protectedLive
    report.recordCounts = Object.fromEntries(Object.entries(finalIntegrity).filter(([key]) => !key.includes('_bindings') && !key.includes('_accounting')))
    record('Local :8080 runs the tested image with strict independent encryption and preserved personal data')
    if (cloudPrimary) {
      verifyDebugOwnership()
      record('Cloud-primary local production identities remain disabled; authenticated API acceptance used the isolated fixture')
    } else {
      await verifyPersonalAPI('http://127.0.0.1:8080')
    }
    const liveBrowser = JSON.parse(execute(process.execPath, [join(deploy, 'verify-local-release.mjs'),
      '--origin', 'http://127.0.0.1:8080', '--version', expectedVersion,
      '--output', join(reportDirectory, 'live')], { encoding: 'utf8' }))
    assert.ok(liveBrowser.passed)
    record('Actual local public UI desktop/mobile regression')
    report.passed = true
    const receipt = { formatVersion: 1, passed: true, imageID, version: expectedVersion,
      verifiedAt: new Date().toISOString(), previousImageID: current.Image,
      recoveryDirectory, reportPath: join(reportDirectory, 'report.json'),
      poolPolicyFile, customFeatures: 'cloud custom image retained; local encryption roots are independent' }
    writeFileSync(releaseFile + '.tmp', JSON.stringify(receipt, null, 2))
    renameSync(releaseFile + '.tmp', releaseFile)
  }
} catch (error) {
  report.error = error.message
  if (writersStopped && !migrationCommitted && !activated) {
    try { d(['start', 'sub2api']); report.previousRuntimeRestored = true } catch {}
  }
  if (migrationCommitted && !report.passed) {
    report.recoveryAction = 'Keep the new protected image and independent local roots. Do not restart the old plaintext binary against migrated data. Use the before-cutover encrypted backup for an isolated restore.'
  }
  console.error(error.message)
  process.exitCode = 1
} finally {
  for (const name of resources.reverse()) { try { d(['rm', '-f', name]) } catch {} }
  if (networkCreated) { try { d(['network', 'rm', fixtureNetwork]) } catch {} }
  cleanupWork()
  report.completedAt = new Date().toISOString()
  writeFileSync(join(reportDirectory, 'report.json'), JSON.stringify(report, null, 2))
  console.log(JSON.stringify({ passed: report.passed, imageID: report.imageID, version: expectedVersion,
    reportPath: join(reportDirectory, 'report.json') }))
}
