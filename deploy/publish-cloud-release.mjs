import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertReleaseProvenance } from './release-provenance.mjs'
import { transferImage } from './image-transfer.mjs'

const sourceDeploy = dirname(fileURLToPath(import.meta.url))
const deploy = process.env.SUB2API_RUNTIME_ROOT ? join(resolve(process.env.SUB2API_RUNTIME_ROOT), 'deploy') : sourceDeploy
const receipt = JSON.parse(readFileSync(join(deploy, '.local-release.json'), 'utf8'))
assert.ok(receipt.passed && /^sha256:[a-f0-9]{64}$/.test(receipt.imageID), 'Local acceptance is missing')
const docker = join(process.env.LOCALAPPDATA, 'Programs/DockerDesktop/resources/bin/docker.exe')
const tested = JSON.parse(readFileSync(receipt.reportPath, 'utf8'))
assert.ok(tested.passed && tested.imageID === receipt.imageID, 'The local acceptance report differs from this release')
assert.match(tested.sourceRevision || '', /^[0-9a-f]{40}$/, 'The local acceptance report lacks the source revision')
const imageMetadata = JSON.parse(execFileSync(docker, ['image', 'inspect', receipt.imageID],
  { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }))[0]
assertReleaseProvenance(imageMetadata.Config.Labels || {}, tested.sourceRevision)
const localImage = execFileSync(docker, ['inspect', 'sub2api', '--format', '{{.Image}}'], { encoding: 'utf8', windowsHide: true }).trim()
assert.equal(localImage, receipt.imageID, 'Install and test this image locally before cloud promotion')
const localHealth = await fetch('http://127.0.0.1:8080/health', { signal: AbortSignal.timeout(5000) })
assert.ok(localHealth.ok && (await localHealth.json()).status === 'ok', 'Local application health check failed')
const ssh = 'C:/Windows/System32/OpenSSH/ssh.exe'
const connection = ['-i', 'D:/Downloads/Chrome/zynexus_shop_tokyo.pem', '-o', 'BatchMode=yes',
  '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3', '-o', 'StrictHostKeyChecking=yes', 'ubuntu@43.165.175.45']
function remote(source) {
  try { return execFileSync(ssh, [...connection, 'sudo -n python3 -'], { input: source,
    encoding: 'utf8', windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }).trim() }
  catch { throw new Error('Cloud promotion command failed; private diagnostic output was not printed') }
}
const current = JSON.parse(remote(`import subprocess,json\nc=json.loads(subprocess.check_output(['docker','inspect','sub2api']))[0]\ne=dict(v.split('=',1) for v in c['Config']['Env'])\nprint(json.dumps({'imageID':c['Image'],'healthy':c['State']['Health']['Status']=='healthy','strict':e.get('ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED')=='true' and e.get('ACCOUNT_CREDENTIAL_ALLOW_LEGACY')=='false','readonlyRoot':c['HostConfig']['ReadonlyRootfs']}))\n`))
assert.ok(current.healthy && current.strict && current.readonlyRoot, 'Cloud protection must be healthy before promotion')
const currentSourceRevision = remote(`import json,subprocess\nc=json.loads(subprocess.check_output(['docker','inspect','sub2api']))[0]\nprint((c.get('Config',{}).get('Labels') or {}).get('org.opencontainers.image.revision',''))\n`)
if (!/^[0-9a-f]{40}$/.test(currentSourceRevision)) {
  throw new Error('The current cloud image has an invalid source revision label')
}
if (current.imageID !== receipt.imageID) {
  assert.ok(tested.rollbackCompatibleImageIDs?.includes(current.imageID), 'Verify the current cloud image against the migrated local fixture before promotion')
}
if (process.argv.includes('--check-only') || current.imageID === receipt.imageID) {
  console.log(JSON.stringify({ localGatePassed: true, cloud: current,
    alreadySameImage: current.imageID === receipt.imageID, changed: false }))
  process.exit(0)
}
// Stream only the tested image, never the personal database or local keyring.
const source = spawn(docker, ['save', receipt.imageID], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
const sink = spawn(ssh, [...connection, 'sudo -n docker load'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
await transferImage(source, sink)
const request = { image: receipt.imageID, version: receipt.version, revision: tested.sourceRevision, expected_previous: current.imageID }
const script = 'REQUEST_JSON = ' + JSON.stringify(JSON.stringify(request)) + String.fromCharCode(10) + readFileSync(join(sourceDeploy, 'cloud_release_transaction.py'), 'utf8')
const result = JSON.parse(remote(script))
assert.ok(result.passed, 'Cloud promotion failed: ' + JSON.stringify(result))
const promotedSourceRevision = remote(`import json,subprocess\nc=json.loads(subprocess.check_output(['docker','inspect','sub2api']))[0]\nprint((c.get('Config',{}).get('Labels') or {}).get('org.opencontainers.image.revision',''))\n`)
assert.equal(promotedSourceRevision, tested.sourceRevision, 'Cloud image source revision differs from the tested release')
console.log(JSON.stringify(result))
