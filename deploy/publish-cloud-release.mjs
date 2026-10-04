import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertReleaseProvenance } from './release-provenance.mjs'

const deploy = dirname(fileURLToPath(import.meta.url))
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
  '-o', 'ConnectTimeout=15', '-o', 'StrictHostKeyChecking=yes', 'ubuntu@43.165.175.45']
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
if (process.argv.includes('--check-only') || current.imageID === receipt.imageID) {
  console.log(JSON.stringify({ localGatePassed: true, cloud: current,
    alreadySameImage: current.imageID === receipt.imageID, changed: false }))
  process.exit(0)
}
// Stream only the tested image, never the personal database or local keyring.
const source = spawn(docker, ['save', receipt.imageID], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
const sink = spawn(ssh, [...connection, 'sudo -n docker load'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
source.stdout.pipe(sink.stdin)
sink.stdin.on('error', () => {})
source.stderr.resume(); sink.stderr.resume(); sink.stdout.resume()
const codes = await Promise.all([new Promise(resolve => source.on('close', resolve)), new Promise(resolve => sink.on('close', resolve))])
assert.ok(codes.every(code => code === 0), 'Tested image transfer failed')
const result = remote(`import json,subprocess,pathlib,datetime,time,sys,yaml,urllib.request\nroot=pathlib.Path('/home/ubuntu/sub2api')\nimage=${JSON.stringify(receipt.imageID)}\nversion=${JSON.stringify(receipt.version)}\nrun=lambda a: subprocess.check_output(a,text=True)\nold=json.loads(run(['docker','inspect','sub2api']))[0]\nif not old['HostConfig']['ReadonlyRootfs']: sys.exit(1)\npath=root/'sub2api.override.yaml'\nconfig=yaml.safe_load(path.read_text())\nif not isinstance(config.get('services',{}).get('sub2api'),dict): sys.exit(1)\nsubprocess.run(['systemctl','start','sub2api-backup.service'],check=True,capture_output=True)\nbackup=root/('sub2api.override.before-local-promotion-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.yaml')\nbackup.write_bytes(path.read_bytes()); backup.chmod(0o600)\nconfig['services']['sub2api']['image']=image\npending=path.with_suffix('.promotion.tmp'); pending.write_text(yaml.safe_dump(config,sort_keys=False));pending.chmod(0o600);pending.replace(path)\nsubprocess.run(['docker','compose','--project-directory',str(root),'--env-file',str(root/'.env'),'-f',str(root/'docker-compose.local.yml'),'-f',str(path),'up','-d','--no-deps','--no-build','--pull','never','sub2api'],check=True,capture_output=True)\nnew=None\nfor i in range(90):\n c=json.loads(run(['docker','inspect','sub2api']))[0]\n if c['State'].get('Health',{}).get('Status')=='healthy': new=c; break\n time.sleep(1)\nif new is None or new['Image']!=image: sys.exit(1)\nif sorted(old['Config']['Env'])!=sorted(new['Config']['Env']): sys.exit(1)\nif old['HostConfig']['ReadonlyRootfs']!=new['HostConfig']['ReadonlyRootfs'] or old['Mounts']!=new['Mounts']: sys.exit(1)\nsettings=json.loads(run(['docker','exec','sub2api','wget','-qO-','http://127.0.0.1:8080/api/v1/settings/public']))['data']\nif settings['version']!=version: sys.exit(1)\nprint(json.dumps({'passed':True,'imageID':new['Image'],'version':settings['version'],'cloudSecretsAndMountsPreserved':True,'overrideBackup':str(backup)}))\n`)
const promotedSourceRevision = remote(`import json,subprocess\nc=json.loads(subprocess.check_output(['docker','inspect','sub2api']))[0]\nprint((c.get('Config',{}).get('Labels') or {}).get('org.opencontainers.image.revision',''))\n`)
assert.equal(promotedSourceRevision, tested.sourceRevision, 'Cloud image source revision differs from the tested release')
console.log(result)
