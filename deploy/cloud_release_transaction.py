"""Promote a tested custom image; recover the compatible previous runtime on failure."""
import datetime
import json
import pathlib
import re
import subprocess
import time

import yaml

OWNED_SOURCE = 'https://github.com/hbq2004/sub2api'
SCHEMA_QUERY = "SELECT coalesce(json_agg(json_build_object('filename',filename,'checksum',checksum) ORDER BY filename),'[]'::json) FROM schema_migrations"


def run(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()


def protected(state):
    environment = dict(item.split('=', 1) for item in state['Config']['Env'])
    return (state['HostConfig']['ReadonlyRootfs']
            and environment.get('ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED') == 'true'
            and environment.get('ACCOUNT_CREDENTIAL_ALLOW_LEGACY') == 'false')


def preserved(before, after):
    mounts = lambda state: sorted(state.get('Mounts', []), key=lambda item: item['Destination'])
    return (sorted(before['Config']['Env']) == sorted(after['Config']['Env'])
            and before['HostConfig'] == after['HostConfig']
            and mounts(before) == mounts(after)
            and sorted(before.get('NetworkSettings', {}).get('Networks', {}))
            == sorted(after.get('NetworkSettings', {}).get('Networks', {})))


def promote(root, image, version, revision, expected_previous, command=run, pause=time.sleep, attempts=90):
    root = pathlib.Path(root)
    path = root / 'sub2api.override.yaml'
    stage, changed, backup = 'preflight', False, None
    old, original, schema_before = None, None, None
    compose = ['docker', 'compose', '--project-directory', str(root), '--env-file', str(root / '.env'),
               '-f', str(root / 'docker-compose.local.yml'), '-f', str(path), 'up', '-d', '--no-deps',
               '--no-build', '--pull', 'never', 'sub2api']

    def inspect():
        return json.loads(command(['docker', 'inspect', 'sub2api']))[0]

    def schema():
        value = json.loads(command(['docker', 'exec', 'sub2api-postgres', 'psql', '-U', 'sub2api',
                                    '-d', 'sub2api', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', SCHEMA_QUERY]))
        if not isinstance(value, list):
            raise ValueError('invalid schema receipt')
        return value

    def wait_healthy(expected_image):
        for _ in range(attempts):
            state = inspect()
            if state['Image'] != expected_image or not state['State'].get('Running', True):
                raise ValueError('unexpected runtime')
            if state['State'].get('Health', {}).get('Status') == 'healthy':
                return state
            if state['State'].get('Status') in ('exited', 'dead'):
                raise ValueError('runtime stopped')
            pause(1)
        raise ValueError('runtime health timeout')

    def replace_override(data):
        pending = path.with_suffix('.promotion.tmp')
        pending.write_bytes(data)
        pending.chmod(0o600)
        pending.replace(path)

    try:
        if (not re.fullmatch(r'sha256:[a-f0-9]{64}', image)
                or not re.fullmatch(r'[a-f0-9]{40}', revision)
                or not re.fullmatch(r'[A-Za-z0-9.-]+', version)
                or path.is_symlink()):
            raise ValueError('invalid release input')
        old = inspect()
        if old['Image'] != expected_previous or not protected(old):
            raise ValueError('cloud baseline changed')
        if old['State'].get('Health', {}).get('Status') != 'healthy':
            raise ValueError('cloud baseline is unhealthy')
        candidate = json.loads(command(['docker', 'image', 'inspect', image]))[0]
        labels = candidate['Config'].get('Labels', {})
        if (candidate['Id'] != image or labels.get('org.opencontainers.image.revision') != revision
                or labels.get('org.opencontainers.image.source') != OWNED_SOURCE):
            raise ValueError('candidate provenance mismatch')
        original = path.read_bytes()
        config = yaml.safe_load(original)
        if not isinstance(config.get('services', {}).get('sub2api'), dict):
            raise ValueError('invalid live override')
        schema_before = schema()
        stage = 'backup'
        command(['systemctl', 'start', 'sub2api-backup.service'])
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup = root / ('sub2api.override.before-local-promotion-' + stamp + '.yaml')
        with backup.open('xb') as saved:
            saved.write(original)
        backup.chmod(0o600)
        stage = 'replace_override'
        config['services']['sub2api']['image'] = image
        replace_override(yaml.safe_dump(config, sort_keys=False).encode())
        changed = True
        stage = 'start'
        command(compose)
        stage = 'health'
        new = wait_healthy(image)
        stage = 'configuration'
        if not protected(new) or not preserved(old, new):
            raise ValueError('cloud configuration changed')
        if new['Config'].get('Labels', {}).get('org.opencontainers.image.revision') != revision:
            raise ValueError('runtime revision mismatch')
        stage = 'version'
        settings = json.loads(command(['docker', 'exec', 'sub2api', 'wget', '-qO-',
                                       'http://127.0.0.1:8080/api/v1/settings/public']))['data']
        if settings.get('version') != version:
            raise ValueError('runtime version mismatch')
        return {'passed': True, 'imageID': new['Image'], 'version': version,
                'cloudSecretsAndMountsPreserved': True, 'overrideBackup': str(backup)}
    except Exception:
        restored, rollback_blocked = False, changed
        if changed:
            try:
                if schema() == schema_before:
                    rollback_blocked = False
                    replace_override(original)
                    command(compose)
                    recovered = wait_healthy(old['Image'])
                    restored = protected(recovered) and preserved(old, recovered)
            except Exception:
                pass
        return {'passed': False, 'stage': stage, 'previousRuntimeRestored': restored,
                'rollbackBlocked': rollback_blocked, 'overrideBackup': str(backup) if backup else None,
                'diagnosticsSuppressed': True}


if __name__ == '__main__':
    import fcntl
    import os
    os.umask(0o077)
    root = pathlib.Path('/home/ubuntu/sub2api')
    request = json.loads(REQUEST_JSON)
    try:
        with (root / '.release-promotion.lock').open('a') as lock:
            (root / '.release-promotion.lock').chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = promote(root, request['image'], request['version'], request['revision'], request['expected_previous'])
    except Exception:
        result = {'passed': False, 'stage': 'promotion_lock', 'previousRuntimeRestored': False,
                  'rollbackBlocked': False, 'diagnosticsSuppressed': True}
    print(json.dumps(result))
