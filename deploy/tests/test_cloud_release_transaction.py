import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

import yaml

spec = importlib.util.spec_from_file_location('cloud_release_transaction', pathlib.Path(__file__).resolve().parents[1] / 'cloud_release_transaction.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
OLD, NEW, REVISION = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64, 'b' * 40


class Fixture:
    def __init__(self, root, fault=None, schema_changed=False):
        self.root, self.fault, self.schema_changed = root, fault, schema_changed
        self.migrated, self.compose_calls = False, []
        self.config = {'services': {'sub2api': {'image': OLD, 'read_only': True, 'volumes': ['fixture:/app/data']}, 'other': {'image': 'fixture'}}}
        self.path = root / 'sub2api.override.yaml'
        self.path.write_text(yaml.safe_dump(self.config))
        self.original = self.path.read_bytes()
        self.state = {'Image': OLD, 'Config': {'Env': ['ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED=true', 'ACCOUNT_CREDENTIAL_ALLOW_LEGACY=false'], 'Labels': {}},
                      'HostConfig': {'ReadonlyRootfs': True}, 'Mounts': [{'Destination': '/app/data', 'RW': True}],
                      'NetworkSettings': {'Networks': {'fixture': {}}}, 'State': {'Running': True, 'Status': 'running', 'Health': {'Status': 'healthy'}}}
        self.baseline = copy.deepcopy(self.state)

    def command(self, args):
        if args[:3] == ['docker', 'image', 'inspect']:
            return json.dumps([{'Id': NEW, 'Config': {'Labels': {'org.opencontainers.image.revision': REVISION, 'org.opencontainers.image.source': release.OWNED_SOURCE}}}])
        if args[:2] == ['docker', 'inspect']:
            return json.dumps([self.state])
        if args[:3] == ['docker', 'exec', 'sub2api-postgres']:
            return json.dumps([{'filename': 'baseline.sql', 'checksum': 'fixture'}] + ([{'filename': 'new.sql', 'checksum': 'fixture'}] if self.migrated else []))
        if args[:3] == ['docker', 'exec', 'sub2api']:
            return json.dumps({'data': {'version': 'wrong' if self.fault == 'version' and self.state['Image'] == NEW else '0.2.14-custom'}})
        if args[:2] == ['systemctl', 'start']:
            if self.fault == 'backup':
                raise RuntimeError('synthetic backup failure')
            return ''
        if args[:2] == ['docker', 'compose']:
            image = yaml.safe_load(self.path.read_text())['services']['sub2api']['image']
            self.compose_calls.append(image)
            self.state = copy.deepcopy(self.baseline)
            self.state['Image'] = image
            self.state['Config']['Labels']['org.opencontainers.image.revision'] = REVISION if image == NEW else 'a' * 40
            if image == NEW:
                self.migrated = self.schema_changed
                if self.fault in ('compose', 'health'):
                    self.state['State']['Health']['Status'] = 'unhealthy'
                if self.fault == 'compose':
                    raise RuntimeError('synthetic compose failure')
                if self.fault == 'configuration':
                    self.state['Config']['Env'].append('SYNTHETIC=changed')
            return ''
        raise AssertionError('unexpected release command')

    def promote(self, previous=OLD):
        return release.promote(self.root, NEW, '0.2.14-custom', REVISION, previous, command=self.command, pause=lambda _: None, attempts=2)


class CloudReleaseRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='sub2api-release-qa-')
        self.addCleanup(self.work.cleanup)
        self.root = pathlib.Path(self.work.name)

    def test_success_changes_only_the_requested_image(self):
        fixture = Fixture(self.root)
        result = fixture.promote()
        self.assertTrue(result['passed'])
        expected = copy.deepcopy(fixture.config)
        expected['services']['sub2api']['image'] = NEW
        self.assertEqual(yaml.safe_load(fixture.path.read_text()), expected)
        self.assertEqual(pathlib.Path(result['overrideBackup']).read_bytes(), fixture.original)

    def check_recovery(self, fault):
        fixture = Fixture(self.root, fault=fault)
        result = fixture.promote()
        self.assertFalse(result['passed'])
        self.assertTrue(result['previousRuntimeRestored'])
        self.assertFalse(result['rollbackBlocked'])
        self.assertEqual(fixture.path.read_bytes(), fixture.original)
        self.assertEqual(fixture.state['Image'], OLD)
        self.assertEqual(fixture.compose_calls, [NEW, OLD])

    def test_compose_failure_restores_previous_runtime(self):
        self.check_recovery('compose')

    def test_health_timeout_restores_previous_runtime(self):
        self.check_recovery('health')

    def test_configuration_drift_restores_previous_runtime(self):
        self.check_recovery('configuration')

    def test_wrong_version_restores_previous_runtime(self):
        self.check_recovery('version')

    def test_schema_change_blocks_unsafe_old_image_rollback(self):
        fixture = Fixture(self.root, fault='health', schema_changed=True)
        result = fixture.promote()
        self.assertFalse(result['passed'])
        self.assertTrue(result['rollbackBlocked'])
        self.assertFalse(result['previousRuntimeRestored'])
        self.assertEqual(fixture.compose_calls, [NEW])

    def test_backup_failure_leaves_runtime_and_override_untouched(self):
        fixture = Fixture(self.root, fault='backup')
        result = fixture.promote()
        self.assertFalse(result['passed'])
        self.assertEqual(result['stage'], 'backup')
        self.assertEqual(fixture.path.read_bytes(), fixture.original)
        self.assertEqual(fixture.compose_calls, [])

    def test_changed_cloud_baseline_is_not_overwritten(self):
        fixture = Fixture(self.root)
        result = fixture.promote(previous='sha256:' + 'c' * 64)
        self.assertFalse(result['passed'])
        self.assertEqual(result['stage'], 'preflight')
        self.assertEqual(fixture.path.read_bytes(), fixture.original)
        self.assertEqual(fixture.compose_calls, [])


if __name__ == '__main__':
    unittest.main()
