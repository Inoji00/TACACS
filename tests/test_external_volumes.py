import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from local_appliance import local_config
from repair_external_volumes import repair


class ExternalVolumesTests(unittest.TestCase):
    def config(self):
        services = {name: {} for name in ('app', 'initialize', 'admin', 'postgres')}
        services['postgres']['healthcheck'] = {}
        return local_config({'services': services}, 'tnac-' + 'a' * 32)

    def test_fresh_config_uses_external_secret_volumes(self):
        volumes = self.config()['volumes']
        for key in ('config', 'runtime', 'provision', 'dbsecret', 'admin'):
            self.assertTrue(volumes[key]['external'])
        self.assertEqual(volumes['postgres-data'], {})

    def test_existing_config_repair_preserves_services_and_is_idempotent(self):
        config = self.config()
        for volume in config['volumes'].values():
            volume.pop('external', None)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / 'compose.json'
            path.write_text(json.dumps(config), encoding='utf-8')
            with patch('repair_external_volumes.local.state', return_value={'project': 'tnac-' + 'a' * 32}), \
                 patch('repair_external_volumes.local.run'):
                repair(directory)
                updated = json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual(updated['services'], config['services'])
                self.assertEqual(updated['volumes']['postgres-data'], {})
                self.assertEqual(len(list(directory.glob('compose.json.before-external-*'))), 1)
                repair(directory)
                self.assertEqual(len(list(directory.glob('compose.json.before-external-*'))), 1)

    def test_missing_volume_preserves_existing_compose(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / 'compose.json'
            original = json.dumps(self.config())
            path.write_text(original, encoding='utf-8')
            with patch('repair_external_volumes.local.state', return_value={'project': 'tnac-' + 'a' * 32}), \
                 patch('repair_external_volumes.local.run', side_effect=RuntimeError('missing volume')):
                with self.assertRaises(RuntimeError):
                    repair(directory)
            self.assertEqual(path.read_text(encoding='utf-8'), original)
