import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

spec=importlib.util.spec_from_file_location('local_launcher',Path(__file__).resolve().parents[1]/'scripts/local_appliance.py')
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)


class LocalLauncherTests(unittest.TestCase):
    def test_ports_loopback_and_no_owner_mount_in_services(self):
        config={'services':{name:{'build':'.','volumes':['bad']} for name in ('app','initialize','admin','postgres')}}
        config['services']['postgres']['healthcheck']={}
        config['services']['admin']['networks']=['private']
        result=launcher.local_config(config,'tacacs-local-'+'a'*32)
        services=result['services']
        self.assertEqual(services['app']['ports'],['127.0.0.1:49:49/tcp'])
        self.assertEqual(services['postgres']['ports'],['127.0.0.1:8443:8443/tcp'])
        self.assertEqual(services['admin']['network_mode'],'service:postgres')
        self.assertNotIn('networks',services['admin'])
        self.assertIn('127.0.0.1',services['postgres']['healthcheck']['test'])
        for name in ('app','admin'):
            self.assertFalse(any('provision' in mount for mount in services[name]['volumes']))
        self.assertNotIn('volumes',services['proxy'])
        self.assertNotIn('ports',services['proxy'])
        self.assertEqual(services['proxy']['cap_drop'],['ALL'])
        self.assertEqual(services['proxy']['network_mode'],'service:postgres')

    def test_generated_files_protected_distinct_and_sha256_enrollment(self):
        try:import cryptography
        except ImportError:self.skipTest('cryptography unavailable')
        files,certificate=launcher.prepare_files(str(uuid4()),'198.51.100.1')
        decode=lambda name:base64.b64decode(files[name][0])
        self.assertEqual(len(decode('/admin/admin_totp')),32)
        self.assertIn(b'BEGIN CERTIFICATE',certificate)
        access=json.loads(decode('/provision/operator-access.json'))
        self.assertGreaterEqual(len(access['password']),48)
        self.assertIn('algorithm=SHA256',access['totp_uri'])
        self.assertNotEqual(decode('/provision/aaa_password'),decode('/provision/admin_password'))
        for name,(_,uid,mode) in files.items():
            if not name.endswith(('.toml','.pem')) or name.endswith('key.pem'):
                self.assertEqual(mode,0o600,name)
        self.assertEqual(files['/provision/operator-access.json'][1],0)

    def test_invalid_gateway_rejected(self):
        with self.assertRaises(ValueError):launcher.prepare_files(str(uuid4()),'0.0.0.0; unexpected')

    def test_existing_installation_never_reinitialized(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(launcher,'run') as run:
            with self.assertRaises(ValueError):launcher.initialize(Path(directory))
            run.assert_not_called()

    def test_incomplete_install_never_starts_or_overwrites(self):
        with patch.object(launcher,'run') as run:
            with self.assertRaises(ValueError):launcher.start(Path('unused'),{'factor':None})
            run.assert_not_called()

    def test_state_requires_exact_project_and_valid_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.json'
            item=dict(project='tacacs-local-'+'a'*32,tenant=str(uuid4()),user=None,factor=None)
            path.write_text(json.dumps(item))
            self.assertEqual(launcher.state(Path(directory)),item)
            for invalid in (item|{'project':'other'},item|{'factor':'invalid'},item|{'password':'secret'}):
                path.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):launcher.state(Path(directory))
