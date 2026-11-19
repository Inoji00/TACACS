import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import vm_preflight


class SocketFixture:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def bind(self, address): pass


class PreflightTests(unittest.TestCase):
    def test_fresh_install_without_a_device_does_not_check_switch_route(self):
        def runner(args):
            self.assertEqual(args[0], 'docker')
            return '2.39.4'
        with tempfile.TemporaryDirectory() as directory, patch.object(vm_preflight.sys, 'platform', 'linux'):
            report = vm_preflight.check('192.0.2.10', root=Path(directory), runner=runner,
                                       binder=lambda *args: SocketFixture())
        self.assertTrue(report['ready_for_init'])
        self.assertNotIn('switch-route', {item['check'] for item in report['checks']})

    def test_host_only_rejects_existing_container_without_requiring_images(self):
        def runner(args):
            self.assertNotIn('image', args)
            if args[1] == 'ps':
                return 'tnac-admin\n'
            return '2.39.4'

        with tempfile.TemporaryDirectory() as directory, patch.object(vm_preflight.sys, 'platform', 'linux'):
            report = vm_preflight.check('192.0.2.10', root=Path(directory), runner=runner,
                                       binder=lambda *args: SocketFixture(), check_images=False)
        self.assertFalse(report['host_ready'])
        checks = {item['check']: item['status'] for item in report['checks']}
        self.assertEqual(checks['container-names-available'], 'FAIL')

    def test_pass_is_not_hardware_or_firewall_proof(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(vm_preflight.sys, 'platform', 'linux'):
            report = vm_preflight.check('192.0.2.10', '192.0.2.2', Path(directory),
                                       lambda args: '2.39.4', lambda *args: SocketFixture())
            self.assertTrue(report['ready_for_init'])
            self.assertIn('vendor-AAA-interoperability', report['not_verified'])

    def test_existing_state_and_command_failure_fail_closed_without_output(self):
        def failed(args): raise RuntimeError('SECRET-OUTPUT')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'data'/'vm-appliance').mkdir(parents=True)
            report = vm_preflight.check('192.0.2.10', '192.0.2.2', root, failed,
                                       lambda *args: SocketFixture())
            self.assertFalse(report['ready_for_init'])
            self.assertNotIn('SECRET-OUTPUT', str(report))
            state = next(item for item in report['checks'] if item['check'] == 'fresh-install-state')
            self.assertEqual(state['status'], 'FAIL')

    def test_bad_addresses_rejected_before_commands(self):
        with self.assertRaises(ValueError):
            vm_preflight.check('127.0.0.1', '192.0.2.2', runner=lambda args: self.fail('command ran'))
