import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch,Mock
from contextlib import ExitStack
import signal
from tacacs_appliance.admin_runtime import load_config,main


class AdminRuntimeTests(unittest.TestCase):
    def run_composed(self,*,application_error=False,listener_error=False,cleanup_error=False,unexpected_stop=False,client_ca=None,tls_error=False):
        config=load_config(Path(__file__).resolve().parent/'fixtures/admin.example.toml')
        if client_ca is not None:config['client_ca_file']=client_ca
        pool=Mock();server=Mock();proxy=Mock();handlers={}
        def signals(number,handler):
            handlers[number]=handler
            return signal.SIG_DFL
        def serve():
            if listener_error:raise RuntimeError('sensitive-listener-value')
            if not unexpected_stop:handlers[signal.SIGTERM](signal.SIGTERM,None)
        server.serve_forever.side_effect=serve
        proxy.serve_forever.side_effect=serve
        if cleanup_error:server.server_close.side_effect=RuntimeError('sensitive-close-value')
        with ExitStack() as stack:
            stack.enter_context(patch('sys.argv',['admin','--config','admin.toml']))
            for name,value in [('load_config',config),
                               ('read_secret',b'dsn'),('ConnectionPool',pool),('AdminHttpsServer',server),
                               ('ProxiedAdminHttpsServer',proxy)]:
                stack.enter_context(patch('tacacs_appliance.admin_runtime.'+name,return_value=value))
            tls=stack.enter_context(patch('tacacs_appliance.admin_runtime.create_admin_tls_context'))
            if tls_error:tls.side_effect=ValueError('sensitive-invalid-ca')
            api=stack.enter_context(patch('tacacs_appliance.admin_runtime.build_admin_api'))
            if application_error:api.side_effect=RuntimeError('sensitive-database-value')
            stack.enter_context(patch('tacacs_appliance.admin_runtime.signal.signal',side_effect=signals))
            captured=stack.enter_context(self.assertLogs('tacacs_appliance.admin_runtime',level='INFO'))
            result=main()
        tls.assert_called_once_with(config['cert_file'],config['key_file'],client_ca=client_ca)
        if tls_error:
            pool.open.assert_not_called();server.serve_forever.assert_not_called()
        else:pool.close.assert_called_once()
        self.assertNotIn('sensitive-', ''.join(captured.output))
        if not application_error and not tls_error:server.server_close.assert_called_once()
        return result,server

    def test_signal_shutdown_closes_server_and_pool(self):
        result,server=self.run_composed()
        self.assertEqual(result,0)
        server.serve_forever.assert_called_once()

    def test_client_ca_is_forwarded_to_tls_without_fallback(self):
        self.assertEqual(self.run_composed(client_ca=Path('client-ca.pem'))[0],0)

    def test_invalid_client_ca_stops_before_database_and_bind(self):
        self.assertEqual(self.run_composed(client_ca=Path('bad-ca.pem'),tls_error=True)[0],1)

    def test_application_initialization_failure_closes_opened_pool(self):
        result,server=self.run_composed(application_error=True)
        self.assertEqual(result,1);server.serve_forever.assert_not_called()

    def test_listener_failure_is_nonzero_and_resources_close(self):
        self.assertEqual(self.run_composed(listener_error=True)[0],1)

    def test_cleanup_failure_does_not_prevent_pool_close(self):
        self.assertEqual(self.run_composed(cleanup_error=True)[0],1)

    def test_unexpected_listener_return_is_not_success(self):
        self.assertEqual(self.run_composed(unexpected_stop=True)[0],1)

    def test_example_resolves_paths_without_reading_secrets(self):
        path=Path(__file__).resolve().parent/'fixtures/admin.example.toml'
        config=load_config(path)
        self.assertEqual(config['port'],8443)
        self.assertEqual(config['database_dsn_file'],path.parent/'../secrets/admin_dsn')
        self.assertIn('secret://admin-totp',config['mfa_references'])

    def test_configuration_does_not_accept_network_bind_override(self):
        example=Path(__file__).resolve().parent/'fixtures/admin.example.toml'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'admin.toml'
            # Generated test fixture only; no operator configuration modified.
            path.write_text('host="0.0.0.0"\n'+example.read_text(),encoding='utf-8')
            with self.assertRaises(ValueError):load_config(path)

    def test_client_ca_configuration_resolves_relative_path_and_rejects_empty(self):
        example=Path(__file__).resolve().parent/'fixtures/admin.example.toml'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'admin.toml'
            path.write_text('client_ca_file="client-ca.pem"\n'+example.read_text(),encoding='utf-8')
            self.assertEqual(load_config(path)['client_ca_file'],path.parent/'client-ca.pem')
            path.write_text('client_ca_file=""\n'+example.read_text(),encoding='utf-8')
            with self.assertRaises(ValueError):load_config(path)

    def test_startup_failure_returns_generic_error_without_secret(self):
        with patch('sys.argv',['admin','--config','missing.toml']), \
             patch('tacacs_appliance.admin_runtime.load_config',side_effect=RuntimeError('secret-value')), \
             self.assertLogs('tacacs_appliance.admin_runtime',level='ERROR') as captured:
            self.assertEqual(main(),1)
        self.assertNotIn('secret-value',''.join(captured.output))
        self.assertIn('ADMIN_SERVICE_FAILED',''.join(captured.output))
