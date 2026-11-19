import io
from pathlib import Path
import unittest
from uuid import UUID
from unittest.mock import patch, MagicMock
from tacacs_appliance.runtime import RuntimeConfig, build_listener
from tacacs_appliance.__main__ import main

CONFIG = b'''tenant_id = "00000000-0000-0000-0000-000000000001"
database_dsn_file = "dsn.secret"
[listener]
host = "127.0.0.1"
[[devices]]
address = "127.0.0.1"
secret_file = "device.secret"
'''


class RuntimeTests(unittest.TestCase):
    def test_device_authentication_uses_four_failure_lockout(self):
        config = self.load()
        with patch("tacacs_appliance.runtime.read_secret", return_value=b"test-device-secret"), \
             patch("tacacs_appliance.runtime.load_active_policy"), \
             patch("tacacs_appliance.runtime.PostgresLocalProvider") as provider, \
             patch("tacacs_appliance.runtime.TacacsListener"):
            pool = MagicMock()
            build_listener(config, pool)
        provider.assert_called_once_with(pool, config.tenant_id, lockout_after=4)

    def load(self, raw=CONFIG):
        with patch.object(Path, "open", return_value=io.BytesIO(raw)):
            return RuntimeConfig.load(Path("config/service.toml"))

    def test_standard_port_and_device_only_acl(self):
        config = self.load()
        self.assertEqual(config.listener.port, 49)
        self.assertEqual(config.listener.allowed_sources, ("127.0.0.1/32",))
        self.assertEqual(config.database_dsn_file, Path("config/dsn.secret"))

    def test_unknown_fields_and_invalid_ports_rejected(self):
        for raw in (CONFIG.replace(b"[listener]", b"unexpected = true\n[listener]"),
                    CONFIG.replace(b"[listener]", b"[listener]\nport = true"),
                    CONFIG.replace(b"[listener]", b"[listener]\nport = 0"),
                    CONFIG.replace(b"127.0.0.1", b"::1")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.load(raw)

    def test_duplicate_device_rejected(self):
        with self.assertRaises(ValueError):
            self.load(CONFIG + b'[[devices]]\naddress="127.0.0.1"\nsecret_file="other"\n')

    def test_fresh_vm_config_has_no_static_device_and_uses_live_registry(self):
        import base64
        import sys
        with patch.object(sys, 'path', [str(Path(__file__).resolve().parents[1]/'scripts'), *sys.path]):
            from local_appliance import prepare_files
        files, _ = prepare_files(str(UUID(int=1)), None)
        self.assertNotIn('/runtime/device_local', files)
        raw = base64.b64decode(files['/config/service.toml'][0])
        config = self.load(raw)
        self.assertEqual(config.devices, ())
        with self.assertRaises(ValueError):
            self.load(raw.split(b'\n', 1)[1])
        pool = MagicMock()
        connection = pool.connection.return_value.__enter__.return_value
        row = connection.execute.return_value.fetchone
        with patch("tacacs_appliance.runtime.read_secret", return_value=b"s" * 32), \
             patch("tacacs_appliance.runtime.load_active_policy"):
            listener = build_listener(config, pool)
            try:
                row.return_value = None
                self.assertFalse(listener._source_allowed("192.0.2.10"))
                row.return_value = (True, 1)
                self.assertTrue(listener._source_allowed("192.0.2.10"))
                row.return_value = (False, 2)
                self.assertFalse(listener._source_allowed("192.0.2.10"))
            finally:
                listener.shutdown()

    def test_legacy_shared_listener_setting_still_uses_configured_tenant(self):
        config = self.load(b'shared_listener=true\ndevice_registry_key_file="key"\n' + CONFIG)
        pool = MagicMock()
        connection = pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.return_value = (True, 1)
        with patch("tacacs_appliance.runtime.read_secret", return_value=b"s" * 32), \
             patch("tacacs_appliance.runtime.load_active_policy"), \
             patch("tacacs_appliance.aaa_events.ObservedRouter") as observed:
            listener = build_listener(config, pool)
            try:
                self.assertTrue(listener._source_allowed("192.0.2.10"))
                self.assertEqual(connection.execute.call_args_list[0].args[1],
                                 (UUID(config.tenant_id), "192.0.2.10"))
                self.assertEqual(observed.call_args.args[1].tenant, UUID(config.tenant_id))
                observed.assert_called_once()
            finally:
                listener.shutdown()

    def test_composition_isolates_connection_auth_state(self):
        config = self.load()
        with patch("tacacs_appliance.runtime.read_secret", return_value=b"s" * 32), \
             patch("tacacs_appliance.runtime.load_active_policy"):
            listener = build_listener(config, MagicMock())
            try:
                first = listener._handler_factory()
                second = listener._handler_factory()
                self.assertIsNot(first.router._authentication, second.router._authentication)
                self.assertIs(first.events, second.events)
            finally:
                listener.shutdown()

    def test_entrypoint_stays_running_until_listener_exits_and_closes_resources(self):
        pool, listener = MagicMock(), MagicMock()
        with patch("sys.argv", ["tacacs", "--config", "service.toml"]), \
             patch("tacacs_appliance.__main__.RuntimeConfig.load", return_value=self.load()), \
             patch("tacacs_appliance.__main__.open_pool", return_value=pool), \
             patch("tacacs_appliance.__main__.build_listener", return_value=listener):
            self.assertEqual(main(), 0)
        listener.start.assert_called_once()
        listener.serve_forever.assert_called_once()
        listener.shutdown.assert_called_once()
        pool.close.assert_called_once()

    def test_startup_failure_returns_nonzero_without_secret_diagnostic(self):
        with patch("sys.argv", ["tacacs", "--config", "service.toml"]), \
             patch("tacacs_appliance.__main__.RuntimeConfig.load", side_effect=ValueError("SECRET_VALUE")), \
             self.assertLogs("tacacs_appliance.__main__", level="ERROR") as logs:
            self.assertEqual(main(), 1)
        self.assertNotIn("SECRET_VALUE", " ".join(logs.output))

    def test_monitoring_bind_failure_closes_listener_and_pool(self):
        pool,listener=MagicMock(),MagicMock()
        with patch("sys.argv",["tacacs","--config","service.toml","--health-port","9090"]), \
             patch("tacacs_appliance.__main__.RuntimeConfig.load",return_value=self.load()), \
             patch("tacacs_appliance.__main__.open_pool",return_value=pool), \
             patch("tacacs_appliance.__main__.build_listener",return_value=listener), \
             patch("tacacs_appliance.__main__.create_health_server",side_effect=OSError("bind failed")), \
             self.assertLogs("tacacs_appliance.__main__",level="ERROR"):
            self.assertEqual(main(),1)
        listener.shutdown.assert_called_once()
        pool.close.assert_called_once()

    def test_listener_cleanup_error_still_closes_database_pool(self):
        pool,listener=MagicMock(),MagicMock()
        listener.shutdown.side_effect=OSError("SECRET_DIAGNOSTIC")
        with patch("sys.argv",["tacacs","--config","service.toml"]), \
             patch("tacacs_appliance.__main__.RuntimeConfig.load",return_value=self.load()), \
             patch("tacacs_appliance.__main__.open_pool",return_value=pool), \
             patch("tacacs_appliance.__main__.build_listener",return_value=listener), \
             self.assertLogs("tacacs_appliance.__main__",level="INFO") as logs:
            self.assertEqual(main(),1)
        pool.close.assert_called_once()
        self.assertNotIn("SECRET_DIAGNOSTIC"," ".join(logs.output))
