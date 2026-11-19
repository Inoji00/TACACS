import io
from pathlib import Path
import ssl
import unittest
from unittest.mock import Mock,patch
from tacacs_appliance.admin_tls import create_admin_tls_context


class AdminTlsTests(unittest.TestCase):
    def context(self,client_ca=None):
        context=Mock();context.options=0
        with patch.object(Path,"is_symlink",return_value=False), \
             patch.object(Path,"open",return_value=io.BytesIO(b"key")), \
             patch("tacacs_appliance.admin_tls.os.fstat"), \
             patch("tacacs_appliance.admin_tls.validate_secret_metadata"), \
             patch("tacacs_appliance.admin_tls.ssl.SSLContext",return_value=context):
            # BytesIO has no descriptor; replace stream with context manager mock.
            stream=Mock();stream.fileno.return_value=1
            with patch.object(Path,"open",return_value=Mock(__enter__=Mock(return_value=stream),__exit__=Mock(return_value=False))):
                result=create_admin_tls_context(Path("cert.pem"),Path("key.pem"),client_ca=client_ca)
        return result

    def test_tls13_only_and_no_resumption_tickets(self):
        context=self.context()
        self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.maximum_version,ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.num_tickets,0)
        self.assertTrue(context.options & ssl.OP_NO_TICKET)
        context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        callback=context.load_cert_chain.call_args.kwargs["password"]
        with self.assertRaises(ValueError):callback()

    def test_optional_client_ca_requires_client_certificate(self):
        context=self.context(Path("local-ca.pem"))
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        context.load_verify_locations.assert_called_once_with(cafile="local-ca.pem")

    def test_symlink_credentials_rejected_before_loading(self):
        with patch.object(Path,"is_symlink",return_value=True):
            with self.assertRaises(ValueError):create_admin_tls_context(Path("cert"),Path("key"))
