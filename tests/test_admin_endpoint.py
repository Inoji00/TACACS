from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from local_appliance import admin_certificate
from tacacs_appliance.admin_api import lan_admin_origin
from tacacs_appliance.admin_endpoint import verify_certificate, verify_dns_binding


class AdminEndpointTests(unittest.TestCase):
    def test_origin_is_canonical_and_requires_an_ip_binding(self):
        self.assertEqual(lan_admin_origin('192.0.2.2', 'TNAC.Example.org'),
                         'https://tnac.example.org:8443')
        for name in ('https://tnac.example.org', 'tnac.example.org:443', '192.0.2.2', 'a..org'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                lan_admin_origin('192.0.2.2', name)
        with self.assertRaises(ValueError):
            lan_admin_origin(None, 'tnac.example.org')

    def test_dns_must_resolve_to_only_the_bound_ip(self):
        with patch('tacacs_appliance.admin_endpoint.socket.getaddrinfo') as lookup:
            lookup.return_value = [(None, None, None, None, ('192.0.2.2', 8443))]
            verify_dns_binding('tnac.example.org', '192.0.2.2')
            lookup.return_value.append((None, None, None, None, ('192.0.2.3', 8443)))
            with self.assertRaises(ValueError):
                verify_dns_binding('tnac.example.org', '192.0.2.2')

    def test_certificate_requires_matching_san_key_and_trust(self):
        certificate, key = admin_certificate()
        other_certificate, other_key = admin_certificate()
        with tempfile.TemporaryDirectory() as directory:
            cert, private, ca = [Path(directory) / name for name in ('cert.pem', 'key.pem', 'ca.pem')]
            cert.write_bytes(certificate)
            private.write_bytes(key)
            ca.write_bytes(certificate)
            verify_certificate('localhost', cert, private, ca)
            with self.assertRaises(ssl.SSLCertVerificationError):
                verify_certificate('tnac.example.org', cert, private, ca)
            ca.write_bytes(other_certificate)
            with self.assertRaises(ssl.SSLCertVerificationError):
                verify_certificate('localhost', cert, private, ca)
            private.write_bytes(other_key)
            with self.assertRaises(ssl.SSLError):
                verify_certificate('localhost', cert, private, ca)
