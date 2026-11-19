import struct
import unittest

from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.protocol import AUTHENTICATION, parse_frame
from tacacs_appliance.secrets import SecretNotFoundError, StaticDeviceSecretProvider


SECRET_A = b"a" * 32
SECRET_B = b"b" * 32


def parsed(body: bytes, flags: int = 0):
    raw = struct.pack("!BBBBII", 0xC0, AUTHENTICATION, 1, flags, 0x01020304, len(body)) + body
    return parse_frame(raw)


class ObfuscationTests(unittest.TestCase):
    def test_xor_body_round_trip_and_multi_digest_pad(self):
        cleartext = bytes(range(64))
        encrypted = xor_body(parsed(cleartext), SECRET_A)
        self.assertNotEqual(encrypted, cleartext)
        self.assertEqual(xor_body(parsed(encrypted), SECRET_A), cleartext)

    def test_fourteen_byte_key_round_trip_and_boundary(self):
        secret=b'AbCdEfGh1234-_'
        provider=StaticDeviceSecretProvider({'device':secret})
        body=b'authentication-body'
        encrypted=xor_body(parsed(body),provider.resolve('device'))
        self.assertEqual(xor_body(parsed(encrypted),secret),body)
        with self.assertRaises(ValueError):xor_body(parsed(body),secret[:-1])
        with self.assertRaises(ValueError):StaticDeviceSecretProvider({'device':secret[:-1]})

    def test_secret_changes_obfuscation_result(self):
        cleartext = b"authorization-body"
        self.assertNotEqual(xor_body(parsed(cleartext), SECRET_A), xor_body(parsed(cleartext), SECRET_B))

    def test_provider_rejects_shared_or_short_secrets(self):
        with self.assertRaises(ValueError):
            StaticDeviceSecretProvider({"a": SECRET_A, "b": SECRET_A})
        with self.assertRaises(ValueError):
            StaticDeviceSecretProvider({"a": b"short"})

    def test_provider_hides_unknown_secret_details(self):
        provider = StaticDeviceSecretProvider({"router-a": SECRET_A})
        with self.assertRaises(SecretNotFoundError) as caught:
            provider.resolve("router-b")
        self.assertNotIn("router-b", str(caught.exception))
