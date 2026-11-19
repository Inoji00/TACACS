import unittest
from tacacs_appliance.authentication_service import AuthenticationService
from tacacs_appliance.local_identity import LocalProvider
from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.protocol import AUTHENTICATION, Frame, Header
from tacacs_appliance.secrets import StaticDeviceSecretProvider
from tacacs_appliance.tacacs_handler import TacacsAuthenticationHandler

class ConnectionIsolationTests(unittest.TestCase):
    def test_another_connection_cannot_consume_challenge(self):
        secret = b"a" * 32
        template = TacacsAuthenticationHandler(StaticDeviceSecretProvider({"127.0.0.1": secret}), AuthenticationService(LocalProvider({})))
        first, second = template.new_connection(), template.new_connection()
        body = bytes((1,15,1,1,1,0,0,0)) + b"u"
        frame = Frame(Header(0xc0,AUTHENTICATION,1,0,7,len(body)),body)
        self.assertIsNotNone(first("127.0.0.1",Frame(frame.header,xor_body(frame,secret))))
        body = b"\x00\x01\x00\x00\x00x"
        frame = Frame(Header(0xc0,AUTHENTICATION,3,0,7,len(body)),body)
        encrypted = Frame(frame.header,xor_body(frame,secret))
        self.assertIsNone(second("127.0.0.1", encrypted))
        self.assertIsNotNone(first("127.0.0.1", encrypted))
