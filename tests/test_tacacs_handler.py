import struct,unittest
from argon2 import PasswordHasher
from tacacs_appliance.authentication_service import AuthenticationService,STATUS_GETPASS
from tacacs_appliance.local_identity import LocalProvider,LocalUser
from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.protocol import AUTHENTICATION,Frame,Header,parse_frame
from tacacs_appliance.secrets import StaticDeviceSecretProvider
from tacacs_appliance.tacacs_handler import TacacsAuthenticationHandler
SECRET=b"a"*32
class HandlerTests(unittest.TestCase):
 def test_rejects_invalid_pending_limit(self):
  with self.assertRaises(ValueError):TacacsAuthenticationHandler(StaticDeviceSecretProvider({"127.0.0.1":SECRET}),AuthenticationService(LocalProvider({})),0)
  with self.assertRaises(ValueError):TacacsAuthenticationHandler(StaticDeviceSecretProvider({"127.0.0.1":SECRET}),AuthenticationService(LocalProvider({})),pending_ttl_seconds=0)
 def test_start_returns_obfuscated_getpass(self):
  h=TacacsAuthenticationHandler(StaticDeviceSecretProvider({"127.0.0.1":SECRET}),AuthenticationService(LocalProvider({"alice":LocalUser("alice",PasswordHasher().hash("x"))})))
  clear=bytes((1,15,1,1,5,4,8,0))+b"alicevty010.0.0.1";frame=Frame(Header(0xc0,AUTHENTICATION,1,0,7,len(clear)),clear)
  encrypted=Frame(frame.header,xor_body(frame,SECRET));response=parse_frame(h("127.0.0.1",encrypted))
  reply=xor_body(response,SECRET);self.assertEqual(reply[0],STATUS_GETPASS);self.assertEqual(response.header.sequence,2)
 def test_continue_returns_pass_and_consumes_challenge(self):
  h=TacacsAuthenticationHandler(StaticDeviceSecretProvider({"127.0.0.1":SECRET}),AuthenticationService(LocalProvider({"alice":LocalUser("alice",PasswordHasher().hash("good"))})))
  start=bytes((1,15,1,1,5,4,8,0))+b"alicevty010.0.0.1";first=Frame(Header(0xc0,AUTHENTICATION,1,0,9,len(start)),start)
  h("127.0.0.1",Frame(first.header,xor_body(first,SECRET)))
  cont=b"\x00\x04\x00\x00\x00good";third=Frame(Header(0xc0,AUTHENTICATION,3,0,9,len(cont)),cont)
  response=parse_frame(h("127.0.0.1",Frame(third.header,xor_body(third,SECRET))))
  self.assertEqual(xor_body(response,SECRET)[0],1);self.assertEqual(response.header.sequence,4)
  self.assertIsNone(h("127.0.0.1",Frame(third.header,xor_body(third,SECRET))))
