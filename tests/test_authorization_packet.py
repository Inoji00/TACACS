import unittest
from tacacs_appliance.authorization_packet import *
def body(args=(b"cmd=show version",)):
 user,port,remote=b"alice",b"vty0",b"10.0.0.1"
 return bytes((6,15,1,1,len(user),len(port),len(remote),len(args)))+bytes(map(len,args))+user+port+remote+b"".join(args)
class AuthorizationPacketTests(unittest.TestCase):
 def test_parse_valid_request(self):
  value=parse_authorization_request(body());self.assertEqual(value.username,"alice");self.assertEqual(value.arguments,("cmd=show version",))
 def test_rejects_truncation_and_too_many_attributes(self):
  with self.assertRaises(AuthorizationPacketError):parse_authorization_request(body()[:-1])
  with self.assertRaises(AuthorizationPacketError):parse_authorization_request(bytes((0,0,0,0,0,0,0,65)))
