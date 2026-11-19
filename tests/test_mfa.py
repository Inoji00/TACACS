import unittest
from tacacs_appliance.mfa import totp,verify_totp
class MfaTests(unittest.TestCase):
 def test_rfc6238_sha256_vectors(self):
  secret=b"12345678901234567890123456789012"
  for timestamp,expected in ((59,"46119246"),(1111111109,"68084774"),(1111111111,"67062674"),(1234567890,"91819424"),(2000000000,"90698825"),(20000000000,"77737706")):
   with self.subTest(timestamp=timestamp):self.assertEqual(totp(secret,timestamp,digits=8),expected)
 def test_totp_and_bounded_window(self):
  secret=b"a"*32;code=totp(secret,1_700_000_000)
  self.assertTrue(verify_totp(secret,code,1_700_000_000));self.assertFalse(verify_totp(secret,"000000",1_700_000_000));self.assertFalse(verify_totp(secret,code,1_700_000_100))
