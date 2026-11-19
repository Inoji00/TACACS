import unittest
from argon2 import PasswordHasher
from tacacs_appliance.local_identity import LocalProvider, LocalUser

class LocalProviderTests(unittest.TestCase):
    def setUp(self):
        self.user = LocalUser("alice", PasswordHasher().hash("correct horse battery staple"))
        self.provider = LocalProvider({"alice": self.user}, lockout_after=2)
    def test_argon2_password_authentication(self):
        result = self.provider.authenticate("alice", "correct horse battery staple")
        self.assertTrue(result.authenticated); self.assertEqual(result.subject, "alice")
    def test_generic_failure_and_lockout(self):
        self.assertEqual(self.provider.authenticate("nobody", "x").reason, "invalid credentials")
        self.provider.authenticate("alice", "wrong"); self.provider.authenticate("alice", "wrong")
        self.assertTrue(self.user.locked)
