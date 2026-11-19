import unittest
from argon2 import PasswordHasher
from tacacs_appliance.password_timing import acceptable_password_hash


class PasswordParameterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.encoded=PasswordHasher().hash("test-password")

    def test_default_argon2id_accepted(self):
        self.assertTrue(acceptable_password_hash(self.encoded))

    def test_excessive_weak_or_wrong_type_hash_rejected_without_hashing(self):
        encoded=self.encoded
        for value in (encoded.replace("m=65536","m=999999999"),encoded.replace("t=3","t=1000"),
                      encoded.replace("p=4","p=1000"),encoded.replace("m=65536","m=8"),
                      encoded.replace("argon2id","argon2i"),"broken",None):
            self.assertFalse(acceptable_password_hash(value))
