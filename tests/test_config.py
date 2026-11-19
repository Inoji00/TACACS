import unittest
from tacacs_appliance.config import DatabaseConfig
class ConfigTests(unittest.TestCase):
 def test_rejects_plaintext_dsn(self):
  with self.assertRaises(ValueError):DatabaseConfig("postgres://password@db")
 def test_accepts_secret_reference(self):self.assertEqual(DatabaseConfig("secret://database/dsn").dsn_reference,"secret://database/dsn")
