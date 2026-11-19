import unittest
from tacacs_appliance.command import *
class CommandTests(unittest.TestCase):
 def test_normalizes_whitespace(self):self.assertEqual(normalize(" show   version ").canonical,"show version")
 def test_denies_ambiguous_shell_syntax(self):
  with self.assertRaises(CommandError):normalize("show version; reload")
