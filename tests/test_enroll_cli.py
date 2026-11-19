import unittest
import warnings
from getpass import GetPassWarning
from pathlib import Path
from unittest.mock import patch,Mock
from contextlib import nullcontext
from tacacs_appliance.enroll_cli import matching_file_resolver,main


class EnrollmentCliTests(unittest.TestCase):
    def test_nonhidden_getpass_fallback_aborts_before_database(self):
        arguments=["enroll","--dsn-file","dsn","--secret-file","secret","--secret-reference","secret://mfa/admin",
                   "--tenant-id","tenant","--user-id","user","--factor-id","factor"]
        def fallback(*_):
            warnings.warn("input echo unavailable",GetPassWarning)
            raise AssertionError("fallback must not read secret input")
        with patch("sys.argv",arguments),patch("tacacs_appliance.enroll_cli.getpass",side_effect=fallback), \
             patch("tacacs_appliance.enroll_cli.psycopg.connect") as connect,patch("builtins.print"):
            self.assertEqual(main(),1)
        connect.assert_not_called()
    def test_reference_mismatch_never_reads_secret(self):
        resolver=matching_file_resolver("secret://mfa/admin",Path("private"))
        with patch("tacacs_appliance.enroll_cli.read_secret") as reader:
            with self.assertRaises(ValueError):resolver("secret://mfa/other")
            reader.assert_not_called()

    def test_confirmation_command_uses_hidden_input_and_no_code_argument(self):
        arguments=["enroll","--dsn-file","dsn","--secret-file","secret","--secret-reference","secret://mfa/admin",
                   "--tenant-id","tenant","--user-id","user","--factor-id","factor"]
        connection=Mock()
        with patch("sys.argv",arguments),patch("tacacs_appliance.enroll_cli.getpass",return_value="123456") as prompt, \
             patch("tacacs_appliance.enroll_cli.read_secret",return_value=b"dsn"), \
             patch("tacacs_appliance.enroll_cli.psycopg.connect",return_value=nullcontext(connection)), \
             patch("tacacs_appliance.enroll_cli.validate_schema"), \
             patch("tacacs_appliance.enroll_cli.confirm_pending_factor",return_value=True) as confirm, \
             patch("builtins.print") as output:
            self.assertEqual(main(),0)
        prompt.assert_called_once()
        self.assertEqual(confirm.call_args.kwargs["code"],"123456")
        self.assertNotIn("123456",str(output.call_args_list))
