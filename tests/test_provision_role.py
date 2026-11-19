import unittest
from contextlib import nullcontext
from unittest.mock import Mock,patch
from tacacs_appliance.provision_role import provision_aaa_role,provision_admin_role,provision_new_login


class ProvisionRoleTests(unittest.TestCase):
    def test_new_login_rejects_weak_password_or_unknown_profile_before_database(self):
        connection=Mock()
        for password,profile in (('short','aaa'),('x'*31+'\n','aaa'),('x'*32,'unknown')):
            with self.assertRaises(ValueError):provision_new_login(connection,'role','schema',password,profile=profile)
        connection.execute.assert_not_called()

    def test_new_login_creation_and_grants_share_outer_transaction(self):
        connection=Mock();connection.transaction.side_effect=lambda:nullcontext()
        connection.pgconn.encrypt_password.return_value=b'SCRAM-SHA-256$test-verifier'
        with patch('tacacs_appliance.provision_role.provision_admin_role') as grants:
            provision_new_login(connection,'admin','schema','test-only-password-value-'+'x'*32,profile='admin')
        statement=connection.execute.call_args.args[0].as_string()
        self.assertIn('NOSUPERUSER',statement);self.assertNotIn('IF NOT EXISTS',statement)
        self.assertNotIn('test-only-password-value-',statement)
        self.assertIn('SCRAM-SHA-256$',statement)
        connection.pgconn.encrypt_password.assert_called_once_with(
            ('test-only-password-value-'+'x'*32).encode(),b'admin',b'scram-sha-256')
        grants.assert_called_once_with(connection,'admin','schema')

    def test_new_login_rejects_non_scram_verifier_before_create(self):
        connection=Mock();connection.transaction.side_effect=lambda:nullcontext()
        connection.pgconn.encrypt_password.return_value=b'md5not-allowed'
        with self.assertRaises(ValueError):provision_new_login(connection,'role','schema','x'*32)
        connection.execute.assert_not_called()
    def test_admin_profile_uses_dedicated_validation_and_limited_mutations(self):
        connection=Mock()
        connection.transaction.side_effect=lambda:nullcontext()
        connection.execute.return_value.fetchone.side_effect=[(True,),('public.audit_sequence',),('public','audit_sequence')]
        with patch('tacacs_appliance.provision_role.validate_admin_role') as validate, \
             patch('tacacs_appliance.provision_role.validate_runtime_role') as aaa:
            provision_admin_role(connection,'admin_service','public')
        validate.assert_called_once_with(connection);aaa.assert_not_called()
        statements=[call.args[0].as_string() if hasattr(call.args[0],'as_string') else call.args[0]
                    for call in connection.execute.call_args_list]
        self.assertTrue(any('UPDATE(state,approver_id)' in statement for statement in statements))
        self.assertFalse(any('INSERT ON "public"."accounting_records"' in statement for statement in statements))
        self.assertFalse(any('DELETE ON "public".policy' in statement for statement in statements))

    def test_missing_login_rejected_before_grants(self):
        connection = Mock()
        connection.transaction.side_effect = lambda: nullcontext()
        connection.execute.return_value.fetchone.return_value = None
        with self.assertRaises(ValueError):
            provision_aaa_role(connection, "aaa", "public")
        self.assertEqual(connection.execute.call_count, 1)

    def test_invalid_names_rejected_without_database(self):
        connection = Mock()
        for role, schema in (("", "public"), ("aaa", ""), ("x"*64, "public")):
            with self.assertRaises(ValueError):
                provision_aaa_role(connection, role, schema)
        connection.transaction.assert_not_called()
