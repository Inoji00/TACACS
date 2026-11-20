import unittest
from contextlib import nullcontext
from unittest.mock import Mock,patch
from argon2 import PasswordHasher
from tacacs_appliance.bootstrap import bootstrap_tenant

TENANT="00000000-0000-0000-0000-000000000001"


class BootstrapTests(unittest.TestCase):
    def test_password_hashed_mfa_disabled_and_audit_shares_connection(self):
        connection=Mock();connection.transaction.side_effect=lambda:nullcontext()
        with patch("tacacs_appliance.bootstrap.validate_schema"),patch("tacacs_appliance.bootstrap.PostgresAuditWriter") as writer:
            user,factor=bootstrap_tenant(connection,tenant_id=TENANT,name="Local",username="admin",
                                        password="Strong-local-42!",mfa_reference="secret://mfa/admin")
        insert=next(c for c in connection.execute.call_args_list if c.args[0].startswith("INSERT INTO users"))
        self.assertTrue(PasswordHasher().verify(insert.args[1][-1],"Strong-local-42!"))
        self.assertNotIn("Strong-local-42!",str(connection.execute.call_args_list))
        mfa=next(c for c in connection.execute.call_args_list if c.args[0].startswith("INSERT INTO mfa_factors"))
        self.assertIn("FALSE",mfa.args[0])
        writer.return_value.append_in_transaction.assert_called_once()
        self.assertIs(writer.return_value.append_in_transaction.call_args.args[0],connection)
        self.assertNotEqual(user,factor)

    def test_weak_password_rejected_before_database(self):
        connection=Mock()
        with self.assertRaises(ValueError):
            bootstrap_tenant(connection,tenant_id=TENANT,name="Local",username="admin",password="weak",mfa_reference="secret://mfa/admin")
        connection.transaction.assert_not_called()
