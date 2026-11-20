import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from argon2 import PasswordHasher

from tacacs_appliance import admin_reset


class AdminResetTests(unittest.TestCase):
    def setUp(self):
        self.connection = MagicMock()
        self.tenant, self.user = uuid4(), uuid4()
        self.password = "Reset-test-42!"

    def test_weak_password_never_enters_database_transaction(self):
        with self.assertRaises(ValueError):
            admin_reset.reset_admin(self.connection, self.tenant, self.user, "weak")
        self.connection.transaction.assert_not_called()

    @patch.object(admin_reset, "validate_schema")
    @patch.object(admin_reset, "PostgresAuditWriter")
    def test_unknown_or_ineligible_administrator_is_not_audited_as_success(self, writer, schema):
        self.connection.execute.return_value.fetchone.return_value = None
        with self.assertRaises(PermissionError):
            admin_reset.reset_admin(self.connection, self.tenant, self.user, self.password)
        writer.assert_not_called()

    @patch.object(admin_reset, "validate_schema")
    @patch.object(admin_reset, "PostgresAuditWriter")
    def test_hash_and_audit_use_same_connection_and_target(self, writer, schema):
        self.connection.execute.return_value.fetchone.return_value = (self.user,)
        admin_reset.reset_admin(self.connection, self.tenant, self.user, self.password)
        self.connection.transaction.assert_called_once_with()
        schema.assert_called_once_with(self.connection)
        _, parameters = self.connection.execute.call_args.args
        self.assertTrue(PasswordHasher().verify(parameters[0], self.password))
        self.assertEqual(parameters[1:], (self.tenant, self.user))
        writer.return_value.append_in_transaction.assert_called_once_with(
            self.connection, actor="local-root", source="local-cli",
            action="admin.password.reset", target=str(self.user), result="success",
        )
