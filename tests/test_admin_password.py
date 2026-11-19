from contextlib import nullcontext
import unittest
from unittest.mock import Mock
from argon2 import PasswordHasher
from tacacs_appliance.admin_password import AdminPasswordChange

ID='00000000-0000-0000-0000-000000000001'


class AdminPasswordTests(unittest.TestCase):
    def setUp(self):
        self.pool,self.db,self.audit=Mock(),Mock(),Mock()
        self.pool.connection.side_effect=lambda:nullcontext(self.db)
        self.db.transaction.side_effect=lambda:nullcontext()
        self.db.execute.return_value.fetchone.return_value=(PasswordHasher().hash('admin'),)
        self.service=AdminPasswordChange(self.pool,ID,self.audit)

    def test_success_locks_user_hashes_password_and_audits_without_secrets(self):
        self.service.change(ID,'admin','new-password-test-only')
        calls=self.db.execute.call_args_list
        self.assertIn('FOR UPDATE',calls[0].args[0]);self.assertIn('console.read',calls[0].args[0])
        self.assertTrue(PasswordHasher().verify(calls[1].args[1][0],'new-password-test-only'))
        self.assertNotIn('new-password-test-only',str(self.audit.call_args))
        self.audit.assert_called_once()

    def test_wrong_current_or_missing_subject_cannot_update(self):
        with self.assertRaises(PermissionError):self.service.change(ID,'wrong','new-password-test-only')
        self.assertEqual(self.db.execute.call_count,1);self.audit.assert_not_called()
        self.db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):self.service.change(ID,'admin','new-password-test-only')
        self.audit.assert_not_called()

    def test_weak_new_password_rejected_before_database(self):
        with self.assertRaises(ValueError):self.service.change(ID,'admin','admin')
        self.pool.connection.assert_not_called()
