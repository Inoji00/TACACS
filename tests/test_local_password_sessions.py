from contextlib import nullcontext
import unittest
from unittest.mock import Mock,patch
from uuid import UUID
from tacacs_appliance.local_password_sessions import LocalPasswordSessions

ID='00000000-0000-0000-0000-000000000001'


class LocalPasswordSessionTests(unittest.TestCase):
    def setUp(self):
        self.pool,self.db=Mock(),Mock()
        self.pool.connection.side_effect=lambda:nullcontext(self.db)
        self.db.execute.return_value.fetchone.return_value=('hash-original',UUID(int=1))
        self.sessions=LocalPasswordSessions(self.pool,ID)

    def test_hashed_ephemeral_session_without_false_mfa_database_insert(self):
        token=self.sessions.create_password_only(ID)
        self.assertEqual(self.sessions.resolve(token),ID)
        self.assertNotIn(token,str(self.sessions.entries))
        self.assertFalse(any('INSERT' in call.args[0] for call in self.db.execute.call_args_list))
        self.sessions.revoke(token);self.assertIsNone(self.sessions.resolve(token))

    def test_password_change_or_unavailable_subject_revokes(self):
        for row in (('changed',UUID(int=1)),None):
            self.setUp();token=self.sessions.create_password_only(ID)
            self.db.execute.return_value.fetchone.return_value=row
            self.assertIsNone(self.sessions.resolve(token));self.assertFalse(self.sessions.entries)

    def test_regrant_does_not_restore_an_old_session(self):
        token=self.sessions.create_password_only(ID)
        self.db.execute.return_value.fetchone.return_value=('hash-original',UUID(int=2))
        self.assertIsNone(self.sessions.resolve(token))
        self.assertEqual(self.sessions.resolve(self.sessions.create_password_only(ID)),ID)

    def test_expiry_and_process_restart(self):
        with patch('tacacs_appliance.local_password_sessions.time.monotonic',return_value=10):
            token=self.sessions.create_password_only(ID)
        with patch('tacacs_appliance.local_password_sessions.time.monotonic',return_value=911):
            self.assertIsNone(self.sessions.resolve(token))
        self.assertIsNone(LocalPasswordSessions(self.pool,ID).resolve(token))

    def test_missing_grant_cannot_issue_session(self):
        self.db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(ValueError):self.sessions.create_password_only(ID)
