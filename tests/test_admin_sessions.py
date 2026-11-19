import unittest
from contextlib import contextmanager,nullcontext
from unittest.mock import Mock
from tacacs_appliance.admin_sessions import PostgresAdminSessions

ID="00000000-0000-0000-0000-000000000001"
class Pool:
    def __init__(self):self.db=Mock();self.db.transaction.side_effect=lambda:nullcontext()
    @contextmanager
    def connection(self):yield self.db
class SessionTests(unittest.TestCase):
    def test_requires_mfa_and_stores_only_token_hash(self):
        pool=Pool();sessions=PostgresAdminSessions(pool,ID)
        with self.assertRaises(ValueError):sessions.create(ID,mfa_verified=False)
        token=sessions.create(ID,mfa_verified=True,factor_id=ID)
        parameters=pool.db.execute.call_args.args[1]
        self.assertNotIn(token,str(parameters));self.assertEqual(parameters[0],sessions._hash(token))

    def test_missing_or_revoked_administrator_cannot_receive_session(self):
        pool=Pool()
        pool.db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(ValueError):
            PostgresAdminSessions(pool,ID).create(ID,mfa_verified=True,factor_id=ID)
        self.assertEqual(pool.db.execute.call_count,1)

    def test_resolution_checks_live_console_grant(self):
        pool=Pool()
        pool.db.execute.return_value.fetchone.return_value=None
        self.assertIsNone(PostgresAdminSessions(pool,ID).resolve('a'*43))
        query=pool.db.execute.call_args.args[0]
        self.assertIn("admin_grants",query)
        self.assertIn("console.read",query)

    def test_factor_disabled_between_verification_and_session_creation_is_rejected(self):
        pool=Pool();pool.db.execute.return_value.fetchone.side_effect=[(ID,),None]
        with self.assertRaises(ValueError):PostgresAdminSessions(pool,ID).create(ID,mfa_verified=True,factor_id=ID)
        self.assertFalse(any(call.args[0].startswith('INSERT') for call in pool.db.execute.call_args_list))

    def test_verified_boolean_without_factor_cannot_issue_session(self):
        pool=Pool()
        with self.assertRaises(ValueError):PostgresAdminSessions(pool,ID).create(ID,mfa_verified=True)
        pool.db.execute.assert_not_called()
