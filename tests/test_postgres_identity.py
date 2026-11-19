"""Provider boundary tests with real Argon2 hashing and simulated DB rows."""
from contextlib import contextmanager, nullcontext
from unittest.mock import Mock
import unittest
from argon2 import PasswordHasher
from tacacs_appliance.postgres_identity import PostgresLocalProvider

TENANT = "00000000-0000-0000-0000-000000000001"


class Pool:
    def __init__(self, row):
        self.db = Mock()
        self.db.transaction.side_effect = lambda: nullcontext()
        self.db.execute.return_value.fetchone.return_value = row

    @contextmanager
    def connection(self):
        yield self.db


class PostgresIdentityTests(unittest.TestCase):
    def test_invalid_stored_hash_does_not_count_as_wrong_password(self):
        pool=Pool(("id","invalid",True,False,0))
        provider=PostgresLocalProvider(pool,TENANT);provider._dummy=Mock()
        self.assertFalse(provider.authenticate("u","password").authenticated)
        provider._dummy.verify.assert_called_once_with("password")
        self.assertEqual(pool.db.execute.call_count,1)
    def test_unavailable_accounts_run_dummy_work_without_updates(self):
        for row in (None, ("id","hash",False,False,0), ("id","hash",True,True,5)):
            pool=Pool(row);provider=PostgresLocalProvider(pool,TENANT)
            provider._dummy=Mock()
            self.assertFalse(provider.authenticate("u","password").authenticated)
            provider._dummy.verify.assert_called_once_with("password")
            self.assertEqual(pool.db.execute.call_count,1)
    @classmethod
    def setUpClass(cls):
        cls.password_hash = PasswordHasher().hash("correct")

    def test_password_failure_atomically_locks_at_threshold(self):
        pool = Pool(("user-id", self.password_hash, True, False, 4))
        result = PostgresLocalProvider(pool, TENANT).authenticate("u", "incorrect")
        self.assertFalse(result.authenticated)
        sql, parameters = pool.db.execute.call_args.args
        self.assertIn("tenant_id=%s", sql)
        self.assertEqual(parameters[:2], (5, True))

    def test_locked_account_cannot_authenticate(self):
        pool = Pool(("user-id", self.password_hash, True, True, 5))
        self.assertFalse(PostgresLocalProvider(pool, TENANT).authenticate("u", "correct").authenticated)
        self.assertEqual(pool.db.execute.call_count, 1)

    def test_device_threshold_locks_on_fourth_wrong_password(self):
        for previous_failures in range(4):
            with self.subTest(previous_failures=previous_failures):
                pool = Pool(("user-id", self.password_hash, True, False, previous_failures))
                provider = PostgresLocalProvider(pool, TENANT, lockout_after=4)
                self.assertFalse(provider.authenticate("u", "incorrect").authenticated)
                parameters = pool.db.execute.call_args.args[1]
                self.assertEqual(parameters[:2], (previous_failures + 1, previous_failures == 3))

    def test_success_resets_counter_and_scopes_user(self):
        pool = Pool(("user-id", self.password_hash, True, False, 3))
        result = PostgresLocalProvider(pool, TENANT).authenticate("u", "correct")
        self.assertTrue(result.authenticated)
        self.assertEqual(result.subject, "u")
        self.assertIn("failed_logins=0", pool.db.execute.call_args.args[0])
