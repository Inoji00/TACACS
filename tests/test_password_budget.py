import unittest
from unittest.mock import Mock, patch
from tacacs_appliance.password_timing import PASSWORD_WORK_SLOTS, PasswordWorkUnavailable, bounded_password_work
from tacacs_appliance.postgres_identity import PostgresLocalProvider


class PasswordBudgetTests(unittest.TestCase):
    def test_saturation_fails_before_database_or_counter_update(self):
        provider=PostgresLocalProvider.__new__(PostgresLocalProvider)
        provider._pool=Mock()
        slots = Mock()
        slots.acquire.return_value = False
        with patch("tacacs_appliance.password_timing.PASSWORD_WORK_SLOTS", slots):
            with self.assertRaises(PasswordWorkUnavailable):
                provider.authenticate("u", "password")
        slots.acquire.assert_called_once_with(timeout=1.5)
        slots.release.assert_not_called()
        provider._pool.connection.assert_not_called()

    def test_exception_releases_hash_budget(self):
        @bounded_password_work
        def fails():raise OSError("provider failure")
        with self.assertRaises(OSError):fails()
        acquired=0
        try:
            for _ in range(4):
                self.assertTrue(PASSWORD_WORK_SLOTS.acquire(blocking=False));acquired+=1
        finally:
            for _ in range(acquired):PASSWORD_WORK_SLOTS.release()
