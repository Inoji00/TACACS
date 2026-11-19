from contextlib import contextmanager
from unittest.mock import Mock
import unittest
from tacacs_appliance.postgres_groups import PostgresGroupResolver

class Pool:
    def __init__(self, rows):
        self.db = Mock()
        self.db.execute.return_value.fetchall.return_value = rows
    @contextmanager
    def connection(self): yield self.db

class GroupResolverTests(unittest.TestCase):
    def test_unknown_user_and_user_without_groups_are_distinct(self):
        tenant = "00000000-0000-0000-0000-000000000001"
        self.assertIsNone(PostgresGroupResolver(Pool([]),tenant)("unknown"))
        self.assertEqual(PostgresGroupResolver(Pool([(None,)]),tenant)("u"),frozenset())
        self.assertEqual(PostgresGroupResolver(Pool([("ops",)]),tenant)("u"),frozenset({"ops"}))
