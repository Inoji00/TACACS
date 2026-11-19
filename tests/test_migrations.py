import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock
from tacacs_appliance.migrations import migrate

class MigrationTests(unittest.TestCase):
    def test_applied_checksum_mismatch_refuses_schema_change(self):
        connection = Mock()
        connection.transaction.side_effect = lambda: nullcontext()
        connection.execute.return_value.fetchone.return_value = ("incorrect",)
        with tempfile.TemporaryDirectory() as folder:
            Path(folder,"001_test.sql").write_text("BEGIN;\nSELECT 1;\nCOMMIT;",encoding="utf-8")
            with self.assertRaises(ValueError): migrate(connection,Path(folder))
        queries = [call.args[0] for call in connection.execute.call_args_list]
        self.assertNotIn("SELECT 1;",queries)
        self.assertIn("SELECT pg_advisory_unlock(8907001)",queries)
        connection.rollback.assert_called_once_with()

    def test_script_and_metadata_share_transaction(self):
        connection = Mock()
        connection.transaction.side_effect = lambda: nullcontext()
        connection.execute.return_value.fetchone.return_value = None
        with tempfile.TemporaryDirectory() as folder:
            Path(folder,"001_test.sql").write_text("BEGIN;\nSELECT 42;\nCOMMIT;",encoding="utf-8")
            migrate(connection,Path(folder))
        queries = [call.args[0] for call in connection.execute.call_args_list]
        self.assertIn("SELECT 42;",queries)
        self.assertNotIn("BEGIN;\nSELECT 42;\nCOMMIT;",queries)
        self.assertIn("INSERT INTO schema_migrations(name,checksum) VALUES (%s,%s)",queries)
        connection.rollback.assert_not_called()
