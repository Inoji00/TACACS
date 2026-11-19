import hashlib
from pathlib import Path
import unittest
from unittest.mock import Mock
from tacacs_appliance.schema_manifest import EXPECTED_MIGRATIONS, validate_schema


class SchemaManifestTests(unittest.TestCase):
    def test_packaged_manifest_matches_all_source_migrations(self):
        directory = Path(__file__).resolve().parents[1] / "migrations"
        actual = {p.name: hashlib.sha256(p.read_text(encoding="utf-8").encode()).hexdigest() for p in directory.glob("[0-9]*.sql")}
        self.assertEqual(actual, EXPECTED_MIGRATIONS)

    def test_exact_manifest_accepted(self):
        connection = Mock()
        connection.execute.return_value.fetchall.return_value = list(EXPECTED_MIGRATIONS.items())
        validate_schema(connection)

    def test_missing_changed_or_future_schema_rejected(self):
        for entries in ([], [(name,"0"*64) for name in EXPECTED_MIGRATIONS],
                        list(EXPECTED_MIGRATIONS.items())+[("future.sql","0"*64)]):
            connection = Mock()
            connection.execute.return_value.fetchall.return_value = entries
            with self.assertRaises(ValueError):
                validate_schema(connection)
