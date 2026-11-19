"""Repository boundary tests; real PostgreSQL integration remains separate."""
import unittest
from contextlib import contextmanager
from unittest.mock import Mock
from psycopg.pq import TransactionStatus

from tacacs_appliance.accounting import AccountingRecord
from tacacs_appliance.postgres_accounting import PostgresAccountingStore

TENANT = "00000000-0000-0000-0000-000000000001"


class Pool:
    def __init__(self):
        self.connection_object = Mock()
        self.connection_object.transaction.return_value.__enter__ = Mock()
        self.connection_object.transaction.return_value.__exit__ = Mock(return_value=False)

    @contextmanager
    def connection(self):
        yield self.connection_object


class PostgresAccountingBoundaryTests(unittest.TestCase):
    def test_rejects_cross_tenant_before_database_access(self):
        pool = Pool()
        store = PostgresAccountingStore(pool, TENANT)
        with self.assertRaises(ValueError):
            store.append(AccountingRecord("00000000-0000-0000-0000-000000000002", "s", "u", "d", "start", ()))
        pool.connection_object.execute.assert_not_called()

    def test_sql_parameters_and_redaction(self):
        pool = Pool()
        pool.connection_object.info.transaction_status = TransactionStatus.INTRANS
        pool.connection_object.execute.return_value.fetchone.side_effect = [(TENANT,), (TENANT,), None]
        store = PostgresAccountingStore(pool, TENANT)
        store.append(AccountingRecord(TENANT, "s", "u'; DROP TABLE users;--", "d", "start", ("password=x",)))
        calls = pool.connection_object.execute.call_args_list
        sql, parameters = next(call.args for call in calls if call.args[0].startswith("INSERT INTO accounting_records"))
        self.assertNotIn("DROP TABLE", sql)
        self.assertEqual(parameters[3], "u'; DROP TABLE users;--")
        self.assertEqual(parameters[-1].obj, ["<redacted>"])
        self.assertTrue(any(call.args[0].startswith("INSERT INTO audit_events") for call in calls))

    def test_audit_failure_exits_transaction_with_error(self):
        pool = Pool()
        store = PostgresAccountingStore(pool, TENANT)
        store._audit.append_in_transaction = Mock(side_effect=OSError("audit unavailable"))
        with self.assertRaises(OSError):
            store.append(AccountingRecord(TENANT, "s", "u", "d", "start", ()))
        exit_args = pool.connection_object.transaction.return_value.__exit__.call_args.args
        self.assertIs(exit_args[0], OSError)

    def test_storage_error_propagates_for_wire_error_mapping(self):
        pool = Pool()
        pool.connection_object.execute.side_effect = OSError("database unavailable")
        with self.assertRaises(OSError):
            PostgresAccountingStore(pool, TENANT).append(AccountingRecord(TENANT, "s", "u", "d", "start", ()))
