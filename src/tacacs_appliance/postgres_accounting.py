"""Transactional PostgreSQL accounting store using parameterized statements."""
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .accounting import AccountingRecord, redact_arguments
from .postgres_audit import PostgresAuditWriter


class PostgresAccountingStore:
    def __init__(self, pool: ConnectionPool, tenant_id: str):
        self._pool = pool
        self._tenant = UUID(tenant_id)
        self._audit = PostgresAuditWriter(pool, tenant_id)

    def append(self, record: AccountingRecord) -> None:
        """Commit before acknowledgement; never trust the caller's tenant scope."""
        if UUID(record.tenant_id) != self._tenant:
            raise ValueError("accounting tenant mismatch")
        with self._pool.connection() as connection:
            with connection.transaction():
                if connection.execute("SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self._tenant,)).fetchone() is None:
                    raise ValueError("accounting tenant unavailable")
                connection.execute(
                    "INSERT INTO accounting_records "
                    "(id,tenant_id,session_id,username,device_id,action,arguments) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (uuid4(), self._tenant, record.session_id, record.username,
                     record.device_id, record.action, Jsonb(list(redact_arguments(record.arguments)))),
                )
                self._audit.append_in_transaction(connection, actor=record.username, source=record.device_id,
                    action="accounting." + record.action, target=record.device_id,
                    result="committed", session_id=record.session_id)
