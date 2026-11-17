"""PostgreSQL audit appends serialized using the tenant row lock."""
from datetime import datetime, timezone
import hashlib
import json
import hmac
import ipaddress
import re
from psycopg import Error as DatabaseError
from uuid import UUID, uuid4
from psycopg.types.json import Jsonb
from .audit import _canonical


class PostgresAuditWriter:
    def __init__(self, pool, tenant_id: str):
        self._pool, self._tenant = pool, UUID(tenant_id)

    def append(self, *, actor: str, source: str, action: str, target: str,
               result: str, policy_version: str | None = None,
               session_id: str | None = None, correlation_id: str = "",
               security_context: dict | None = None) -> str:
        with self._pool.connection() as connection:
            with connection.transaction():
                return self.append_in_transaction(connection, actor=actor, source=source, action=action,
                    target=target, result=result, policy_version=policy_version, session_id=session_id,
                    correlation_id=correlation_id, security_context=security_context)

    def _device_name(self, connection, target):
        try:
            address = str(ipaddress.IPv4Address(target))
        except (ValueError, TypeError):
            return None
        try:
            # Keep a failed enrichment query from rolling back the audit append.
            with connection.transaction():
                row = connection.execute(
                    'SELECT name FROM network_devices WHERE tenant_id=%s AND address=%s AND NOT deleted',
                    (self._tenant,address)).fetchone()
        except DatabaseError:
            return None
        name = row[0] if row else None
        return name if isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_. -]{1,64}',name) else None

    def append_in_transaction(self, connection, *, actor: str, source: str, action: str,
                              target: str, result: str, policy_version: str | None = None,
                              session_id: str | None = None, correlation_id: str = "",
                              security_context: dict | None = None) -> str:
        """Caller owns transaction/commit; acquire tenant lock before mutations.

        This method neither opens a second connection nor commits independently.
        """
        from psycopg.pq import TransactionStatus
        if connection.info.transaction_status != TransactionStatus.INTRANS:
            raise ValueError("audit requires an active transaction")
        tenant = connection.execute("SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self._tenant,)).fetchone()
        if tenant is None:
            raise ValueError("audit tenant unavailable")
        previous = connection.execute("SELECT event_hash FROM audit_events WHERE tenant_id=%s ORDER BY chain_sequence DESC LIMIT 1", (self._tenant,)).fetchone()
        if source == 'tacacs' and action in ('aaa.authentication','aaa.authorization','aaa.accounting'):
            if name := self._device_name(connection, target):
                security_context = {**(security_context or {}), 'target_name': name}
        event = dict(event_id=str(uuid4()), tenant_id=str(self._tenant), timestamp=datetime.now(timezone.utc).isoformat(),
                     actor=actor, source=source, action=action, target=target, result=result,
                     policy_version=policy_version, session_id=session_id, correlation_id=correlation_id,
                     security_context=security_context or {}, previous_hash=previous[0] if previous else "0" * 64)
        canonical = _canonical(event)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        connection.execute("INSERT INTO audit_events "
            "(id,tenant_id,occurred_at,actor,source,action,target,result,policy_version,session_id,correlation_id,security_context,previous_hash,event_hash,canonical_data) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (UUID(event["event_id"]), self._tenant, event["timestamp"], actor, source, action, target, result, policy_version,
             session_id, correlation_id, Jsonb(event["security_context"]), event["previous_hash"], digest, canonical))
        return digest

    def policy_callback(self, connection, *, actor: str, action: str, target: str) -> str:
        return self.append_in_transaction(connection, actor=actor, source="admin-policy",
                                          action=action, target=target, result="success", policy_version=target)

    def verify(self) -> bool:
        """Verify a consistent snapshot. A trusted external anchor is still
        required to detect removal of a valid trailing segment or total rewrite.
        """
        with self._pool.connection() as connection:
            with connection.transaction():
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                rows = connection.execute("SELECT canonical_data,previous_hash,event_hash,actor,source,action,target,result,policy_version,session_id,correlation_id,security_context,id,occurred_at FROM audit_events WHERE tenant_id=%s ORDER BY chain_sequence", (self._tenant,)).fetchall()
                previous = "0" * 64
                for row in rows:
                    if len(row) != 14:
                        return False
                    canonical, stored_previous, digest = row[:3]
                    if (not isinstance(canonical, str) or stored_previous != previous
                            or not isinstance(digest, str) or len(digest) != 64
                            or any(c not in "0123456789abcdef" for c in digest)):
                        return False
                    try:
                        event = json.loads(canonical)
                        if not isinstance(event, dict): return False
                        if event["tenant_id"] != str(self._tenant) or event["previous_hash"] != previous: return False
                        if _canonical(event) != canonical: return False
                        names = ("actor","source","action","target","result","policy_version","session_id","correlation_id","security_context")
                        if any(event.get(name) != value for name,value in zip(names,row[3:12],strict=True)): return False
                        if event.get("event_id") != str(row[12]): return False
                        if datetime.fromisoformat(event["timestamp"]) != row[13]: return False
                    except (ValueError, KeyError, TypeError, OverflowError):
                        return False
                    if not hmac.compare_digest(hashlib.sha256(canonical.encode()).hexdigest(), digest): return False
                    previous = digest
                return True
