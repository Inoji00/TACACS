"""Read-only accounting with bounded redacted command projection, never raw AV pairs."""

from uuid import UUID
import ipaddress
from .accounting import accounting_details
from .admin_logs import log_filters
from .device_console_scope import aaa_log_device_clause, require_aaa_log_scope


class AdminAccounting:
    def __init__(self, pool, tenant):
        self.pool, self.tenant = pool, UUID(tenant)

    def list_events(
        self,
        actor,
        *,
        username="",
        device="",
        session="",
        action="",
        command="",
        since="",
        until="",
        before=None,
        limit=50,
    ):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid limit")
        for value in (username, device, session, action, command):
            if (
                not isinstance(value, str)
                or len(value) > 253
                or any(ord(c) < 32 or ord(c) == 127 for c in value)
            ):
                raise ValueError("invalid filter")
        if action not in ("", "start", "stop", "watchdog"):
            raise ValueError("invalid action")
        if device:
            device = str(ipaddress.IPv4Address(device))
        cursor = UUID(before) if before is not None else None
        clauses = ["tenant_id=%s"]
        values = [self.tenant]
        if since or until or command:
            _, _, start, end, _, _ = log_filters(since=since, until=until)
            clauses.append("occurred_at BETWEEN %s AND %s")
            values.extend((start, end))
        for column, value in (
            ("username", username),
            ("device_id", device),
            ("session_id", session),
            ("action", action),
        ):
            if value:
                clauses.append(column + "=%s")
                values.append(value)
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                connection.execute("SET LOCAL statement_timeout='3000ms'")
                allowed = connection.execute(
                    "SELECT 1 FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
                    "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission='audit.read' AND u.enabled AND NOT u.locked",
                    (self.tenant, UUID(actor)),
                ).fetchone()
                scope_clause = ""
                scope_values = []
                if allowed is None:
                    scope = require_aaa_log_scope(connection, self.tenant, actor)
                    scoped, groups = aaa_log_device_clause(
                        scope,
                        "accounting_records.device_id",
                        "accounting_records.occurred_at",
                    )
                    clauses.append(scoped)
                    scope_clause = " AND " + scoped
                    scope_values = [self.tenant, *groups]
                    values.extend(scope_values)
                if cursor is not None:
                    anchor = connection.execute(
                        "SELECT occurred_at,id FROM accounting_records WHERE tenant_id=%s AND id=%s"
                        + scope_clause,
                        (self.tenant, cursor, *scope_values),
                    ).fetchone()
                    if anchor is None:
                        raise ValueError("cursor unavailable")
                    clauses.append("(occurred_at,id)<(%s,%s)")
                    values.extend(anchor)
                scan_limit = 500 if command else limit
                rows = connection.execute(
                    "SELECT id,occurred_at,session_id,username,device_id,action,arguments FROM accounting_records WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY occurred_at DESC,id DESC LIMIT %s",
                    tuple(values + [scan_limit + 1]),
                ).fetchall()
        items = []
        next_before = None
        needle = command.casefold()
        for index, row in enumerate(rows[:scan_limit]):
            details = accounting_details(row[6])
            visible_command = details.get("command") or ""
            if not needle or (
                not details.get("redacted") and needle in visible_command.casefold()
            ):
                items.append(
                    dict(
                        id=str(row[0]),
                        timestamp=row[1].isoformat(),
                        session=row[2],
                        username=row[3],
                        device=row[4],
                        action=row[5],
                        **details,
                    )
                )
            if len(items) == limit or index + 1 == scan_limit:
                next_before = str(row[0]) if index + 1 < len(rows) else None
                break
        return {"items": items, "next_before": next_before, "scope": "accounting-only"}
