"""Bounded tenant audit summaries, never raw canonical/security-context data."""

from uuid import UUID


class PostgresAdminAudit:
    def __init__(self, pool, tenant_id):
        self.pool, self.tenant = pool, UUID(tenant_id)

    def list_events(self, actor, *, before=9223372036854775807, limit=50):
        if (
            type(before) is not int
            or not 1 <= before <= 9223372036854775807
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise ValueError("invalid pagination")
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                allowed = connection.execute(
                    "SELECT 1 FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
                    "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission='audit.read' AND u.enabled AND NOT u.locked",
                    (self.tenant, UUID(actor)),
                ).fetchone()
                if allowed is None:
                    raise PermissionError("audit permission required")
                rows = connection.execute(
                    "SELECT id,chain_sequence,occurred_at,left(actor,256),left(source,256),"
                    "left(action,256),left(target,256),left(result,256),event_hash FROM audit_events "
                    "WHERE tenant_id=%s AND chain_sequence<%s ORDER BY chain_sequence DESC LIMIT %s",
                    (self.tenant, before, limit + 1),
                ).fetchall()
        names = (
            "event_id",
            "sequence",
            "timestamp",
            "actor",
            "source",
            "action",
            "target",
            "result",
            "event_hash",
        )
        items = [
            dict(
                zip(
                    names,
                    (str(row[0]), row[1], row[2].isoformat(), *row[3:]),
                    strict=True,
                )
            )
            for row in rows[:limit]
        ]
        return dict(
            items=items,
            next_before=items[-1]["sequence"] if len(rows) > limit else None,
        )
