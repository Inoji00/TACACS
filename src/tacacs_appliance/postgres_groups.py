"""Server-side group membership scoped to a configured tenant."""

from uuid import UUID


class PostgresGroupResolver:
    def __init__(self, pool, tenant_id: str):
        self._pool, self._tenant = pool, UUID(tenant_id)

    def __call__(self, username: str) -> frozenset[str] | None:
        # One statement gives an internally consistent view of status and
        # memberships; client attributes never contribute to this result.
        with self._pool.connection() as connection:
            rows = connection.execute(
                "SELECT g.name FROM users u "
                "LEFT JOIN user_groups ug ON ug.user_id=u.id AND ug.tenant_id=u.tenant_id "
                "LEFT JOIN identity_groups g ON g.id=ug.group_id AND g.tenant_id=u.tenant_id "
                "WHERE u.tenant_id=%s AND u.username=%s AND u.enabled AND NOT u.locked",
                (self._tenant, username),
            ).fetchall()
        if not rows:
            return None
        return frozenset(row[0] for row in rows if row[0] is not None)
