"""Bounded tenant-scoped identity inventory; never returns credentials."""

from uuid import UUID


class AdminInventory:
    def __init__(self, pool, tenant):
        self.pool, self.tenant = pool, UUID(tenant)

    def read(self, *, only_user=None):
        with self.pool.connection() as connection:
            subject = UUID(only_user) if only_user is not None else None
            users = connection.execute(
                "SELECT id,username,enabled,locked FROM users WHERE tenant_id=%s AND NOT deleted "
                "AND (%s::uuid IS NULL OR id=%s) ORDER BY username,id LIMIT 201",
                (self.tenant, subject, subject),
            ).fetchall()
            groups = connection.execute(
                "SELECT id,name FROM identity_groups WHERE tenant_id=%s ORDER BY name,id LIMIT 201",
                (self.tenant,),
            ).fetchall()
        return {
            "users": [
                dict(id=str(r[0]), username=r[1], enabled=r[2], locked=r[3])
                for r in users[:200]
            ],
            "groups": [dict(id=str(r[0]), name=r[1]) for r in groups[:200]],
            "truncated": len(users) > 200 or len(groups) > 200,
        }
