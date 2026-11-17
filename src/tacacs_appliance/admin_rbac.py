"""Explicit tenant-scoped administrative grants, separate from device groups."""
from uuid import UUID

PERMISSIONS = frozenset({"console.read", "users.manage", "devices.manage", "policy.draft",
                         "policy.approve", "policy.activate", "audit.read", "backup.manage"})
DEVICE_OPERATOR_PERMISSIONS = frozenset({"console.read", "devices.manage"})


class PostgresAdminPermissions:
    def __init__(self, pool, tenant_id: str):
        self._pool, self._tenant = pool, UUID(tenant_id)

    def __call__(self, user_id: str, permission: str) -> bool:
        if permission not in PERMISSIONS:
            return False
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
                "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission=%s AND u.enabled AND NOT u.locked",
                (self._tenant, UUID(user_id), permission)).fetchone()
        return row is not None

    def device_operator(self, user_id: str) -> bool:
        with self._pool.connection() as connection:
            rows = connection.execute(
                "SELECT permission FROM admin_grants WHERE tenant_id=%s AND user_id=%s",
                (self._tenant, UUID(user_id))).fetchall()
        return {permission for permission, in rows} == DEVICE_OPERATOR_PERMISSIONS
