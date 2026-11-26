"""Policy and trusted group membership from a single repeatable-read snapshot."""

from uuid import UUID
from .authorization import (
    AuthorizationEngine,
    AuthorizationRequest,
    AuthorizationResult,
    Decision,
)
from .postgres_policy import decode_rules
from .device_access import assignment, read_only_command
from .shell_profiles import CISCO_IOS, RUCKUS_FASTIRON, shell_reply


def _ipv4(value):
    import ipaddress

    try:
        ipaddress.IPv4Address(value)
        return True
    except (ValueError, TypeError):
        return False


class PostgresAuthorizationService:
    def __init__(self, pool, tenant_id: str, shell_grants=()):
        self._pool, self._tenant = pool, UUID(tenant_id)
        self._shell_grants = tuple(shell_grants)
        self._fastiron_devices = {
            grant.device
            for grant in self._shell_grants
            if grant.profile == RUCKUS_FASTIRON
        }

    def authorize_shell(self, username, device_id):
        with self._pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                rows = connection.execute(
                    "SELECT g.name FROM users u JOIN user_groups ug ON ug.user_id=u.id AND ug.tenant_id=u.tenant_id "
                    "JOIN identity_groups g ON g.id=ug.group_id AND g.tenant_id=u.tenant_id "
                    "WHERE u.tenant_id=%s AND u.username=%s AND u.enabled AND NOT u.locked",
                    (self._tenant, username),
                ).fetchall()
                device = (
                    connection.execute(
                        "SELECT enabled,access_mappings FROM network_devices WHERE tenant_id=%s AND address=%s",
                        (self._tenant, device_id),
                    ).fetchone()
                    if _ipv4(device_id)
                    else None
                )
        groups = {row[0] for row in rows}
        if device is not None:
            if device_id in self._fastiron_devices:
                return ()
            grant = assignment(groups, device[1]) if device[0] else None
            return shell_reply(CISCO_IOS, grant[0]) if grant else ()
        levels = {
            (grant.profile, grant.privilege)
            for grant in self._shell_grants
            if grant.device == device_id and grant.group in groups
        }
        # Ambiguous assignments fail closed rather than silently elevating.
        if len(levels) != 1:
            return ()
        return shell_reply(*levels.pop())

    def authorize(
        self, username: str, device_id: str, command: str
    ) -> AuthorizationResult:
        if device_id in self._fastiron_devices:
            return AuthorizationResult(
                Decision.DENY,
                "default-deny",
                None,
                "command authorization unavailable for profile",
            )
        with self._pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                policy = connection.execute(
                    "SELECT id,rules FROM policy_versions WHERE tenant_id=%s AND state='active'",
                    (self._tenant,),
                ).fetchone()
                engine = (
                    AuthorizationEngine(str(policy[0]), decode_rules(policy[1]))
                    if policy
                    else AuthorizationEngine("default-deny", ())
                )
                rows = connection.execute(
                    "SELECT g.name FROM users u LEFT JOIN user_groups ug ON ug.user_id=u.id AND ug.tenant_id=u.tenant_id "
                    "LEFT JOIN identity_groups g ON g.id=ug.group_id AND g.tenant_id=u.tenant_id "
                    "WHERE u.tenant_id=%s AND u.username=%s AND u.enabled AND NOT u.locked",
                    (self._tenant, username),
                ).fetchall()
                if not rows:
                    return AuthorizationResult(
                        Decision.DENY,
                        str(policy[0]) if policy else "default-deny",
                        None,
                        "identity unavailable",
                    )
                groups = frozenset(row[0] for row in rows if row[0] is not None)
                device = (
                    connection.execute(
                        "SELECT enabled,access_mappings FROM network_devices WHERE tenant_id=%s AND address=%s",
                        (self._tenant, device_id),
                    ).fetchone()
                    if _ipv4(device_id)
                    else None
                )
                if device is not None:
                    grant = assignment(groups, device[1]) if device[0] else None
                    if grant is None or (
                        grant[1] == "read_only" and not read_only_command(command)
                    ):
                        return AuthorizationResult(
                            Decision.DENY,
                            str(policy[0]) if policy else "default-deny",
                            None,
                            "switch access denied",
                        )
                return engine.evaluate(
                    AuthorizationRequest(username, device_id, command, groups)
                )
