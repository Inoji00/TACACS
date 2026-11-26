"""Tenant-scoped active policy snapshot loaded from PostgreSQL."""

from uuid import UUID
from .authorization import AuthorizationEngine, Decision, PolicyRule


def decode_rules(value) -> tuple[PolicyRule, ...]:
    """Validate persisted policy before it crosses the decision boundary."""
    if not isinstance(value, list) or len(value) > 4096:
        raise ValueError("invalid policy rules")
    result, identifiers = [], set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "rule_id",
            "groups",
            "device_ids",
            "command_prefix",
            "decision",
        }:
            raise ValueError("invalid policy rule schema")
        rule_id = item["rule_id"]
        if not isinstance(rule_id, str) or not rule_id or rule_id in identifiers:
            raise ValueError("invalid policy rule identifier")
        identifiers.add(rule_id)
        scopes = []
        for name in ("groups", "device_ids"):
            values = item[name]
            if (
                not isinstance(values, list)
                or len(values) > 1024
                or any(not isinstance(x, str) or not x for x in values)
            ):
                raise ValueError("invalid policy scope")
            scopes.append(frozenset(values))
        prefix = item["command_prefix"]
        if not isinstance(prefix, str) or not prefix.strip() or len(prefix) > 1024:
            raise ValueError("invalid policy command")
        result.append(
            PolicyRule(
                rule_id, scopes[0], scopes[1], prefix, Decision(item["decision"])
            )
        )
    return tuple(result)


def load_active_policy(pool, tenant_id: str) -> AuthorizationEngine:
    tenant = UUID(tenant_id)
    with pool.connection() as connection:
        row = connection.execute(
            "SELECT id,rules FROM policy_versions WHERE tenant_id=%s AND state='active'",
            (tenant,),
        ).fetchone()
    if row is None:
        return AuthorizationEngine("default-deny", ())
    return AuthorizationEngine(str(row[0]), decode_rules(row[1]))


class LivePostgresPolicyEngine:
    """One immutable active snapshot per decision; never reuse stale allows.

    A database failure propagates so the transport fails closed. Activation
    committed before the SELECT is visible without restarting the service.
    An in-flight decision can finish using its already selected snapshot.
    """

    def __init__(self, pool, tenant_id: str):
        self._pool, self._tenant = pool, str(UUID(tenant_id))

    def evaluate(self, request):
        return load_active_policy(self._pool, self._tenant).evaluate(request)
