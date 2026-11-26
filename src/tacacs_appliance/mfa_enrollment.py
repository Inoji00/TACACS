"""Operator-only confirmation of a pending TOTP factor, with transactional audit."""

import hmac
import time
from uuid import UUID
from .mfa import totp
from .postgres_audit import PostgresAuditWriter


def confirm_pending_factor(
    connection,
    *,
    tenant_id: str,
    user_id: str,
    factor_id: str,
    code: str,
    resolve_secret,
    now: int | None = None,
) -> bool:
    if (
        not isinstance(code, str)
        or not code.isascii()
        or not code.isdecimal()
        or len(code) != 6
    ):
        return False
    tenant, user, factor = UUID(tenant_id), UUID(user_id), UUID(factor_id)
    current = int(time.time() if now is None else now) // 30
    with connection.transaction():
        if (
            connection.execute(
                "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (tenant,)
            ).fetchone()
            is None
        ):
            return False
        if (
            connection.execute(
                "SELECT id FROM users WHERE id=%s AND tenant_id=%s AND enabled AND NOT locked FOR UPDATE",
                (user, tenant),
            ).fetchone()
            is None
        ):
            return False
        row = connection.execute(
            "SELECT secret_reference,enabled,last_accepted_step FROM mfa_factors "
            "WHERE id=%s AND tenant_id=%s AND user_id=%s FOR UPDATE",
            (factor, tenant, user),
        ).fetchone()
        if row is None or row[1]:
            return False
        secret = resolve_secret(row[0])
        matches = [
            step
            for step in (current - 1, current, current + 1)
            if step >= 0
            and step > row[2]
            and hmac.compare_digest(code, totp(secret, step * 30))
        ]
        if not matches:
            return False
        connection.execute(
            "UPDATE mfa_factors SET enabled=TRUE,last_accepted_step=%s,failed_attempts=0,locked_until=NULL "
            "WHERE id=%s AND tenant_id=%s AND user_id=%s",
            (max(matches), factor, tenant, user),
        )
        PostgresAuditWriter(None, str(tenant)).append_in_transaction(
            connection,
            actor="operator-enrollment",
            source="local-cli",
            action="mfa.confirm",
            target=str(factor),
            result="success",
        )
    return True
