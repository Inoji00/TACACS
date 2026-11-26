"""Atomic TOTP replay prevention with externally resolved MFA secrets."""

import hmac
import time
from uuid import UUID
from .mfa import totp


class PostgresTotpVerifier:
    def __init__(self, pool, tenant_id: str, resolve_secret):
        self._pool, self._tenant, self._resolve = pool, UUID(tenant_id), resolve_secret

    def verify(
        self, user_id: str, factor_id: str, code: str, now: int | None = None
    ) -> bool:
        if (
            not isinstance(code, str)
            or not code.isascii()
            or not code.isdecimal()
            or len(code) != 6
        ):
            return False
        current = int(time.time() if now is None else now) // 30
        with self._pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT secret_reference,last_accepted_step,failed_attempts,"
                    "locked_until>clock_timestamp(),locked_until IS NOT NULL AND locked_until<=clock_timestamp() FROM mfa_factors "
                    "WHERE id=%s AND user_id=%s AND tenant_id=%s AND enabled "
                    "AND EXISTS (SELECT 1 FROM users u WHERE u.id=mfa_factors.user_id "
                    "AND u.tenant_id=mfa_factors.tenant_id AND u.enabled AND NOT u.locked) FOR UPDATE",
                    (UUID(factor_id), UUID(user_id), self._tenant),
                ).fetchone()
                if row is None:
                    return False
                if row[3]:
                    return False
                failures = 0 if row[4] else row[2]
                secret = self._resolve(row[0])
                # Lock spans verification and update, preventing two concurrent
                # requests from consuming the same time step on separate nodes.
                matches = [
                    step
                    for step in (current - 1, current, current + 1)
                    if step >= 0
                    and step > row[1]
                    and hmac.compare_digest(code, totp(secret, step * 30))
                ]
                if not matches:
                    failures += 1
                    connection.execute(
                        "UPDATE mfa_factors SET failed_attempts=%s,"
                        "locked_until=CASE WHEN %s>=5 THEN clock_timestamp()+interval '5 minutes' ELSE NULL END "
                        "WHERE id=%s AND tenant_id=%s",
                        (failures, failures, UUID(factor_id), self._tenant),
                    )
                    return False
                connection.execute(
                    "UPDATE mfa_factors SET last_accepted_step=%s,failed_attempts=0,locked_until=NULL WHERE id=%s AND tenant_id=%s",
                    (max(matches), UUID(factor_id), self._tenant),
                )
                return True
