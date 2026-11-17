"""Local identities persisted in PostgreSQL with atomic lockout counters."""
from uuid import UUID
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from .local_identity import AuthenticationResult
from .password_timing import DummyPasswordVerifier, bounded_password_work, acceptable_password_hash


class PostgresLocalProvider:
    def __init__(self, pool, tenant_id: str, lockout_after: int = 5):
        if lockout_after < 1: raise ValueError("invalid lockout threshold")
        self._pool, self._tenant = pool, UUID(tenant_id)
        self._threshold = lockout_after
        self._hasher = PasswordHasher()
        self._dummy = DummyPasswordVerifier()

    @bounded_password_work
    def authenticate(self, username: str, password: str) -> AuthenticationResult:
        """Row lock makes counters consistent across processes and HA nodes."""
        with self._pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT id,password_hash,enabled,locked,failed_logins FROM users "
                    "WHERE tenant_id=%s AND username=%s FOR UPDATE", (self._tenant, username)
                ).fetchone()
                if row is None or not row[2] or row[3]:
                    self._dummy.verify(password)
                    return AuthenticationResult(False)
                if not acceptable_password_hash(row[1]):
                    self._dummy.verify(password)
                    return AuthenticationResult(False)
                try:
                    self._hasher.verify(row[1], password)
                except (VerifyMismatchError, InvalidHashError):
                    failures = row[4] + 1
                    connection.execute("UPDATE users SET failed_logins=%s,locked=%s WHERE id=%s AND tenant_id=%s",
                                       (failures, failures >= self._threshold, row[0], self._tenant))
                    return AuthenticationResult(False)
                password_hash = self._hasher.hash(password) if self._hasher.check_needs_rehash(row[1]) else row[1]
                connection.execute("UPDATE users SET failed_logins=0,password_hash=%s WHERE id=%s AND tenant_id=%s",
                                   (password_hash, row[0], self._tenant))
                return AuthenticationResult(True, username, "")
