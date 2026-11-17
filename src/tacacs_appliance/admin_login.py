"""Password/TOTP by default; explicit password-only configuration."""
from uuid import UUID


class PostgresAdminSubjectResolver:
    def __init__(self, pool, tenant_id: str):
        self._pool, self._tenant = pool, UUID(tenant_id)

    def __call__(self, username: str) -> str | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT id FROM users WHERE tenant_id=%s AND username=%s AND enabled AND NOT locked",
                (self._tenant, username)).fetchone()
        return str(row[0]) if row else None


class AdminLoginService:
    def __init__(self, passwords, subjects, permissions, totp, sessions,*,password_only=False):
        if type(password_only) is not bool:raise ValueError('explicit authentication mode required')
        self.password_only=password_only
        self._passwords, self._subjects, self._permissions = passwords, subjects, permissions
        self._totp, self._sessions = totp, sessions

    def login(self, username: str, password: str, factor_id=None, code=None) -> str | None:
        if (not isinstance(username, str) or not 1 <= len(username) <= 253
                or any(ord(c) < 32 or ord(c) == 127 for c in username)
                or not isinstance(password, str) or not 1 <= len(password) <= 1024):
            return None
        if not self.password_only:
            if not isinstance(code,str) or len(code)!=6 or not code.isascii() or not code.isdecimal():return None
            try:factor=str(UUID(factor_id))
            except (ValueError,TypeError,AttributeError):return None
        result = self._passwords.authenticate(username, password)
        if not result.authenticated:
            return None
        # Resolve from the authenticated provider subject, never caller user ID.
        if not isinstance(result.subject, str):
            return None
        user_id = self._subjects(result.subject)
        if user_id is None or not self._permissions(user_id, "console.read"):
            return None
        if self.password_only:return self._sessions.create_password_only(user_id)
        if not self._totp.verify(user_id, factor, code):
            return None
        return self._sessions.create(user_id, mfa_verified=True,factor_id=factor)
