"""Opaque session credentials; database stores hashes rather than bearer tokens."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID


class PostgresAdminSessions:
    def __init__(self, pool, tenant_id: str, lifetime_seconds: int = 900):
        if not 60 <= lifetime_seconds <= 3600: raise ValueError("invalid session lifetime")
        self._pool,self._tenant,self._lifetime=pool,UUID(tenant_id),lifetime_seconds

    def create(self, user_id: str, *, mfa_verified: bool,factor_id: str | None=None) -> str:
        if not mfa_verified: raise ValueError("MFA required for administrator session")
        if factor_id is None:raise ValueError('verified MFA factor required')
        factor=UUID(factor_id)
        token=secrets.token_urlsafe(32)
        expires=datetime.now(timezone.utc)+timedelta(seconds=self._lifetime)
        with self._pool.connection() as connection:
            with connection.transaction():
                row = connection.execute("SELECT u.id FROM users u WHERE u.id=%s AND u.tenant_id=%s AND u.enabled AND NOT u.locked "
                    "AND EXISTS (SELECT 1 FROM admin_grants g WHERE g.user_id=u.id AND g.tenant_id=u.tenant_id AND g.permission='console.read') "
                    "FOR UPDATE", (UUID(user_id),self._tenant)).fetchone()
                if row is None:
                    raise ValueError("administrator unavailable")
                live_factor=connection.execute('SELECT id FROM mfa_factors WHERE id=%s AND tenant_id=%s '
                    'AND user_id=%s AND enabled AND last_accepted_step>=0 FOR SHARE',
                    (factor,self._tenant,UUID(user_id))).fetchone()
                if live_factor is None:raise ValueError('verified MFA factor unavailable')
                connection.execute("INSERT INTO admin_sessions(token_hash,tenant_id,user_id,expires_at,mfa_verified) VALUES (%s,%s,%s,%s,%s)",
                    (self._hash(token),self._tenant,UUID(user_id),expires,True))
        return token

    def resolve(self, token: str) -> str | None:
        if not isinstance(token,str) or not 40<=len(token)<=128:return None
        with self._pool.connection() as connection:
            row=connection.execute("SELECT s.user_id FROM admin_sessions s JOIN users u ON u.id=s.user_id AND u.tenant_id=s.tenant_id "
                "WHERE s.token_hash=%s AND s.tenant_id=%s AND s.expires_at>now() AND s.mfa_verified AND u.enabled AND NOT u.locked "
                "AND EXISTS (SELECT 1 FROM admin_grants g WHERE g.user_id=u.id AND g.tenant_id=u.tenant_id AND g.permission='console.read')",
                (self._hash(token),self._tenant)).fetchone()
        return str(row[0]) if row else None

    def revoke(self, token: str) -> None:
        with self._pool.connection() as connection:
            with connection.transaction():
                connection.execute("DELETE FROM admin_sessions WHERE token_hash=%s AND tenant_id=%s",(self._hash(token),self._tenant))

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
