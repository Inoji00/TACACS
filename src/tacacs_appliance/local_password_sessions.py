"""Explicit local evaluation sessions. Never records a false MFA assertion."""
import hashlib
import hmac
import secrets
import threading
import time
from uuid import UUID


class LocalPasswordSessions:
    def __init__(self,pool,tenant_id):
        self.pool,self.tenant=pool,UUID(tenant_id)
        self.entries={};self.lock=threading.Lock()

    def snapshot(self,user):
        with self.pool.connection() as connection:
            row=connection.execute('SELECT u.password_hash,g.generation FROM users u JOIN admin_grants g '
                'ON g.tenant_id=u.tenant_id AND g.user_id=u.id WHERE u.tenant_id=%s AND u.id=%s '
                "AND u.enabled AND NOT u.locked AND NOT u.deleted AND g.permission='console.read'",
                (self.tenant,UUID(user))).fetchone()
        return hashlib.sha256(row[0].encode()+row[1].bytes).digest() if row else None

    def create_password_only(self,user):
        fingerprint=self.snapshot(user)
        if fingerprint is None:raise ValueError('administrator unavailable')
        token=secrets.token_urlsafe(32);now=time.monotonic()
        with self.lock:
            self.entries={key:value for key,value in self.entries.items() if value[1]>now}
            if len(self.entries)>=256:raise ValueError('local session capacity reached')
            self.entries[hashlib.sha256(token.encode()).digest()]=(user,now+900,fingerprint)
        return token

    def resolve(self,token):
        if not isinstance(token,str) or not 40<=len(token)<=128:return None
        key=hashlib.sha256(token.encode()).digest()
        with self.lock:entry=self.entries.get(key)
        if entry is None:return None
        fingerprint=self.snapshot(entry[0])
        if entry[1]<=time.monotonic() or fingerprint is None or not hmac.compare_digest(entry[2],fingerprint):
            self.revoke(token);return None
        return entry[0]

    def revoke(self,token):
        with self.lock:self.entries.pop(hashlib.sha256(token.encode()).digest(),None)
