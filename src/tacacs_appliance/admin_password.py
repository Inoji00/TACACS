"""Authenticated self-service password change, atomic with redacted audit."""
from uuid import UUID
from .password_policy import valid_new_password
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError,InvalidHashError
from .password_timing import acceptable_password_hash,bounded_password_work


@bounded_password_work
def verify_current_password(connection,tenant,actor,password):
    row=connection.execute(
        'SELECT password_hash FROM users u WHERE tenant_id=%s AND id=%s AND enabled AND NOT locked AND NOT deleted '
        'AND EXISTS (SELECT 1 FROM admin_grants g WHERE g.tenant_id=u.tenant_id AND g.user_id=u.id '
        "AND g.permission='console.read')",(tenant,UUID(actor))).fetchone()
    if row is None or not acceptable_password_hash(row[0]):
        raise PermissionError('password verification failed')
    try:
        PasswordHasher().verify(row[0],password)
    except (VerifyMismatchError,InvalidHashError):
        raise PermissionError('password verification failed') from None
    return True


class AdminPasswordChange:
    def __init__(self,pool,tenant,audit):self.pool,self.tenant,self.audit=pool,UUID(tenant),audit

    @bounded_password_work
    def change(self,actor,current_password,new_password):
        if (not isinstance(current_password,str) or not 1<=len(current_password)<=1024
                or not valid_new_password(new_password)
                or current_password==new_password):raise ValueError('invalid password change')
        user=UUID(actor);hasher=PasswordHasher()
        with self.pool.connection() as connection:
            with connection.transaction():
                row=connection.execute('SELECT password_hash FROM users u WHERE tenant_id=%s AND id=%s '
                    'AND enabled AND NOT locked AND EXISTS (SELECT 1 FROM admin_grants g '
                    "WHERE g.tenant_id=u.tenant_id AND g.user_id=u.id AND g.permission='console.read') FOR UPDATE",
                    (self.tenant,user)).fetchone()
                if row is None or not acceptable_password_hash(row[0]):raise PermissionError('password verification failed')
                try:hasher.verify(row[0],current_password)
                except (VerifyMismatchError,InvalidHashError):raise PermissionError('password verification failed') from None
                connection.execute('UPDATE users SET password_hash=%s,failed_logins=0 WHERE tenant_id=%s AND id=%s',
                    (hasher.hash(new_password),self.tenant,user))
                self.audit(connection,actor=str(user),source='admin-password',action='admin.password.change',
                    target=str(user),result='success')
