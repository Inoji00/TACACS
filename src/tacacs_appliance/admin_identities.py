"""Tenant-scoped identity provisioning and device console delegation."""
import re
from uuid import UUID, uuid4
from argon2 import PasswordHasher
from psycopg.errors import ForeignKeyViolation
from .password_timing import bounded_password_work
from .device_console_scope import SCOPE_JSON, parse_scope


class IdentityProtectedError(ValueError):pass
class IdentityNameUnavailable(ValueError):pass


class AdminIdentities:
    def __init__(self, pool, tenant, audit):
        self.pool, self.tenant, self.audit = pool, UUID(tenant), audit

    @bounded_password_work
    def create(self, actor, username, password, group_name):
        if (not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username)
                or not isinstance(password, str) or not 8 <= len(password) <= 1024
                or not isinstance(group_name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', group_name)):
            raise ValueError('invalid identity')
        actor, user, group = UUID(actor), uuid4(), uuid4()
        password_hash = PasswordHasher().hash(password)
        with self.pool.connection() as connection:
            with connection.transaction():
                self._authorize(connection, actor)
                if connection.execute('SELECT 1 FROM users WHERE tenant_id=%s AND username=%s',
                                      (self.tenant, username)).fetchone():
                    raise IdentityNameUnavailable('username unavailable')
                connection.execute('INSERT INTO identity_groups(id,tenant_id,name) VALUES (%s,%s,%s) '
                                   'ON CONFLICT (tenant_id,name) DO NOTHING', (group, self.tenant, group_name))
                group = connection.execute('SELECT id FROM identity_groups WHERE tenant_id=%s AND name=%s',
                                           (self.tenant, group_name)).fetchone()[0]
                connection.execute('INSERT INTO users(id,tenant_id,username,password_hash) VALUES (%s,%s,%s,%s)',
                                   (user, self.tenant, username, password_hash))
                connection.execute('INSERT INTO user_groups(tenant_id,user_id,group_id) VALUES (%s,%s,%s)',
                                   (self.tenant, user, group))
                self.audit(connection, actor=str(actor), source='admin-identities', action='identity.create',
                           target=str(user), result='success',
                           security_context={'target_name':username,'identity_group':group_name})
        return {'id': str(user)}

    def set_enabled(self, actor, user_id, enabled):
        actor, user = UUID(actor), UUID(user_id)
        if type(enabled) is not bool:raise ValueError('invalid state')
        if actor == user:raise IdentityProtectedError('identity protected')
        with self.pool.connection() as connection:
            with connection.transaction():
                self._authorize(connection, actor)
                # Console accounts require a separate administrative recovery workflow.
                row = connection.execute('SELECT username FROM users u WHERE tenant_id=%s AND id=%s '
                    'AND NOT deleted AND NOT EXISTS (SELECT 1 FROM admin_grants g WHERE g.tenant_id=u.tenant_id AND g.user_id=u.id) '
                    'FOR UPDATE', (self.tenant, user)).fetchone()
                if row is None:
                    raise IdentityProtectedError('identity protected')
                connection.execute('UPDATE users SET enabled=%s WHERE tenant_id=%s AND id=%s',
                                   (enabled, self.tenant, user))
                self.audit(connection, actor=str(actor), source='admin-identities', action='identity.enable' if enabled else 'identity.disable',
                           target=str(user), result='success',
                           security_context={'target_name':row[0],'enabled':enabled})
        return {'status': 'committed'}

    def _authorize(self, connection, actor):
        # Tenant lock orders mutations with audit and serializes duplicate names.
        connection.execute('SELECT id FROM tenants WHERE id=%s FOR UPDATE', (self.tenant,))
        row = connection.execute("SELECT 1 FROM users u JOIN admin_grants g ON g.user_id=u.id AND g.tenant_id=u.tenant_id "
            "WHERE u.tenant_id=%s AND u.id=%s AND u.enabled AND NOT u.locked AND g.permission='users.manage'",
            (self.tenant, actor)).fetchone()
        if row is None:
            raise PermissionError('permission denied')

    def set_console_access(self, actor, user_id, enabled, access=None):
        if type(enabled) is not bool or (not enabled and access is not None):
            raise ValueError('invalid state')
        scope=parse_scope(access) if access is not None else None
        actor, user = UUID(actor), UUID(user_id)
        if actor == user:
            raise IdentityProtectedError('identity protected')
        with self.pool.connection() as connection, connection.transaction():
            self._authorize(connection, actor)
            if scope is not None:
                for group_id,kind in zip(scope[:2],('location','device_type')):
                    if group_id is not None and connection.execute(
                        'SELECT 1 FROM network_device_groups WHERE tenant_id=%s AND id=%s AND kind=%s',
                        (self.tenant,group_id,kind)).fetchone() is None:
                        raise ValueError('device group unavailable')
                # Rotate grant generation to invalidate sessions when changing scope.
                protected, = connection.execute(
                    'SELECT set_device_console_access(%s,%s,%s,false)',
                    (self.tenant,actor,user)).fetchone()
                if protected is None:
                    raise IdentityProtectedError('identity protected')
            changed, = connection.execute(
                'SELECT set_device_console_access(%s,%s,%s,%s)',
                (self.tenant, actor, user, enabled)).fetchone()
            if changed is None:
                raise IdentityProtectedError('identity protected')
            if enabled and (scope is not None or changed):
                location,device_type,actions,creation_addresses=scope if scope is not None else (None,None,[],[])
                connection.execute(
                    'INSERT INTO device_console_scopes(tenant_id,user_id,location_id,device_type_id,actions,creation_addresses) '
                    'VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (tenant_id,user_id) DO UPDATE '
                    'SET location_id=EXCLUDED.location_id,device_type_id=EXCLUDED.device_type_id,'
                    'actions=EXCLUDED.actions,creation_addresses=EXCLUDED.creation_addresses',
                    (self.tenant,user,location,device_type,actions,creation_addresses))
            elif not enabled:
                connection.execute('DELETE FROM device_console_scopes WHERE tenant_id=%s AND user_id=%s',(self.tenant,user))
            context={'security_context':{'location_id':access['location_id'],'device_type_id':access['device_type_id'],
                'actions':scope[2],'creation_addresses':scope[3]}} if scope is not None else {}
            if changed:
                name, = connection.execute('SELECT username FROM users WHERE tenant_id=%s AND id=%s',
                                           (self.tenant,user)).fetchone()
                details=context.get('security_context',{})
                details.update(target_name=name,web_access=enabled)
                self.audit(connection, actor=str(actor), source='admin-identities',
                           action='identity.console.scope' if scope is not None else 'identity.console.grant' if enabled else 'identity.console.revoke',
                           target=str(user), result='success', security_context=details)
        return {'status': 'committed'}

    def list_users(self, actor, after=None):
        cursor=UUID(after) if after else None
        with self.pool.connection() as connection:
            with connection.transaction():
                self._authorize(connection,UUID(actor))
                rows=connection.execute(
                    'SELECT u.id,u.username,u.enabled,u.locked,'
                    'EXISTS(SELECT 1 FROM admin_grants a WHERE a.tenant_id=u.tenant_id AND a.user_id=u.id),'
                    'COALESCE((SELECT array_agg(g.name ORDER BY g.name) FROM user_groups m '
                    'JOIN identity_groups g ON g.id=m.group_id AND g.tenant_id=m.tenant_id '
                    'WHERE m.tenant_id=u.tenant_id AND m.user_id=u.id),ARRAY[]::text[]),'
                    'COALESCE((SELECT array_agg(a.permission ORDER BY a.permission) FROM admin_grants a WHERE a.tenant_id=u.tenant_id AND a.user_id=u.id),ARRAY[]::text[]),'
                    f'(SELECT {SCOPE_JSON} FROM device_console_scopes s WHERE s.tenant_id=u.tenant_id AND s.user_id=u.id) '
                    'FROM users u WHERE u.tenant_id=%s AND NOT u.deleted AND (%s::uuid IS NULL OR u.id>%s) '
                    'ORDER BY u.id LIMIT 101',(self.tenant,cursor,cursor)).fetchall()
                devices=connection.execute('SELECT name,host(address),enabled,access_mappings FROM network_devices WHERE tenant_id=%s AND NOT deleted ORDER BY address',(self.tenant,)).fetchall()
                policy=connection.execute("SELECT id,revision FROM policy_versions WHERE tenant_id=%s AND state='active'",(self.tenant,)).fetchone()
        from .device_access import assignment
        def access(row):
            items=[]
            for name,address,enabled,mappings in devices:
                matched=[m for m in mappings if m.get('group') in row[5]]
                if not matched:continue
                grant=assignment(set(row[5]),mappings)
                items.append(dict(device=name,address=address,groups=[m['group'] for m in matched],privilege=grant[0] if grant else None,
                    mode=grant[1] if grant else None,state='blocked' if not enabled or not row[2] or row[3] else 'conflict' if grant is None else 'mapped'))
            return dict(items=items[:20],total=len(items),truncated=len(items)>20)
        return dict(users=[dict(id=str(r[0]),username=r[1],enabled=r[2],locked=r[3],
                    editable=not r[4] and str(r[0])!=str(actor),groups=r[5],console_permissions=r[6],device_access=r[7],switch_access=access(r)) for r in rows[:100]],
                    next_after=str(rows[99][0]) if len(rows)>100 else None,
                    command_policy=dict(id=str(policy[0]),revision=policy[1]) if policy else None)

    @bounded_password_work
    def update(self, actor, user_id, username, password, group_name, enabled):
        if (not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}',username)
                or not isinstance(password,str) or (password and not 8<=len(password)<=1024)
                or not isinstance(group_name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',group_name)
                or type(enabled) is not bool):
            raise ValueError('invalid identity')
        actor,user=UUID(actor),UUID(user_id)
        password_hash=PasswordHasher().hash(password) if password else None
        with self.pool.connection() as connection:
            with connection.transaction():
                self._authorize(connection,actor)
                previous_name=self._device_user(connection,actor,user)
                duplicate=connection.execute('SELECT 1 FROM users WHERE tenant_id=%s AND username=%s AND id<>%s',
                    (self.tenant,username,user)).fetchone()
                if duplicate:raise IdentityNameUnavailable('username unavailable')
                connection.execute('INSERT INTO identity_groups(id,tenant_id,name) VALUES (%s,%s,%s) '
                    'ON CONFLICT (tenant_id,name) DO NOTHING',(uuid4(),self.tenant,group_name))
                group=connection.execute('SELECT id FROM identity_groups WHERE tenant_id=%s AND name=%s',
                    (self.tenant,group_name)).fetchone()[0]
                connection.execute('UPDATE users SET username=%s,enabled=%s WHERE tenant_id=%s AND id=%s',
                    (username,enabled,self.tenant,user))
                if password_hash:
                    connection.execute('UPDATE users SET password_hash=%s WHERE tenant_id=%s AND id=%s',
                        (password_hash,self.tenant,user))
                connection.execute('DELETE FROM user_groups WHERE tenant_id=%s AND user_id=%s',(self.tenant,user))
                connection.execute('INSERT INTO user_groups(tenant_id,user_id,group_id) VALUES (%s,%s,%s)',
                    (self.tenant,user,group))
                self.audit(connection,actor=str(actor),source='admin-identities',action='identity.update',
                    target=str(user),result='success',security_context={
                        'target_name':username,'previous_name':previous_name,'identity_group':group_name,
                        'enabled':enabled,'password_changed':password_hash is not None,
                    })
        return {'status':'committed'}

    def delete(self, actor, user_id):
        actor,user=UUID(actor),UUID(user_id)
        with self.pool.connection() as connection:
            with connection.transaction():
                self._authorize(connection,actor)
                name=self._device_user(connection,actor,user)
                connection.execute('DELETE FROM user_groups WHERE tenant_id=%s AND user_id=%s',(self.tenant,user))
                connection.execute('DELETE FROM admin_sessions WHERE tenant_id=%s AND user_id=%s',(self.tenant,user))
                try:
                    # A savepoint isolates an FK failure from the removal and audit transaction.
                    with connection.transaction():
                        connection.execute('DELETE FROM users WHERE tenant_id=%s AND id=%s',
                                           (self.tenant,user))
                except ForeignKeyViolation:
                    connection.execute(
                        "UPDATE users SET username=':deleted:' || id::text, password_hash='!', "
                        'enabled=false, deleted=true WHERE tenant_id=%s AND id=%s', (self.tenant,user))
                self.audit(connection,actor=str(actor),source='admin-identities',action='identity.delete',
                    target=str(user),result='success',security_context={'target_name':name})
        return {'status':'committed'}

    def _device_user(self, connection, actor, user):
        if actor==user:raise IdentityProtectedError('identity protected')
        row=connection.execute('SELECT username FROM users u WHERE tenant_id=%s AND id=%s '
            'AND NOT deleted AND NOT EXISTS (SELECT 1 FROM admin_grants g WHERE g.tenant_id=u.tenant_id AND g.user_id=u.id) '
            'FOR UPDATE',(self.tenant,user)).fetchone()
        if row is None:raise IdentityProtectedError('identity protected')
        return row[0]
