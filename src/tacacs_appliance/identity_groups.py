"""Explicit group management with dependency checks; never rewrites policy history."""
import re
from uuid import UUID,uuid4


class IdentityGroups:
    def __init__(self,identities):self.identities=identities;self.pool=identities.pool;self.tenant=identities.tenant

    def _counts(self,connection,identifier,name):
        members=connection.execute('SELECT count(*) FROM user_groups WHERE tenant_id=%s AND group_id=%s',(self.tenant,identifier)).fetchone()[0]
        devices=connection.execute("SELECT count(*) FROM network_devices d WHERE tenant_id=%s AND NOT deleted AND EXISTS(SELECT 1 FROM jsonb_array_elements(d.access_mappings) m WHERE m->>'group'=%s)",(self.tenant,name)).fetchone()[0]
        policies=connection.execute("SELECT count(*) FROM policy_versions p WHERE tenant_id=%s AND EXISTS(SELECT 1 FROM jsonb_array_elements(p.rules) r WHERE (r->'groups') ? %s)",(self.tenant,name)).fetchone()[0]
        return members,devices,policies

    def list(self,actor,after=None):
        cursor=UUID(after) if after else None
        with self.pool.connection() as connection:
            with connection.transaction():
                self.identities._authorize(connection,UUID(actor))
                rows=connection.execute('SELECT id,name FROM identity_groups WHERE tenant_id=%s AND (%s::uuid IS NULL OR id>%s) ORDER BY id LIMIT 101',(self.tenant,cursor,cursor)).fetchall()
                items=[]
                for identifier,name in rows[:100]:
                    members,devices,policies=self._counts(connection,identifier,name)
                    items.append(dict(id=str(identifier),name=name,members=members,devices=devices,policies=policies,editable=not any((members,devices,policies))))
        return dict(groups=items,next_after=str(rows[99][0]) if len(rows)>100 else None)

    def save(self,actor,payload):
        if not isinstance(payload,dict):raise ValueError('invalid group')
        operation=payload.get('operation')
        fields={'create':{'operation','name'},'rename':{'operation','id','name'},'delete':{'operation','id'}}
        if not isinstance(operation,str) or operation not in fields or set(payload)!=fields[operation]:raise ValueError('invalid group')
        identifier=UUID(payload['id']) if operation!='create' and isinstance(payload['id'],str) else uuid4() if operation=='create' else None
        if identifier is None:raise ValueError('invalid group identifier')
        name=payload.get('name')
        if operation!='delete' and (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',name)):raise ValueError('invalid group name')
        with self.pool.connection() as connection:
            with connection.transaction():
                self.identities._authorize(connection,UUID(actor))
                if operation!='create':
                    row=connection.execute('SELECT name FROM identity_groups WHERE tenant_id=%s AND id=%s FOR UPDATE',(self.tenant,identifier)).fetchone()
                    if row is None:raise ValueError('group unavailable')
                    if any(self._counts(connection,identifier,row[0])):raise ValueError('group is referenced')
                if operation!='delete':
                    if connection.execute('SELECT 1 FROM identity_groups WHERE tenant_id=%s AND name=%s AND id<>%s',(self.tenant,name,identifier)).fetchone():raise ValueError('group name unavailable')
                if operation=='create':connection.execute('INSERT INTO identity_groups(id,tenant_id,name) VALUES (%s,%s,%s)',(identifier,self.tenant,name))
                elif operation=='rename':connection.execute('UPDATE identity_groups SET name=%s WHERE tenant_id=%s AND id=%s',(name,self.tenant,identifier))
                else:connection.execute('DELETE FROM identity_groups WHERE tenant_id=%s AND id=%s',(self.tenant,identifier))
                details={'target_name':row[0] if operation=='delete' else name}
                if operation=='rename':details['previous_name']=row[0]
                self.identities.audit(connection,actor=actor,source='admin-identities',action='identity-group.'+operation,
                                      target=str(identifier),result='success',security_context=details)
        return dict(status='committed',id=str(identifier))
