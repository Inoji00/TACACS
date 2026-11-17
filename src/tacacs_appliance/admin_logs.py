"""Bounded, read-only reporting over persisted audit metadata; no raw context."""
from datetime import datetime, timedelta, timezone
import ipaddress
import re
from uuid import UUID
from .aaa_events import safe_attempted_username, safe_authorization_details
from .web_audit_network import audit_ip


KINDS = ('all', 'aaa', 'activity', 'issues')
ACTOR_NAME_SQL = "(SELECT left(u.username,253) FROM users u WHERE u.tenant_id=a.tenant_id AND u.id::text=a.actor)"
WEB_ACCESS_SQL = "a.source='admin-web' AND a.action IN ('web.login','web.logout')"
WEB_SOURCE_IP_SQL = f"CASE WHEN ({WEB_ACCESS_SQL}) THEN left(a.security_context->>'source_ip',46) END"
WEB_DESTINATION_IP_SQL = f"CASE WHEN ({WEB_ACCESS_SQL}) THEN left(a.security_context->>'destination_ip',46) END"
AAA_ACCESS_SQL = "a.source='tacacs' AND a.action IN ('aaa.authentication','aaa.authorization')"
AAA_REMOTE_IP_SQL = f"CASE WHEN ({AAA_ACCESS_SQL}) THEN left(a.security_context->>'remote_address',46) END"
ATTEMPTED_USERNAME_SQL = f"CASE WHEN (({WEB_ACCESS_SQL}) OR ({AAA_ACCESS_SQL})) AND jsonb_typeof(a.security_context->'attempted_username')='string' THEN left(a.security_context->>'attempted_username',253) END"
IDENTITY_TARGET = """a.source='admin-identities' AND a.action IN
    ('identity.create','identity.update','identity.enable','identity.disable','identity.delete',
     'identity.console.scope','identity.console.grant','identity.console.revoke')"""
ADMIN_TARGET = f"""(({IDENTITY_TARGET})
    OR (a.source='admin-identities' AND a.action IN ('identity-group.create','identity-group.rename','identity-group.delete'))
    OR (a.source='admin-device-groups' AND a.action IN ('device-group.create','device-group.update','device-group.delete'))
    OR (a.source='admin-devices' AND a.action IN ('device.create','device.update','device.delete')))"""
AAA_TARGET = "a.source='tacacs' AND a.action IN ('aaa.authentication','aaa.authorization','aaa.accounting')"
TARGET_NAME_SQL = f"""CASE WHEN ({ADMIN_TARGET} OR ({AAA_TARGET})) THEN COALESCE(
    CASE WHEN jsonb_typeof(a.security_context->'target_name')='string'
         THEN left(a.security_context->>'target_name',64) END,
    CASE WHEN {IDENTITY_TARGET} THEN (SELECT left(u.username,64) FROM users u WHERE u.tenant_id=a.tenant_id AND u.id=
      CASE WHEN a.target ~ '^[0-9a-f]{{8}}(-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}$'
           THEN a.target::uuid END) END) END"""
IDENTITY_FIELDS = ('target_name','previous_name','identity_group','enabled','password_changed',
                   'web_access','location_id','device_type_id','actions','changed_fields')
IDENTITY_DETAILS_SQL = f"""CASE WHEN {ADMIN_TARGET} THEN jsonb_build_object(
    {', '.join(f"'{key}', a.security_context->'{key}'" for key in IDENTITY_FIELDS)}) END"""

AUTHORIZATION_DETAILS_SQL = """CASE WHEN a.source='tacacs' AND a.action='aaa.authorization' THEN
    jsonb_build_object('authorization_kind',a.security_context->'authorization_kind',
                       'reason',a.security_context->'reason','matched_rule_id',a.security_context->'matched_rule_id') END"""


def identity_details(value):
    if not isinstance(value,dict):
        return {}
    details={}
    for key in ('target_name','previous_name','identity_group'):
        item=value.get(key)
        if isinstance(item,str) and re.fullmatch(r'[A-Za-z0-9_.@ -]{1,64}',item):
            details[key]=item
    for key in ('enabled','password_changed','web_access'):
        if type(value.get(key)) is bool:
            details[key]=value[key]
    for key in ('location_id','device_type_id'):
        item=value.get(key)
        if isinstance(item,str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',item):
            details[key]=item
    actions=value.get('actions')
    if isinstance(actions,list):
        from .device_console_scope import ACTIONS
        details['actions']=[item for item in actions if isinstance(item,str) and item in ACTIONS][:16]
    fields=value.get('changed_fields')
    if isinstance(fields,list):
        allowed_fields=('name','description','enabled','location','device_type','access_mappings','shared_secret','parent')
        details['changed_fields']=[item for item in fields if isinstance(item,str) and item in allowed_fields][:8]
    return details


def log_filters(*, kind='all', search='', action='', result='', device='', session='',
                actor='', since='', until='', before=None, limit=50):
    if kind not in KINDS or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('invalid log query')
    for value in (search, action, result, device, session, actor):
        if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('invalid log filter')
    if before is not None:
        if isinstance(before, str) and before.isascii() and before.isdecimal() and len(before) <= 19:
            before = int(before)
        if type(before) is not int or not 1 <= before <= 9223372036854775807:
            raise ValueError('invalid cursor')
    now = datetime.now(timezone.utc)
    def timestamp(value, default):
        if not value:
            return default
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError('invalid time')
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('timezone required')
        return stamp.astimezone(timezone.utc)
    end = timestamp(until, now)
    start = timestamp(since, end - timedelta(days=1))
    if start >= end or end - start > timedelta(days=31):
        raise ValueError('time range must be at most 31 days')
    clauses = ['a.tenant_id=%s', 'a.occurred_at>=%s', 'a.occurred_at<=%s']
    values = [start, end]
    if kind == 'aaa':
        clauses.append("a.source='tacacs'")
    elif kind == 'activity':
        clauses.append("a.source<>'tacacs' AND a.action NOT LIKE 'accounting.%%'")
    elif kind == 'issues':
        clauses.append("a.result IN ('error','fail','deny','no-reply','unclassified','unknown')")
    if device:
        device = str(ipaddress.IPv4Address(device))
        clauses.append(f"((a.source<>'admin-web' AND a.target=%s) OR ({WEB_SOURCE_IP_SQL})=%s)")
        values.extend((device,device))
    for column, value in (('action', action), ('result', result), ('session_id', session), ('actor', actor)):
        if value:
            clauses.append('a.' + column + '=%s'); values.append(value)
    if search:
        # Position matches literally: percent/underscore are not SQL wildcards.
        clauses.append("position(lower(%s) in lower(concat_ws(' ',a.actor,a.source,a.action,a.target,a.result,a.session_id,"+ACTOR_NAME_SQL+","+ATTEMPTED_USERNAME_SQL+","+TARGET_NAME_SQL+","+WEB_SOURCE_IP_SQL+","+WEB_DESTINATION_IP_SQL+","+AAA_REMOTE_IP_SQL+")))>0")
        values.append(search)
    return ' AND '.join(clauses), values, start, end, before, limit


class AdminLogs:
    def __init__(self, pool, tenant):
        self.pool, self.tenant = pool, UUID(tenant)

    def read(self, principal, *, report=False, **filters):
        where, values, start, end, before, limit = log_filters(**filters)
        values = [self.tenant, *values]
        if report and before is not None:
            raise ValueError('report cursor not supported')
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                connection.execute("SET LOCAL statement_timeout='3000ms'")
                allowed = connection.execute("SELECT 1 FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
                    "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission='audit.read' AND u.enabled AND NOT u.locked",
                    (self.tenant, UUID(principal))).fetchone()
                if allowed is None:
                    raise PermissionError('permission denied')
                window = dict(since=start.isoformat(), until=end.isoformat())
                if report:
                    totals = connection.execute('SELECT count(*),count(*) FILTER (WHERE a.source=\'tacacs\'),'
                        "count(*) FILTER (WHERE a.result IN ('fail','deny','error','no-reply','unclassified','unknown')) "
                        'FROM audit_events a WHERE ' + where, tuple(values)).fetchone()
                    rows = connection.execute('SELECT left(a.action,128),left(a.result,64),count(*) FROM audit_events a WHERE '
                        + where + ' GROUP BY 1,2 ORDER BY 3 DESC,1,2 LIMIT 201', tuple(values)).fetchall()
                    devices = connection.execute("SELECT left(a.target,64),count(*),max(a.occurred_at) FROM audit_events a WHERE "
                        + where + " AND a.source='tacacs' GROUP BY a.target ORDER BY 2 DESC,1 LIMIT 10", tuple(values)).fetchall()
                    return dict(window=window, total=totals[0], aaa_events=totals[1], issues=totals[2],
                        breakdown=[dict(action=r[0], result=r[1], count=r[2]) for r in rows[:200]],
                        breakdown_truncated=len(rows)>200,
                        devices=[dict(device=r[0], count=r[1], last_at=r[2].isoformat()) for r in devices],
                        scope='persisted-audit-metadata')
                if before is not None:
                    where += ' AND a.chain_sequence<%s'; values.append(before)
                rows = connection.execute('SELECT a.id,a.chain_sequence,a.occurred_at,left(a.actor,256),left(a.source,256),'
                    'left(a.action,256),left(a.target,256),left(a.result,256),left(a.session_id,256),a.policy_version,'
                    +ACTOR_NAME_SQL+","+ATTEMPTED_USERNAME_SQL+','+TARGET_NAME_SQL+','+IDENTITY_DETAILS_SQL+','+AUTHORIZATION_DETAILS_SQL+','+WEB_SOURCE_IP_SQL+','+WEB_DESTINATION_IP_SQL+','+AAA_REMOTE_IP_SQL+' '
                    'FROM audit_events a WHERE ' + where + ' ORDER BY a.chain_sequence DESC LIMIT %s', tuple([*values, limit+1])).fetchall()
        names = ('event_id','sequence','timestamp','actor','source','action','target','result','session','policy_version','actor_name','attempted_username','target_name','target_name_source','identity_details')
        items = []
        for r in rows[:limit]:
            details=identity_details(r[13])
            name=details.pop('target_name',None)
            current=r[12]
            if r[4]=='tacacs' and isinstance(current,str) and re.fullmatch(r'[A-Za-z0-9_. -]{1,64}',current):
                name,current=current,None
            item=dict(zip(names,(str(r[0]),r[1],r[2].isoformat(),*r[3:9],
                str(r[9]) if r[9] else None,r[10],safe_attempted_username(r[11]),name or current,
                'event' if name else 'current' if current else None,details),strict=True))
            if len(r)>14 and (authorization:=safe_authorization_details(r[14])):
                item['authorization_details']=authorization
            if r[4]=='admin-web' and r[5] in ('web.login','web.logout'):
                for key,value in zip(('source_ip','destination_ip'),r[15:17]):
                    if address:=audit_ip(value):
                        item[key]=address
            if r[4]=='tacacs' and r[5] in ('aaa.authentication','aaa.authorization') and len(r)>17 and (address:=audit_ip(r[17])):
                item['remote_address']=address
            items.append(item)
        return dict(items=items, next_before=items[-1]['sequence'] if len(rows)>limit else None,
                    window=window, scope='persisted-audit-metadata')
