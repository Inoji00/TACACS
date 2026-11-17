"""Tenant-scoped dashboard facts. No host metrics or daemon health are inferred."""
from importlib.metadata import version
from uuid import UUID

from .aaa_events import safe_attempted_username


def read_failed_auth(connection, tenant):
    rows = connection.execute("""
        WITH failed AS (
            SELECT target, occurred_at,
                   CASE WHEN jsonb_typeof(security_context->'attempted_username')='string'
                        AND length(security_context->>'attempted_username') BETWEEN 1 AND 253
                        THEN security_context->>'attempted_username' END AS username
            FROM audit_events
            WHERE tenant_id=%s AND source='tacacs' AND action='aaa.authentication'
              AND result='fail' AND occurred_at BETWEEN now()-interval '24 hours' AND now()
        ), summary AS (
            SELECT count(*) AS total, count(DISTINCT username) AS users,
                   count(DISTINCT target) AS source_ips FROM failed
        ), ranked AS (
            SELECT left(target,64) AS device, count(*) AS failures, max(occurred_at) AS last_at, username
            FROM failed GROUP BY target,username
            ORDER BY failures DESC,device,username LIMIT 5
        )
        SELECT device, failures, last_at, username, total, users, source_ips
        FROM summary LEFT JOIN ranked ON TRUE
        ORDER BY failures DESC NULLS LAST,device,username
        """, (tenant,)).fetchall()
    total, users, source_ips = rows[0][4:]
    summary = dict(total=total, users=users, source_ips=source_ips)
    failures = [dict(device=device, count=count, last_at=last_at.isoformat(),
                     username=safe_attempted_username(username))
                for device,count,last_at,username,*_ in rows if count is not None]
    return failures, summary


class AdminDashboard:
    def __init__(self,pool,tenant):
        self.pool,self.tenant=pool,UUID(tenant)

    def read(self,actor):
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                allowed=connection.execute("SELECT 1 FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
                    "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission='audit.read' AND u.enabled AND NOT u.locked",
                    (self.tenant,UUID(actor))).fetchone()
                if allowed is None:raise PermissionError('audit permission required')
                now=connection.execute('SELECT now()').fetchone()[0]
                users=connection.execute('SELECT count(*),count(*) FILTER (WHERE enabled AND NOT locked),count(*) FILTER (WHERE locked) FROM users WHERE tenant_id=%s AND NOT deleted',(self.tenant,)).fetchone()
                groups=connection.execute('SELECT count(*) FROM identity_groups WHERE tenant_id=%s',(self.tenant,)).fetchone()[0]
                devices=connection.execute('SELECT count(*),count(*) FILTER (WHERE d.enabled),count(*) FILTER (WHERE o.revision IS DISTINCT FROM d.revision) '
                    'FROM network_devices d LEFT JOIN device_runtime_observations o ON o.tenant_id=d.tenant_id AND o.address=d.address WHERE d.tenant_id=%s AND NOT d.deleted',(self.tenant,)).fetchone()
                policies=connection.execute('SELECT state,count(*) FROM policy_versions WHERE tenant_id=%s AND NOT EXISTS (SELECT 1 FROM policy_retirements r WHERE r.version_id=policy_versions.id AND r.tenant_id=policy_versions.tenant_id) GROUP BY state',(self.tenant,)).fetchall()
                activity=connection.execute("SELECT date_trunc('hour',occurred_at AT TIME ZONE 'UTC'),action,result,count(*) FROM audit_events "
                    "WHERE tenant_id=%s AND source='tacacs' AND occurred_at>=(date_trunc('hour',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')-interval '23 hours' AND occurred_at<=now() "
                    "AND action IN ('aaa.authentication','aaa.authorization','aaa.accounting') GROUP BY 1,2,3 ORDER BY 1",(self.tenant,)).fetchall()
                daily_auth=connection.execute(
                    "SELECT (occurred_at AT TIME ZONE 'Asia/Ho_Chi_Minh')::date,"
                    " count(*) FILTER (WHERE result='pass'), count(*) FILTER (WHERE result='fail') "
                    "FROM audit_events WHERE tenant_id=%s AND source='tacacs' "
                    "AND action='aaa.authentication' AND result IN ('pass','fail') "
                    "AND occurred_at >= ((date_trunc('day',now() AT TIME ZONE 'Asia/Ho_Chi_Minh') "
                    "- interval '6 days') AT TIME ZONE 'Asia/Ho_Chi_Minh') AND occurred_at<=now() "
                    "GROUP BY 1 ORDER BY 1",(self.tenant,)).fetchall()
                failures, failure_summary = read_failed_auth(connection, self.tenant)
                recent=connection.execute("SELECT occurred_at,left(action,128),left(target,128),left(result,64) FROM audit_events "
                    "WHERE tenant_id=%s AND source<>'tacacs' ORDER BY chain_sequence DESC LIMIT 6",(self.tenant,)).fetchall()
                hourly=connection.execute(
                    "SELECT date_trunc('hour',occurred_at AT TIME ZONE 'UTC'), "
                    "count(*) FILTER (WHERE action='aaa.authentication' AND result IN ('pass','fail')), "
                    "count(*) FILTER (WHERE action='aaa.authentication' AND result='fail'), count(DISTINCT target), "
                    "count(*) FILTER (WHERE action='aaa.authorization' AND result='allow' AND security_context->>'authorization_kind'='command') "
                    "FROM audit_events WHERE tenant_id=%s AND source='tacacs' AND occurred_at BETWEEN now()-interval '24 hours' AND now() "
                    "GROUP BY GROUPING SETS ((date_trunc('hour',occurred_at AT TIME ZONE 'UTC')),()) ORDER BY 1 NULLS LAST",(self.tenant,)).fetchall()
                rankings=connection.execute(
                    "SELECT left(target,64),count(*) FROM audit_events WHERE tenant_id=%s AND source='tacacs' "
                    "AND result IN ('fail','deny') AND action IN ('aaa.authentication','aaa.authorization') "
                    "AND occurred_at BETWEEN now()-interval '24 hours' AND now() GROUP BY target ORDER BY count(*) DESC,target LIMIT 6",(self.tenant,)).fetchall()
                active_users=connection.execute(
                    "SELECT left(security_context->>'attempted_username',253),count(*) FROM audit_events WHERE tenant_id=%s "
                    "AND source='tacacs' AND action='aaa.authentication' AND result='pass' "
                    "AND occurred_at BETWEEN now()-interval '24 hours' AND now() "
                    "AND jsonb_typeof(security_context->'attempted_username')='string' GROUP BY 1 ORDER BY 2 DESC,1 LIMIT 6",
                    (self.tenant,)).fetchall()
                latest=connection.execute(
                    "SELECT occurred_at,left(target,64),result,action,CASE WHEN jsonb_typeof(security_context->'attempted_username')='string' "
                    "THEN left(security_context->>'attempted_username',253) END "
                    "FROM audit_events WHERE tenant_id=%s AND source='tacacs' AND result IN ('pass','fail','allow','deny','error','committed') "
                    "ORDER BY chain_sequence DESC LIMIT 12",(self.tenant,)).fetchall()
        totals=next((list(row[1:]) for row in hourly if row[0] is None),[0]*4)
        return dict(observed_at=now.isoformat(),window='24-hour-buckets',version=version('local-tacacs-appliance'),
            inventory=dict(users=users[0],usable_users=users[1],locked_users=users[2],groups=groups,devices=devices[0],enabled_devices=devices[1],pending_devices=devices[2]),
            policies=dict(policies),activity=[dict(hour=r[0].isoformat()+'Z',action=r[1],result=r[2],count=r[3]) for r in activity],
            daily_auth=[dict(day=r[0].isoformat(),passed=r[1],failed=r[2]) for r in daily_auth],
            failures=failures,failure_summary=failure_summary,
            recent=[dict(timestamp=r[0].isoformat(),action=r[1],target=r[2],result=r[3]) for r in recent],
            totals=totals,hourly=[dict(hour=r[0].isoformat()+'Z',values=list(r[1:])) for r in hourly if r[0] is not None],
            denied_devices=[dict(label=device,count=count) for device,count in rankings],
            active_users=[dict(label=name,count=count) for username,count in active_users if (name:=safe_attempted_username(username))],
            latest=[dict(timestamp=r[0].isoformat(),device=r[1],result=r[2],action=r[3],
                         username=safe_attempted_username(r[4]) if r[3]=='aaa.authentication' else None) for r in latest])
