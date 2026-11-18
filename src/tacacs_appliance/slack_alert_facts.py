"""Read bounded alert facts using the existing restricted administrator role."""
import json
import sys
from pathlib import Path
import tomllib
from uuid import UUID

import psycopg
from .runtime import read_secret
from .alert_storage import ACTIVITY_EVENTS, EVENTS
from .slack_activity import read_activity


def main():
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError('alert control too large')
        control = json.loads(raw) if raw else {}
        after = control.get('after')
        events = control.get('events', [])
        if (set(control) - {'after', 'events'} or
                (after is not None and (type(after) is not int or after < 0 or after > 9223372036854775807))
                or not isinstance(events, list) or len(events) > len(EVENTS) or any(event not in EVENTS for event in events)):
            raise ValueError('invalid alert control')
        config = tomllib.loads(Path('/etc/tacacs/admin.toml').read_text(encoding='utf-8'))
        tenant = UUID(config['tenant_id'])
        dsn = read_secret(Path('/run/admin-secrets/admin_dsn')).decode('utf-8')
        with psycopg.connect(dsn, connect_timeout=3) as connection:
            with connection.transaction():
                connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                connection.execute("SET LOCAL statement_timeout='3000ms'")
                locked = connection.execute(
                    'SELECT id,username FROM users WHERE tenant_id=%s AND locked AND NOT deleted '
                    'ORDER BY id LIMIT 513', (tenant,)).fetchall() if 'locked_accounts' in events else []
                failures = connection.execute(
                    "SELECT count(*) FROM audit_events WHERE tenant_id=%s AND source='tacacs' "
                    "AND action='aaa.authentication' AND result='fail' "
                    "AND occurred_at BETWEEN now()-interval '5 minutes' AND now()", (tenant,)).fetchone()[0] if 'authentication_failures' in events else 0
                activity = read_activity(connection, tenant, after, events) if set(events) & set(ACTIVITY_EVENTS) else {}
        if len(locked) > 512:
            raise ValueError('account alert limit exceeded')
        print(json.dumps({'locked': {str(identifier): username for identifier, username in locked},
                          'failures': failures, **activity}))
        return 0
    except Exception:
        print('Alert facts unavailable.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
