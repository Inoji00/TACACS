"""Safe activity projection using committed audit sequence and exact accounting IDs."""
from uuid import UUID

from .accounting import accounting_details
from .aaa_events import safe_attempted_username
from .web_audit_network import audit_ip


def label(value, limit=100):
    if not isinstance(value, str):
        return 'unknown'
    return ''.join(c for c in value if c.isprintable() and c not in '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069')[:limit]


def project(row, records, events):
    sequence, occurred, actor, source, action, target, result, context, actor_name = row
    context = context if isinstance(context, dict) else {}
    user = safe_attempted_username(context.get('attempted_username')) or actor_name or actor
    text = None
    prefix = '#' + str(sequence) + ' '
    if source == 'tacacs' and action == 'aaa.authentication' and result == 'pass':
        if 'successful_logins' in events:
            remote = audit_ip(context.get('remote_address'))
            text = 'AUTHENTICATION PASS — ' + label(user, 253) + ' → ' + label(target)
            if remote:
                text += ' | Remote: ' + remote
    elif action in ('accounting.start', 'accounting.stop', 'accounting.watchdog'):
        record_id = context.get('accounting_record_id')
        record = records.get(record_id) if isinstance(record_id, str) else None
        if record is not None:
            username, device, arguments = record
            details = accounting_details(arguments)
            if details['kind'] in ('command', 'redacted') or details.get('redacted'):
                if 'command_accounting' in events:
                    command = 'Sensitive command hidden' if details.get('redacted') else details.get('command') or 'Command unavailable'
                    text = 'COMMAND ' + action.split('.')[1] + ' — ' + label(username, 253) + ' → ' + label(device) + ' | ' + label(command, 2048)
            elif 'aaa_activity' in events:
                text = 'ACCOUNTING ' + action.split('.')[1] + ' — ' + label(username) + ' → ' + label(device)
        elif 'aaa_activity' in events:
            text = action + ' — ' + label(actor) + ' → ' + label(target) + ' | Command details unavailable'
    elif source == 'tacacs':
        if 'aaa_activity' in events and action != 'aaa.accounting' and result not in ('challenge', 'restart'):
            text = action + ' ' + label(result) + ' — ' + label(user) + ' → ' + label(target)
            if remote := audit_ip(context.get('remote_address')):
                text += ' | Remote: ' + remote
    elif 'web_activity' in events and source.startswith('admin-'):
        # Do not forward arbitrary targets, raw contexts or request bodies.
        text = 'WEB ' + label(action) + ' ' + label(result) + ' — ' + label(user)
    return {'sequence': sequence, 'text': prefix + text if text else None, 'time': occurred.timestamp()}


def read_activity(connection, tenant, after, events):
    if after is None:
        latest = connection.execute('SELECT COALESCE(max(chain_sequence),0) FROM audit_events WHERE tenant_id=%s',
                                    (tenant,)).fetchone()[0]
        return {'activity': [], 'activity_cursor': latest, 'activity_more': False}
    rows = connection.execute(
        'SELECT a.chain_sequence,a.occurred_at,a.actor,a.source,a.action,a.target,a.result,'
        "jsonb_build_object('attempted_username',CASE WHEN jsonb_typeof(a.security_context->'attempted_username')='string' "
        "AND length(a.security_context->>'attempted_username')<=253 THEN a.security_context->>'attempted_username' END,"
        "'remote_address',left(a.security_context->>'remote_address',64),"
        "'accounting_record_id',CASE WHEN jsonb_typeof(a.security_context->'accounting_record_id')='string' "
        "AND length(a.security_context->>'accounting_record_id')=36 THEN a.security_context->>'accounting_record_id' END),u.username "
        'FROM audit_events a LEFT JOIN users u ON u.tenant_id=a.tenant_id AND u.id::text=a.actor '
        'WHERE a.tenant_id=%s AND a.chain_sequence>%s ORDER BY a.chain_sequence LIMIT 201', (tenant, after)).fetchall()
    selected = rows[:200]
    identifiers = []
    for row in selected:
        if isinstance(row[7], dict):
            try:
                identifiers.append(UUID(row[7].get('accounting_record_id', '')))
            except (ValueError, TypeError, AttributeError):
                pass
    records = {}
    if identifiers:
        stored = connection.execute(
            'SELECT id,username,device_id,arguments FROM accounting_records WHERE tenant_id=%s AND id=ANY(%s::uuid[])',
            (tenant, identifiers)).fetchall()
        records = {str(identifier): (username, device, arguments) for identifier, username, device, arguments in stored}
    return {'activity': [project(row, records, events) for row in selected],
            'activity_cursor': selected[-1][0] if selected else after, 'activity_more': len(rows) > 200}
