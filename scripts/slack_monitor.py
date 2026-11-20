"""Bounded Slack delivery from the Ubuntu host, independent of application health."""
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

import local_appliance as local
try:
    from alert_storage import ACTIVITY_EVENTS, AlertStorage, DEFAULTS, MATTERMOST_URL, validate_webhook
except ModuleNotFoundError:
    from tacacs_appliance.alert_storage import ACTIVITY_EVENTS, AlertStorage, DEFAULTS, MATTERMOST_URL, validate_webhook


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_slack(webhook, text):
    """Return a redacted result and retry delay, never the secret URL or response body."""
    validate_webhook(webhook)
    mattermost = MATTERMOST_URL.fullmatch(webhook)
    provider = 'Mattermost' if mattermost else 'Slack'
    handlers = [NoRedirect(), HTTPSHandler(context=ssl.create_default_context())]
    if mattermost:
        if mattermost['host'] != os.environ.get('TNAC_MATTERMOST_HOST'):
            return 'Mattermost host is not approved', 3600
        handlers.append(ProxyHandler({}))
        sanitized = text[:2900].translate(str.maketrans({'@': '＠', '<': '‹', '>': '›'}))
        payload = {'text': re.sub(r'([\\`*_{}\[\]()#+\-.!|~])', r'\\\1', sanitized)}
    else:
        payload = {'text': 'TNAC+ monitoring alert', 'blocks': [
            {'type': 'section', 'text': {'type': 'plain_text', 'text': text[:2900]}}]}
    body = json.dumps(payload).encode('utf-8')
    request = Request(webhook, data=body, headers={'Content-Type': 'application/json'}, method='POST')
    opener = build_opener(*handlers)
    try:
        with opener.open(request, timeout=5) as response:
            accepted = response.status == 200 and response.read(16).strip() == b'ok'
        return (None, 0) if accepted else (provider + ' response rejected', 300)
    except HTTPError as exc:
        if exc.code == 429:
            retry = (exc.headers or {}).get('Retry-After', '60')
            delay = min(3600, max(60, int(retry))) if retry.isascii() and retry.isdecimal() and len(retry) < 6 else 60
            return provider + ' rate limited', delay
        return provider + ' HTTP ' + str(exc.code), 300 if exc.code >= 500 else 3600
    except (URLError, OSError, ValueError):
        return provider + ' network or TLS failure', 120


FAST_EVENTS = set(ACTIVITY_EVENTS) | {'locked_accounts'}
AAA_RATE_LIMIT = 5
AAA_RATE_WINDOW = 60
AAA_RATE_KEYS = 512


def safe_name(value):
    return ''.join(character if ord(character) >= 32 else ' ' for character in str(value))[:100]


def evaluate(config, state, snapshot, facts, now, *, activity_only=False):
    """Update durable conditions without counting SSH sessions or exposing credentials."""
    pending = state.setdefault('pending', [])
    conditions = state.setdefault('conditions', {})

    def enqueue(key, text, occurred=None, *, batch=None):
        if any(event['key'] == key for event in pending):
            return True
        if len(pending) >= 100:
            state['last_error'] = 'Alert queue full'
            return False
        event = {'key': key, 'text': text, 'time': now if occurred is None else occurred, 'next_attempt': now, 'attempts': 0}
        if batch is not None:
            event['batch'] = batch
        if len(json.dumps([*pending, event])) > 65536:
            state['last_error'] = 'Alert queue full'
            return False
        pending.append(event)
        return True

    if config.get('test_id') and state.get('test_id') != config['test_id']:
        if enqueue('test:' + config['test_id'], '🧪 Webhook Test · Requested by an administrator'):
            state['test_id'] = config['test_id']
    if not config.get('enabled'):
        return

    if (facts is not None and 'locked_accounts' in config['events'] and
            'locked_accounts' in facts.get('checked_events', config['events'])):
        locked = facts['locked']
        previous = state.get('locked_accounts')
        accepted = True
        if previous is not None:
            for kind, changed, label in (
                ('locked', {key: value for key, value in locked.items() if key not in previous}, '🔒 Account Locked · '),
                ('unlocked', {key: value for key, value in previous.items() if key not in locked},
                 '🔓 Account No Longer Locked · '),
            ):
                if changed:
                    digest = hashlib.sha256(json.dumps(sorted(changed)).encode()).hexdigest()[:32]
                    names = ', '.join(safe_name(name) for name in list(changed.values())[:5])
                    suffix = ' (' + str(len(changed)) + ' accounts)' if len(changed) > 1 else ''
                    accepted = enqueue(kind + ':' + digest, label + names + suffix) and accepted
        if accepted:
            state['locked_accounts'] = {identifier: safe_name(name)[:32] for identifier, name in locked.items()}

    if facts is not None and 'activity' in facts:
        recent = {}
        for key, times in state.get('aaa_rate', {}).items():
            active = [stamp for stamp in times if stamp > now - AAA_RATE_WINDOW]
            if active:
                recent[key] = active
        state['aaa_rate'] = recent
        state['activity_backlog'] = facts.get('activity_more', False)
        if 'event_cursor' not in state:
            state['event_cursor'] = facts['activity_cursor']
        else:
            batch = state['event_cursor']
            for event in facts['activity']:
                if event['sequence'] <= state['event_cursor']:
                    continue
                rate_key = event.get('aaa_rate_key')
                if rate_key and (len(recent.get(rate_key, ())) >= AAA_RATE_LIMIT
                                 or (rate_key not in recent and len(recent) >= AAA_RATE_KEYS)):
                    state['event_cursor'] = event['sequence']
                    continue
                group = event.get('group')
                if event['text'] and not enqueue('activity:' + str(event['sequence']), event['text'], event['time'],
                                                 batch=f'{batch}:{json.dumps(group)}' if group else None):
                    state['activity_backlog'] = True
                    break
                if event['text'] and rate_key:
                    recent.setdefault(rate_key, []).append(now)
                state['event_cursor'] = event['sequence']

    if activity_only:
        return

    observations = {'monitor.snapshot': (bool(snapshot.get('snapshot_error')), 'Host Monitoring · Snapshot', 0)}
    if not snapshot.get('snapshot_error'):
        if 'services' in config['events']:
            service_names = {'app': 'TACACS+', 'admin': 'Web Admin', 'proxy': 'HTTPS Proxy', 'postgres': 'PostgreSQL'}
            for service, status in snapshot.get('services', {}).items():
                if service in service_names:
                    observations['service.' + service] = (
                        status not in ('healthy', 'running'), f'Service · {service_names[service]} · {safe_name(status)}', 0)
            for key, label in (('tcp_probe', 'TACACS+ TCP/49'), ('https_probe', 'Web HTTPS')):
                if type(snapshot.get(key)) is bool:
                    observations[key] = (not snapshot[key], 'Readiness · ' + label, 0)
        if 'resources' in config['events']:
            names = {'cpu_percent': 'CPU', 'memory_percent': 'Memory', 'disk_percent': 'Disk'}
            for key, value in snapshot.get('system', {}).items():
                if key in names and type(value) in (int, float) and math.isfinite(value):
                    limit = config[key]
                    observations[key] = (value >= limit, f'{names[key]} · {value:.1f}% · Threshold: {limit}%',
                                         config['resource_seconds'])
    if facts is not None:
        state['facts_available'] = True
        if 'authentication_failures' in config['events']:
            count = facts['failures']
            observations['authentication_failures'] = (
                count >= config['failure_threshold'], f'TACACS+ Login Failures · {count} attempts in 5 min', 0)
    elif 'authentication_failures' in config['events']:
        state['facts_available'] = False

    for key, (bad, detail, duration) in observations.items():
        condition = conditions.setdefault(key, {'count': 0, 'active': False})
        if bad:
            if not condition['count'] or now - condition.get('checked', now) > 180:
                condition.update(since=now, count=0)
            condition['count'] += 1
            ready = condition['count'] >= 2 and now - condition['since'] >= duration
            repeat = now - condition.get('last_queued', 0) >= config['repeat_seconds']
            if ready and (not condition['active'] or repeat):
                kind = 'REMINDER' if condition['active'] else 'WARNING'
                if enqueue(key + ':open', ('🔔 ' if kind == 'REMINDER' else '⚠️ ') + kind.title() + ' · ' + detail):
                    condition.update(active=True, last_queued=now)
        else:
            if condition['active'] and enqueue(key + ':recovered', '🟢 Recovered · ' + detail):
                condition['active'] = False
            condition['count'] = 0
        condition['checked'] = now


def process(storage, snapshot, facts=None, *, now=None, sender=send_slack, activity_only=False):
    now = time.time() if now is None else now
    with storage.locked():
        config = storage.read_file('settings.json', dict(DEFAULTS))
        if not config.get('webhook_url'):
            return
        validate_webhook(config['webhook_url'])
        state = storage.read_file('state.json', {})
        if state.get('revision') != config.get('revision'):
            state = {'revision': config.get('revision')}
        if facts is not None and facts.get('config_revision', config.get('revision')) != config.get('revision'):
            facts = None
        check_key = 'last_activity_check' if activity_only else 'last_checked'
        state[check_key] = datetime.fromtimestamp(now, timezone.utc).isoformat()
        if activity_only:
            state['activity_available'] = facts is not None
        evaluate(config, state, snapshot, facts, now, activity_only=activity_only)
        lines = []
        selected = []
        for event in sorted(state.get('pending', []), key=lambda item: item['key'].startswith('activity:')):
            if now < state.get('delivery_not_before', 0):
                break
            if event['next_attempt'] > now:
                continue
            text = event['text']
            if len(text) > 2700:
                text = text[:2670] + ' [truncated]'
            if selected:
                if selected[0].get('batch') is None:
                    break
                if event.get('batch') != selected[0]['batch']:
                    continue
            if len('\n'.join([*lines, text])) > 2900 or len(selected) >= 8:
                break
            selected.append(event)
            lines.append(text)
        if selected:
            # Persist the queue before attempting delivery so a worker crash cannot lose events.
            storage.write_file('state.json', state)
            error, delay = sender(config['webhook_url'], '\n'.join(lines))
            if error is None:
                state['last_success'] = datetime.fromtimestamp(now, timezone.utc).isoformat()
                state['last_error'] = None
                state.pop('delivery_not_before', None)
                for event in selected:
                    state['pending'].remove(event)
            else:
                state['last_error'] = error
                for event in selected:
                    event['attempts'] += 1
                    event['next_attempt'] = now + max(delay, min(3600, 60 * 2 ** min(event['attempts'], 6)))
                state['delivery_not_before'] = max(event['next_attempt'] for event in selected)
        storage.write_file('state.json', state)


def collect_facts(project, events, after):
    try:
        identifier = subprocess.run(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.project=' + project,
                                     '--filter', 'label=com.docker.compose.service=admin',
                                     '--filter', 'label=com.docker.compose.oneoff=False'],
                                    check=True, capture_output=True, text=True, timeout=5).stdout.strip()
        if not re.fullmatch('[0-9a-f]{12,64}', identifier):
            return None
        result = subprocess.run(['docker', 'exec', '-i', identifier, 'python', '-m', 'tacacs_appliance.slack_alert_facts'],
                                input=json.dumps({'events': events, 'after': after}),
                                check=True, capture_output=True, text=True, timeout=10)
        facts = json.loads(result.stdout)
        if (not isinstance(facts.get('locked'), dict) or len(facts['locked']) > 512
                or type(facts.get('failures')) is not int or facts['failures'] < 0):
            return None
        facts['checked_events'] = events
        return facts
    except Exception:
        return None


def check_alerts(project, snapshot, directory, *, activity_only=False):
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError('invalid alert volume')
    storage = AlertStorage(directory)
    with storage.locked():
        config = storage.read_file('settings.json', dict(DEFAULTS))
        state = storage.read_file('state.json', {})
        cursor = state.get('event_cursor') if state.get('revision') == config.get('revision') else None
    events = [event for event in config.get('events', [])
              if (event in FAST_EVENTS) == activity_only]
    facts = collect_facts(project, events, cursor) if not snapshot.get('snapshot_error') and config.get('enabled') and set(events) & (
        {'locked_accounts', 'authentication_failures'} | set(ACTIVITY_EVENTS)) else None
    if facts is not None:
        facts['config_revision'] = config.get('revision')
    process(storage, snapshot, facts, activity_only=activity_only)
