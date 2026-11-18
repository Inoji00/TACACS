"""Bounded Slack delivery from the Ubuntu host, independent of application health."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import ssl
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import local_appliance as local
try:
    from alert_storage import ACTIVITY_EVENTS, AlertStorage, DEFAULTS, validate_webhook
except ModuleNotFoundError:
    from tacacs_appliance.alert_storage import ACTIVITY_EVENTS, AlertStorage, DEFAULTS, validate_webhook


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_slack(webhook, text):
    """Return a redacted result and retry delay, never the secret URL or response body."""
    validate_webhook(webhook)
    body = json.dumps({'text': 'TNAC+ monitoring alert', 'blocks': [
        {'type': 'section', 'text': {'type': 'plain_text', 'text': text[:2900]}}]}).encode('utf-8')
    request = Request(webhook, data=body, headers={'Content-Type': 'application/json'}, method='POST')
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=5) as response:
            accepted = response.status == 200 and response.read(16).strip() == b'ok'
        return (None, 0) if accepted else ('Slack response rejected', 300)
    except HTTPError as exc:
        if exc.code == 429:
            retry = (exc.headers or {}).get('Retry-After', '60')
            delay = min(3600, max(60, int(retry))) if retry.isascii() and retry.isdecimal() and len(retry) < 6 else 60
            return 'Slack rate limited', delay
        return 'Slack HTTP ' + str(exc.code), 300 if exc.code >= 500 else 3600
    except (URLError, OSError, ValueError):
        return 'Slack network or TLS failure', 120


FAST_EVENTS = set(ACTIVITY_EVENTS) | {'locked_accounts'}


def safe_name(value):
    return ''.join(character if ord(character) >= 32 else ' ' for character in str(value))[:100]


def evaluate(config, state, snapshot, facts, now, *, activity_only=False):
    """Update durable conditions without counting SSH sessions or exposing credentials."""
    pending = state.setdefault('pending', [])
    conditions = state.setdefault('conditions', {})

    def enqueue(key, text, occurred=None):
        if any(event['key'] == key for event in pending):
            return True
        if len(pending) >= 100:
            state['last_error'] = 'Alert queue full'
            return False
        event = {'key': key, 'text': text, 'time': now if occurred is None else occurred, 'next_attempt': now, 'attempts': 0}
        if len(json.dumps([*pending, event])) > 65536:
            state['last_error'] = 'Alert queue full'
            return False
        pending.append(event)
        return True

    if config.get('test_id') and state.get('test_id') != config['test_id']:
        if enqueue('test:' + config['test_id'], 'TEST — Slack connection test requested by a TNAC+ administrator.'):
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
                ('locked', {key: value for key, value in locked.items() if key not in previous}, 'WARNING — Account locked: '),
                ('unlocked', {key: value for key, value in previous.items() if key not in locked},
                 'RECOVERED — Account is no longer locked or was removed: '),
            ):
                if changed:
                    digest = hashlib.sha256(json.dumps(sorted(changed)).encode()).hexdigest()[:32]
                    names = ', '.join(safe_name(name) for name in list(changed.values())[:5])
                    suffix = ' (' + str(len(changed)) + ' accounts)' if len(changed) > 1 else ''
                    accepted = enqueue(kind + ':' + digest, label + names + suffix) and accepted
        if accepted:
            state['locked_accounts'] = {identifier: safe_name(name)[:32] for identifier, name in locked.items()}

    if facts is not None and 'activity' in facts:
        state['activity_backlog'] = facts.get('activity_more', False)
        if 'event_cursor' not in state:
            state['event_cursor'] = facts['activity_cursor']
        else:
            for event in facts['activity']:
                if event['sequence'] <= state['event_cursor']:
                    continue
                if event['text'] and not enqueue('activity:' + str(event['sequence']), event['text'], event['time']):
                    state['activity_backlog'] = True
                    break
                state['event_cursor'] = event['sequence']

    if activity_only:
        return

    observations = {'monitor.snapshot': (bool(snapshot.get('snapshot_error')), 'Host monitoring snapshot failed', 0)}
    if not snapshot.get('snapshot_error'):
        if 'services' in config['events']:
            for service, status in snapshot.get('services', {}).items():
                if service in ('app', 'admin', 'proxy', 'postgres'):
                    observations['service.' + service] = (status not in ('healthy', 'running'), service + ' status: ' + safe_name(status), 0)
            for key, label in (('tcp_probe', 'TACACS+ TCP/49'), ('https_probe', 'Web HTTPS')):
                if type(snapshot.get(key)) is bool:
                    observations[key] = (not snapshot[key], label + ' readiness check', 0)
        if 'resources' in config['events']:
            for key, value in snapshot.get('system', {}).items():
                if key in ('cpu_percent', 'memory_percent', 'disk_percent') and type(value) in (int, float) and math.isfinite(value):
                    observations[key] = (value >= config[key], key + ': ' + str(round(value, 1)) + '%', config['resource_seconds'])
    if facts is not None:
        state['facts_available'] = True
        if 'authentication_failures' in config['events']:
            count = facts['failures']
            observations['authentication_failures'] = (
                count >= config['failure_threshold'], str(count) + ' failed TACACS+ authentications in the last 5 minutes', 0)
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
                if enqueue(key + ':open', kind + ' — ' + detail):
                    condition.update(active=True, last_queued=now)
        else:
            if condition['active'] and enqueue(key + ':recovered', 'RECOVERED — ' + detail):
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
        stamp = datetime.fromtimestamp(now, timezone(timedelta(hours=7))).isoformat(timespec='seconds')
        lines = [safe_name(config['name']), stamp]
        selected = []
        for event in sorted(state.get('pending', []), key=lambda item: item['key'].startswith('activity:')):
            if now < state.get('delivery_not_before', 0):
                break
            if event['next_attempt'] > now:
                continue
            occurred = datetime.fromtimestamp(event['time'], timezone.utc).isoformat(timespec='seconds')
            text = event['text']
            if len(text) > 2700:
                text = text[:2670] + ' [truncated]'
            line = text + ' [' + occurred + ']'
            if len('\n'.join([*lines, line])) > 2900 or len(selected) >= 8:
                break
            selected.append(event)
            lines.append(line)
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
