"""Private alert configuration shared by Web Admin and the host monitor."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from uuid import uuid4

ACTIVITY_EVENTS = ('successful_logins', 'command_accounting', 'web_activity', 'aaa_activity')
EVENTS = ('services', 'resources', 'locked_accounts', 'authentication_failures') + ACTIVITY_EVENTS
DEFAULTS = dict(enabled=False, name='TNAC+', events=list(EVENTS[:4]), cpu_percent=90,
                memory_percent=90, disk_percent=85, resource_seconds=300,
                failure_threshold=10, repeat_seconds=1800)


def validate_webhook(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9_-]{16,128}', value):
        raise ValueError('invalid Slack webhook')
    return value


class AlertStorage:
    def __init__(self, directory=Path('/run/tnac-alerts')):
        self.directory = Path(directory)

    @contextmanager
    def locked(self):
        import fcntl
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise ValueError('alert storage unavailable')
        descriptor = os.open(self.directory / 'alerts.lock',
                             os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if hasattr(os, 'geteuid') and os.geteuid() == 0:
                os.fchown(descriptor, 10001, 10001)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def read_file(self, name, default):
        path = self.directory / name
        if not path.exists():
            return default
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('regular alert file required')
            content = stream.read(262145)
        if len(content) > 262144:
            raise ValueError('alert storage too large')
        return json.loads(content)

    def write_file(self, name, value):
        content = json.dumps(value, ensure_ascii=True).encode('utf-8')
        if len(content) > 262144:
            raise ValueError('alert storage too large')
        descriptor, temporary = tempfile.mkstemp(dir=self.directory, prefix='.alerts-')
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            if hasattr(os, 'geteuid') and os.geteuid() == 0:
                os.chown(temporary, 10001, 10001)
            os.replace(temporary, self.directory / name)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def public(self):
        with self.locked():
            config = self.read_file('settings.json', dict(DEFAULTS))
            state = self.read_file('state.json', {})
            result = {key: config.get(key, value) for key, value in DEFAULTS.items()}
            result.update(webhook_configured=bool(config.get('webhook_url')),
                          last_checked=state.get('last_checked'),
                          last_activity_check=state.get('last_activity_check'),
                          activity_available=state.get('activity_available'),
                          last_success=state.get('last_success'),
                          last_error=state.get('last_error'),
                          facts_available=state.get('facts_available'),
                          activity_backlog=state.get('activity_backlog', False),
                          pending=len(state.get('pending', [])))
            return result

    def save(self, values):
        if not isinstance(values, dict) or set(values) - (set(DEFAULTS) | {'webhook_url'}):
            raise ValueError('invalid alert fields')
        if set(DEFAULTS) - set(values) or type(values['enabled']) is not bool:
            raise ValueError('complete alert settings required')
        name = values['name']
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64 or any(ord(c) < 32 for c in name):
            raise ValueError('invalid installation name')
        events = values['events']
        if (not isinstance(events, list) or len(events) > len(EVENTS)
                or any(event not in EVENTS for event in events) or len(set(events)) != len(events)):
            raise ValueError('invalid alert events')
        for key, low, high in (
            ('cpu_percent', 1, 100), ('memory_percent', 1, 100), ('disk_percent', 1, 100),
            ('resource_seconds', 60, 3600), ('failure_threshold', 1, 1000), ('repeat_seconds', 300, 86400),
        ):
            if type(values[key]) is not int or not low <= values[key] <= high:
                raise ValueError('invalid alert threshold')
        with self.locked():
            previous = self.read_file('settings.json', {})
            webhook = values.get('webhook_url', '')
            if not isinstance(webhook, str):
                raise ValueError('invalid Slack webhook')
            if webhook:
                validate_webhook(webhook)
            else:
                webhook = previous.get('webhook_url', '')
            if values['enabled'] and not webhook:
                raise ValueError('Slack webhook required')
            updated = {key: values[key] for key in DEFAULTS}
            updated.update(name=name.strip(), webhook_url=webhook, revision=uuid4().hex)
            self.write_file('settings.json', updated)
        return self.public()

    def request_test(self):
        with self.locked():
            config = self.read_file('settings.json', {})
            validate_webhook(config.get('webhook_url', ''))
            now = time.time()
            if now - config.get('test_requested_at', 0) < 60:
                raise ValueError('wait before requesting another test')
            config.update(test_id=uuid4().hex, test_requested_at=now)
            self.write_file('settings.json', config)
        return {'status': 'queued'}
