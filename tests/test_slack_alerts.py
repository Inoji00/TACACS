from contextlib import nullcontext
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from types import SimpleNamespace

from tacacs_appliance.alert_storage import AlertStorage, DEFAULTS, validate_webhook
from tacacs_appliance.admin_api import AdminApi, COOKIE_NAME
from slack_monitor import process, send_slack
from prepare_slack_alerts import prepare

WEBHOOK = 'https://hooks.slack.com/services/TEXAMPLE/BEXAMPLE/EXAMPLE_TOKEN_0123456789'
TOKEN = 'a' * 43


class MemoryStorage:
    def __init__(self, config):
        self.files = {'settings.json': config}
        self.history = []

    def locked(self):
        return nullcontext()

    def read_file(self, name, default):
        return copy.deepcopy(self.files.get(name, default))

    def write_file(self, name, value):
        self.files[name] = copy.deepcopy(value)
        self.history.append((name, copy.deepcopy(value)))


def configuration(**values):
    config = copy.deepcopy(DEFAULTS)
    config.update(enabled=True, webhook_url=WEBHOOK, revision='example')
    config.update(values)
    return config


class SlackMonitorTests(unittest.TestCase):
    def setUp(self):
        self.storage = MemoryStorage(configuration())
        self.sender = Mock(return_value=(None, 0))

    def cycle(self, now, snapshot=None, facts=None):
        process(self.storage, snapshot or {'services': {'app': 'healthy'}}, facts,
                now=now, sender=self.sender)

    def test_disabled_monitor_never_sends_automatic_alerts(self):
        self.storage.files['settings.json']['enabled'] = False
        self.cycle(1000, {'services': {'app': 'exited'}})
        self.cycle(1060, {'services': {'app': 'exited'}})
        self.sender.assert_not_called()

    def test_two_failures_then_recovery_and_no_repeat_spam(self):
        bad = {'services': {'app': 'exited'}}
        self.cycle(1000, bad)
        self.sender.assert_not_called()
        self.cycle(1060, bad)
        self.assertIn('Warning', self.sender.call_args.args[1])
        self.cycle(1120, bad)
        self.assertEqual(self.sender.call_count, 1)
        self.cycle(1180)
        self.assertIn('Recovered', self.sender.call_args.args[1])
        self.assertEqual(self.sender.call_count, 2)

    def test_reminder_requires_configured_interval(self):
        for now in range(1000, 2981, 60):
            self.cycle(now, {'services': {'app': 'exited'}})
        self.assertEqual(self.sender.call_count, 2)
        self.assertIn('Reminder', self.sender.call_args.args[1])

    def test_resource_threshold_requires_sustained_duration(self):
        for now in range(1000, 1300, 60):
            self.cycle(now, {'system': {'memory_percent': 95}})
        self.sender.assert_not_called()
        self.cycle(1300, {'system': {'memory_percent': 95}})
        self.assertEqual(self.sender.call_count, 1)

    def test_missing_metrics_do_not_report_false_recovery(self):
        self.cycle(1000, {'services': {'app': 'exited'}})
        self.cycle(1060, {'services': {'app': 'exited'}})
        self.cycle(1120, {'system': {}})
        self.assertEqual(self.sender.call_count, 1)

    def test_queue_is_durable_before_delivery_and_retry_is_bounded(self):
        self.sender.return_value = ('Slack rate limited', 300)
        self.cycle(1000, {'services': {'app': 'exited'}})
        self.cycle(1060, {'services': {'app': 'exited'}})
        state = self.storage.files['state.json']
        self.assertEqual(len(state['pending']), 1)
        self.assertEqual(state['pending'][0]['next_attempt'], 1360)
        self.cycle(1120, {'services': {'app': 'exited'}})
        self.assertEqual(self.sender.call_count, 1)
        self.sender.return_value = (None, 0)
        self.cycle(1360, {'services': {'app': 'exited'}})
        self.assertEqual(self.storage.files['state.json']['pending'], [])
        self.assertNotIn(WEBHOOK, json.dumps(self.storage.files['state.json']))

    def test_account_baseline_new_lock_and_unlock(self):
        self.cycle(1000, facts={'locked': {}, 'failures': 0})
        self.cycle(1060, facts={'locked': {'example': 'test-user'}, 'failures': 0})
        self.assertIn('Account Locked · test-user', self.sender.call_args.args[1])
        self.cycle(1120, facts={'locked': {'example': 'test-user'}, 'failures': 0})
        self.assertEqual(self.sender.call_count, 1)
        self.cycle(1180, facts={'locked': {}, 'failures': 0})
        self.assertIn('Account No Longer Locked', self.sender.call_args.args[1])

    def test_unavailable_account_facts_do_not_infer_unlock(self):
        self.cycle(1000, facts={'locked': {'example': 'test-user'}, 'failures': 0})
        self.cycle(1060, facts=None)
        self.sender.assert_not_called()
        self.assertFalse(self.storage.files['state.json']['facts_available'])

    def test_failure_burst_uses_persisted_failures_and_recovers(self):
        facts = {'locked': {}, 'failures': 10}
        self.cycle(1000, facts=facts)
        self.cycle(1060, facts=facts)
        self.assertIn('10 attempts in 5 min', self.sender.call_args.args[1])
        self.cycle(1120, facts={'locked': {}, 'failures': 0})
        self.assertIn('Recovered', self.sender.call_args.args[1])

    def test_test_alert_can_send_while_automatic_alerting_disabled(self):
        self.storage.files['settings.json'].update(enabled=False, test_id='example')
        self.cycle(1000)
        self.assertIn('Slack Test', self.sender.call_args.args[1])
        self.cycle(1060)
        self.assertEqual(self.sender.call_count, 1)

    def test_host_snapshot_failure_can_be_sent_without_database(self):
        self.cycle(1000, {'snapshot_error': True})
        self.cycle(1060, {'snapshot_error': True})
        self.assertIn('Host Monitoring · Snapshot', self.sender.call_args.args[1])


class SlackStorageTests(unittest.TestCase):
    def test_webhook_restricts_destination_and_rejects_redirect_targets(self):
        self.assertEqual(validate_webhook(WEBHOOK), WEBHOOK)
        for value in ('http://127.0.0.1/', WEBHOOK + '?x=1', WEBHOOK + '#x',
                      WEBHOOK.replace('hooks.slack.com', 'hooks.slack.com.attacker.test'), None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_webhook(value)

    def test_private_saved_settings_are_never_returned_by_public_api(self):
        with tempfile.TemporaryDirectory() as temporary:
            storage = AlertStorage(Path(temporary))
            with patch.object(storage, 'locked', return_value=nullcontext()), \
                 patch('tacacs_appliance.alert_storage.os.O_NOFOLLOW', 0, create=True):
                values = dict(DEFAULTS, enabled=True, webhook_url=WEBHOOK)
                storage.save(values)
                self.assertNotIn(WEBHOOK, json.dumps(storage.public()))
                self.assertTrue(storage.public()['webhook_configured'])
                values['webhook_url'] = ''
                storage.save(values)
                self.assertEqual(storage.read_file('settings.json', {})['webhook_url'], WEBHOOK)
                storage.request_test()
                with self.assertRaises(ValueError):
                    storage.request_test()

    def test_invalid_thresholds_and_missing_webhook_are_rejected(self):
        storage = AlertStorage()
        for values in (dict(DEFAULTS, cpu_percent=True), dict(DEFAULTS, repeat_seconds=1),
                       dict(DEFAULTS, events=['unknown']), dict(DEFAULTS, name='')):
            with self.subTest(values=values), self.assertRaises(ValueError):
                storage.save(values)

    def test_slack_rate_limit_response_is_redacted(self):
        opener = Mock()
        opener.open.side_effect = HTTPError(WEBHOOK, 429, 'secret', {'Retry-After': '300'}, None)
        with patch('slack_monitor.build_opener', return_value=opener):
            self.assertEqual(send_slack(WEBHOOK, 'example'), ('Slack rate limited', 300))


class SlackApiTests(unittest.TestCase):
    def setUp(self):
        self.alerts = Mock()
        self.alerts.public.return_value = {'enabled': False, 'webhook_configured': False}
        sessions = Mock()
        sessions.resolve.return_value = 'example-user'
        self.permissions = Mock(return_value=True)
        self.audit = Mock()
        self.app = AdminApi(sessions, self.permissions, b'k' * 32, 'https://admin.example.test',
                            alerts=self.alerts, web_audit=self.audit)

    def request(self, method='GET', path='/api/alerts', csrf=True):
        body = b'{}'
        environ = {'wsgi.url_scheme': 'https', 'REQUEST_METHOD': method, 'PATH_INFO': path,
                   'HTTP_COOKIE': COOKIE_NAME + '=' + TOKEN, 'CONTENT_TYPE': 'application/json',
                   'CONTENT_LENGTH': str(len(body)), 'wsgi.input': io.BytesIO(body),
                   'HTTP_ORIGIN': 'https://admin.example.test'}
        if csrf:
            environ['HTTP_X_CSRF_TOKEN'] = self.app.csrf_token(TOKEN)
        result = {}
        def start(status, headers):
            result['status'] = status
        result['body'] = json.loads(b''.join(self.app(environ, start)))
        return result

    def test_admin_permission_is_required_for_reads_and_writes(self):
        self.permissions.return_value = False
        self.assertEqual(self.request()['status'], '403 Forbidden')
        self.assertEqual(self.request('POST')['status'], '403 Forbidden')
        self.alerts.public.assert_not_called()
        self.alerts.save.assert_not_called()


    def test_test_request_requires_csrf_and_is_audited_without_secret(self):
        self.assertEqual(self.request('POST', '/api/alerts/test', csrf=False)['status'], '403 Forbidden')
        self.alerts.request_test.return_value = {'status': 'queued'}
        self.assertEqual(self.request('POST', '/api/alerts/test')['status'], '202 Accepted')
        self.assertEqual(self.audit.call_args.kwargs['security_context'], {})
        self.assertEqual(self.audit.call_args.kwargs['action'], 'slack.alerts.test')

    def test_audit_failure_prevents_configuration_mutation(self):
        self.audit.side_effect = RuntimeError('database unavailable')
        self.assertEqual(self.request('POST')['status'], '503 Service Unavailable')
        self.alerts.save.assert_not_called()


class SlackUpgradeTests(unittest.TestCase):
    def test_adds_only_admin_storage_and_preserves_existing_deployment(self):
        config = {'services': {'admin': {'image': 'tnac:current', 'volumes': ['config:/etc/tacacs:ro']},
                               'app': {'image': 'previous-aaa'}, 'postgres': {'image': 'previous-postgres'}},
                  'volumes': {'postgres-data': {}}}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / 'compose.json'
            path.write_text(json.dumps(config), encoding='utf-8')
            response = SimpleNamespace(stdout=json.dumps([{'Driver':'local','Scope':'local'}]))
            with patch('prepare_slack_alerts.local.state', return_value={'project': 'tnac-' + 'a' * 32}), \
                 patch('prepare_slack_alerts.local.run', return_value=response):
                prepare(directory)
                updated = json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual(updated['services']['app'], config['services']['app'])
                self.assertEqual(updated['services']['postgres'], config['services']['postgres'])
                self.assertEqual(updated['volumes']['postgres-data'], {})
                self.assertIn('alerts:/run/tnac-alerts', updated['services']['admin']['volumes'])
                self.assertTrue(updated['volumes']['alerts']['external'])
                prepare(directory)
                self.assertEqual(len(list(directory.glob('compose.json.before-slack-*'))), 1)

    def test_foreign_alert_volume_is_rejected_before_running_docker(self):
        config = {'services': {'admin': {'image':'tnac:current','volumes':[]}},
                  'volumes': {'alerts': {'name':'unrelated-volume','external':True}}}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / 'compose.json'
            original = json.dumps(config)
            path.write_text(original, encoding='utf-8')
            with patch('prepare_slack_alerts.local.state', return_value={'project':'tnac-' + 'a'*32}), \
                 patch('prepare_slack_alerts.local.run') as run:
                with self.assertRaises(ValueError):
                    prepare(directory)
                run.assert_not_called()
            self.assertEqual(path.read_text(encoding='utf-8'), original)

