from datetime import datetime, timezone
import json
import unittest
from unittest.mock import Mock
from uuid import UUID

from tacacs_appliance.slack_activity import project, read_activity
from tacacs_appliance.accounting import AccountingRecord
from tacacs_appliance.postgres_accounting import PostgresAccountingStore
from test_postgres_accounting import Pool, TENANT
from test_slack_alerts import MemoryStorage, configuration
from slack_monitor import process


def row(sequence=1, **changes):
    values = dict(sequence=sequence, occurred=datetime.now(timezone.utc), actor='device', source='tacacs',
                  action='aaa.authentication', target='192.0.2.10', result='pass',
                  context={'attempted_username':'example-user','remote_address':'192.0.2.20'}, actor_name=None)
    values.update(changes)
    return tuple(values.values())


class SlackActivityProjectionTests(unittest.TestCase):
    def test_success_is_opt_in_and_projects_only_safe_fields(self):
        event = row(context={'attempted_username':'example-user','remote_address':'192.0.2.20','password':'DO_NOT_SEND'})
        self.assertIsNone(project(event, {}, [])['text'])
        text = project(event, {}, ['successful_logins'])['text']
        self.assertIn('Switch Login Success', text)
        self.assertIn('example-user', text)
        self.assertIn('192.0.2.20', text)
        self.assertNotIn('DO_NOT_SEND', text)

    def test_only_subscribed_login_results_get_compact_format(self):
        denied = row(result='fail')
        self.assertIsNone(project(denied, {}, ['successful_logins'])['text'])
        self.assertEqual(project(denied, {}, ['aaa_activity'])['text'],
                         '❌ Switch Login Failed · User: example-user · Source: 192.0.2.20 · Switch: 192.0.2.10')
        web = row(source='admin-web', action='web.login', result='success', context={}, actor_name='admin')
        self.assertEqual(project(web, {}, ['web_activity'])['text'], '✅ Web Login Success · User: admin')

    def test_commands_use_exact_accounting_record_and_redaction(self):
        identifier = str(UUID(int=1))
        event = row(source='192.0.2.10', action='accounting.stop', result='committed',
                    context={'accounting_record_id':identifier})
        records = {identifier: ('example-user','192.0.2.10',['service=shell','cmd=show','cmd-arg=clock'])}
        text = project(event, records, ['command_accounting'])['text']
        self.assertIn('show clock', text)
        records[identifier] = ('example-user','192.0.2.10',['cmd=username','cmd-arg=example','cmd-arg=secret','cmd-arg=DO_NOT_SEND'])
        text = project(event, records, ['command_accounting'])['text']
        self.assertIn('Sensitive command hidden', text)
        self.assertNotIn('DO_NOT_SEND', text)

    def test_missing_or_invalid_record_reference_never_guesses_command(self):
        for context in ({}, {'accounting_record_id': []}, {'accounting_record_id': 'missing'}):
            with self.subTest(context=context):
                event = row(source='192.0.2.10', action='accounting.stop', context=context)
                self.assertIsNone(project(event, {}, ['command_accounting'])['text'])

    def test_web_actions_omit_targets_and_raw_context(self):
        event = row(source='admin-devices', action='device.update', target='DO_NOT_SEND',
                    actor='user-id', actor_name='example-admin', result='success', context={'secret':'DO_NOT_SEND'})
        text = project(event, {}, ['web_activity'])['text']
        self.assertIn('device.update', text)
        self.assertIn('example-admin', text)
        self.assertNotIn('DO_NOT_SEND', text)

    def test_aaa_decisions_and_session_events_have_separate_subscription(self):
        event = row(action='aaa.authorization',result='deny')
        self.assertIsNone(project(event, {}, ['successful_logins'])['text'])
        self.assertIn('Authorization Denied', project(event, {}, ['aaa_activity'])['text'])
        self.assertIsNone(project(row(result='challenge'), {}, ['aaa_activity'])['text'])

    def test_initial_cursor_starts_at_committed_sequence(self):
        connection=Mock()
        connection.execute.return_value.fetchone.return_value=(45,)
        result=read_activity(connection, UUID(TENANT), None, ['successful_logins'])
        self.assertEqual(result['activity_cursor'],45)
        self.assertEqual(result['activity'],[])
        self.assertEqual(connection.execute.call_args.args[1],(UUID(TENANT),))

    def test_query_is_tenant_scoped_and_references_use_uuid_batch(self):
        connection=Mock()
        identifier=UUID(int=8)
        event=row(sequence=7,source='192.0.2.10',action='accounting.stop',context={'accounting_record_id':str(identifier)})
        connection.execute.return_value.fetchall.side_effect=[
            [event],[(identifier,'example-user','192.0.2.10',['cmd=show','cmd-arg=clock'])]]
        result=read_activity(connection, UUID(TENANT), 6, ['command_accounting'])
        self.assertIn('show clock',result['activity'][0]['text'])
        self.assertEqual(result['activity_cursor'],7)
        for call in connection.execute.call_args_list:
            self.assertIn('tenant_id=%s',call.args[0])
            self.assertEqual(call.args[1][0],UUID(TENANT))

    def test_accounting_audit_references_inserted_id_in_same_transaction(self):
        pool=Pool()
        store=PostgresAccountingStore(pool,TENANT)
        store._audit.append_in_transaction=Mock()
        store.append(AccountingRecord(TENANT,'session','example-user','192.0.2.10','stop',('cmd=show',)))
        insert=next(call for call in pool.connection_object.execute.call_args_list if call.args[0].startswith('INSERT INTO accounting_records'))
        recorded_id=insert.args[1][0]
        self.assertEqual(store._audit.append_in_transaction.call_args.kwargs['security_context'],
                         {'accounting_record_id':str(recorded_id)})


class SlackActivityCursorTests(unittest.TestCase):
    def setUp(self):
        self.storage=MemoryStorage(configuration())
        self.storage.files['settings.json']['events']=['successful_logins']
        self.sender=Mock(return_value=(None,0))

    def cycle(self, now, activity, cursor):
        process(self.storage, {}, {'locked':{},'failures':0,'activity':activity,
                                  'activity_cursor':cursor,'activity_more':False},now=now,sender=self.sender)

    def test_retry_does_not_duplicate_activity_or_advance_unqueued_cursor(self):
        self.cycle(1000,[],5)
        self.sender.return_value=('Slack network or TLS failure',120)
        event={'sequence':6,'text':'AUTHENTICATION PASS example-user','time':1001}
        self.cycle(1060,[event],6)
        self.assertEqual(self.storage.files['state.json']['event_cursor'],6)
        self.assertEqual(len(self.storage.files['state.json']['pending']),1)
        self.cycle(1120,[event],6)
        self.assertEqual(len(self.storage.files['state.json']['pending']),1)
        self.assertEqual(self.sender.call_count,1)

    def test_login_delivery_has_one_line_without_repeated_metadata(self):
        self.cycle(1000, [], 5)
        event = project(row(sequence=6), {}, ['successful_logins'])
        self.cycle(1060, [event], 6)
        self.assertEqual(self.sender.call_args.args[1],
                         '✅ Switch Login Success · User: example-user · Source: 192.0.2.20 · Switch: 192.0.2.10')

    def test_aaa_rate_limit_is_per_device_and_category_and_expires(self):
        self.cycle(1000, [], 5)
        events = [project(row(sequence=n), {}, ['successful_logins']) for n in range(6, 12)]
        events += [
            project(row(sequence=12, target='192.0.2.11'), {}, ['successful_logins']),
            project(row(sequence=13, result='fail'), {}, ['aaa_activity']),
        ]
        self.cycle(1003, events, 13)
        state = self.storage.files['state.json']
        self.assertEqual(state['event_cursor'], 13)
        self.assertEqual([event['key'] for event in state['pending']],
                         ['activity:7', 'activity:8', 'activity:9', 'activity:10', 'activity:12', 'activity:13'])
        self.cycle(1063, [project(row(sequence=14), {}, ['successful_logins'])], 14)
        self.assertIn('activity:14', [event['key'] for event in self.storage.files['state.json']['pending']])

    def test_groups_device_activity_and_sends_independent_events_separately(self):
        self.cycle(1000, [], 5)
        config = self.storage.files['settings.json']
        config['test_id'] = 'test-id'
        identifier = str(UUID(int=9))
        records = {identifier: ('example-user', '192.0.2.10', ['service=shell'])}
        events = [
            project(row(sequence=6), {}, ['successful_logins']),
            project(row(sequence=7, action='aaa.authorization', result='allow'), {}, ['aaa_activity']),
            project(row(sequence=8, action='accounting.start', context={'accounting_record_id':identifier}),
                    records, ['aaa_activity']),
            project(row(sequence=9, action='accounting.stop', context={'accounting_record_id':identifier}),
                    records, ['aaa_activity']),
        ]
        self.cycle(1003, events, 9)
        self.assertEqual(self.sender.call_args.args[1], '🧪 Slack Test · Requested by an administrator')
        self.cycle(1006, [], 9)
        self.assertEqual(self.sender.call_args.args[1], events[0]['text'])
        self.cycle(1009, [], 9)
        self.assertEqual(self.sender.call_args.args[1].splitlines(), [events[1]['text'], events[2]['text']])
        self.cycle(1012, [], 9)
        self.assertEqual(self.sender.call_args.args[1], events[3]['text'])

    def test_full_queue_keeps_cursor_for_later_replay(self):
        self.cycle(1000,[],5)
        state=self.storage.files['state.json']
        state['pending']=[{'key':str(index),'text':'existing','time':1000,'next_attempt':9999,'attempts':1} for index in range(100)]
        self.cycle(1060,[{'sequence':6,'text':'example event','time':1001}],6)
        state=self.storage.files['state.json']
        self.assertEqual(state['event_cursor'],5)
        self.assertTrue(state['activity_backlog'])

    def test_unsubscribed_events_advance_cursor_without_messages(self):
        self.cycle(1000,[],5)
        self.cycle(1060,[{'sequence':6,'text':None,'time':1001}],6)
        self.assertEqual(self.storage.files['state.json']['event_cursor'],6)
        self.sender.assert_not_called()

    def test_long_command_notifications_are_split_without_silent_content_loss(self):
        self.cycle(1000,[],5)
        text='COMMAND stop — example-user | show '+ 'x'*1800
        events=[{'sequence':sequence,'text':text,'time':1001} for sequence in (6,7)]
        self.cycle(1060,events,7)
        self.assertIn(text,self.sender.call_args.args[1])
        self.assertLessEqual(len(self.sender.call_args.args[1]),2900)
        self.assertEqual(len(self.storage.files['state.json']['pending']),1)
        self.cycle(1120,[],7)
        self.assertEqual(self.sender.call_count,2)
        self.assertEqual(self.storage.files['state.json']['pending'],[])

    def test_slack_cooldown_applies_to_new_activity_too(self):
        self.cycle(1000,[],5)
        self.sender.return_value=('Slack rate limited',300)
        self.cycle(1060,[{'sequence':6,'text':'first event','time':1001}],6)
        self.cycle(1063,[{'sequence':7,'text':'new event','time':1062}],7)
        self.assertEqual(self.sender.call_count,1)
        self.assertEqual(len(self.storage.files['state.json']['pending']),2)
