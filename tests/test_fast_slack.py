import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import monitoring
from slack_monitor import check_alerts, process
from test_slack_alerts import MemoryStorage, configuration


class FastSlackTests(unittest.TestCase):
    def test_fast_activity_preserves_health_conditions_and_account_baseline(self):
        config=configuration()
        config['events'].append('successful_logins')
        storage=MemoryStorage(config)
        storage.files['state.json']={
            'revision':'example','event_cursor':5,'last_checked':'health-stamp',
            'locked_accounts':{'example':'test-user'},
            'conditions':{'service.app':{'active':True,'count':3,'since':1000}},
        }
        facts={'locked':{},'failures':0,'activity':[{'sequence':6,'text':'AUTHENTICATION PASS','time':1000}],
               'activity_cursor':6,'activity_more':False,'checked_events':['successful_logins']}
        sender=Mock(return_value=(None,0))
        process(storage,{},facts,now=1060,sender=sender,activity_only=True)
        state=storage.files['state.json']
        self.assertEqual(state['last_checked'],'health-stamp')
        self.assertTrue(state['conditions']['service.app']['active'])
        self.assertEqual(state['locked_accounts'],{'example':'test-user'})
        self.assertEqual(state['event_cursor'],6)
        self.assertIn('AUTHENTICATION PASS',sender.call_args.args[1])
        self.assertNotIn('Recovered',sender.call_args.args[1])

    def test_fast_collector_requests_only_activity_groups(self):
        config=configuration()
        config['events'].extend(['successful_logins','command_accounting'])
        storage=MemoryStorage(config)
        with patch('slack_monitor.AlertStorage',return_value=storage), \
             patch('slack_monitor.collect_facts',return_value=None) as collect, \
             patch('slack_monitor.process') as deliver:
            check_alerts('project',{},Path.cwd(),activity_only=True)
        self.assertEqual(set(collect.call_args.args[1]),{'successful_logins','command_accounting','locked_accounts'})
        self.assertTrue(deliver.call_args.kwargs['activity_only'])

    def test_health_collector_does_not_duplicate_activity_queries(self):
        config=configuration()
        config['events'].append('successful_logins')
        storage=MemoryStorage(config)
        with patch('slack_monitor.AlertStorage',return_value=storage), \
             patch('slack_monitor.collect_facts',return_value=None) as collect, \
             patch('slack_monitor.process'):
            check_alerts('project',{},Path.cwd())
        self.assertNotIn('successful_logins',collect.call_args.args[1])
        self.assertNotIn('locked_accounts',collect.call_args.args[1])

    def test_fast_path_detects_lock_and_unlock(self):
        storage=MemoryStorage(configuration())
        sender=Mock(return_value=(None,0))
        def poll(now, locked):
            process(storage,{}, {'locked':locked,'failures':0,'checked_events':['locked_accounts']},
                    now=now,sender=sender,activity_only=True)
        poll(1000,{})
        poll(1003,{'example':'test-user'})
        self.assertIn('Account Locked · test-user',sender.call_args.args[1])
        poll(1006,{'example':'test-user'})
        self.assertEqual(sender.call_count,1)
        poll(1009,{})
        self.assertIn('Account No Longer Locked',sender.call_args.args[1])
        self.assertEqual(sender.call_count,2)

    def test_health_query_without_account_facts_cannot_emit_unlock(self):
        storage=MemoryStorage(configuration())
        storage.files['state.json']={'revision':'example','locked_accounts':{'example':'test-user'}}
        sender=Mock(return_value=(None,0))
        process(storage,{}, {'locked':{},'failures':0,'checked_events':['authentication_failures']},
                now=1000,sender=sender)
        self.assertEqual(storage.files['state.json']['locked_accounts'],{'example':'test-user'})
        sender.assert_not_called()

    def test_lock_notification_has_priority_over_activity_backlog(self):
        storage=MemoryStorage(configuration())
        storage.files['state.json']={'revision':'example','locked_accounts':{},
            'pending':[{'key':'activity:'+str(index),'text':'existing','time':900,
                        'next_attempt':0,'attempts':0} for index in range(99)]}
        sender=Mock(return_value=(None,0))
        process(storage,{}, {'locked':{'example':'test-user'},'failures':0,
                            'checked_events':['locked_accounts']},now=1000,sender=sender,activity_only=True)
        self.assertIn('Account Locked · test-user',sender.call_args.args[1])

    def test_worker_waits_for_remaining_three_second_interval(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            (directory/'deployment.json').write_text(json.dumps({'project':'example','alerts_path':temporary}))
            stopped=Mock()
            stopped.is_set.side_effect=[False,True]
            with patch('monitoring.MONITOR',directory), \
                 patch('monitoring.threading.Event',return_value=stopped), \
                 patch('monitoring.signal.signal'), \
                 patch('monitoring.time.monotonic',side_effect=[10,10.5]), \
                 patch('slack_monitor.check_alerts') as collect, \
                 patch('monitoring.capture') as snapshot:
                monitoring.alerts()
            stopped.wait.assert_called_once_with(2.5)
            collect.assert_called_once_with('example',{},temporary,activity_only=True)
            snapshot.assert_not_called()
