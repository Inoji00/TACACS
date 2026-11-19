from contextlib import nullcontext
from datetime import datetime,timezone
import unittest
from unittest.mock import Mock
from uuid import UUID
from tacacs_appliance.postgres_simulation import PostgresPolicySimulation,canonical_digest

TENANT=UUID('00000000-0000-0000-0000-000000000001')
USER=UUID('00000000-0000-0000-0000-000000000002')
VERSION=UUID('00000000-0000-0000-0000-000000000003')
REPORT=UUID('00000000-0000-0000-0000-000000000004')


class PostgresSimulationTests(unittest.TestCase):
    def setUp(self):
        self.pool,self.db=Mock(),Mock()
        self.pool.connection.side_effect=lambda:nullcontext(self.db)
        self.db.transaction.side_effect=lambda:nullcontext()
        self.db.execute.return_value.fetchone.return_value=(1,)
        self.service=PostgresPolicySimulation(self.pool,str(TENANT))
        self.samples=[dict(subject='a',device_id='router',command='show version',groups=[])]

    def test_default_deny_baseline_read_only_snapshot_and_tenant_query(self):
        rule=dict(rule_id='show',groups=[],device_ids=[],command_prefix='show',decision='allow')
        self.db.execute.return_value.fetchall.return_value=[(VERSION,[rule],'draft')]
        report=self.service.compare(str(VERSION),str(USER),self.samples)
        self.assertEqual(report['newly_allowed'],(0,));self.assertEqual(report['baseline_version'],'default-deny')
        calls=self.db.execute.call_args_list
        self.assertIn('REPEATABLE READ READ ONLY',calls[0].args[0])
        self.assertEqual(calls[-1].args[1],(TENANT,VERSION))
        self.assertFalse(any('FOR UPDATE' in call.args[0] for call in calls))

    def test_missing_permission_prevents_policy_reads(self):
        self.db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):self.service.compare(str(VERSION),str(USER),self.samples)
        self.assertEqual(self.db.execute.call_count,2)

    def test_unknown_candidate_and_ambiguous_active_policy_fail(self):
        self.db.execute.return_value.fetchall.return_value=[]
        with self.assertRaises(ValueError):self.service.compare(str(VERSION),str(USER),self.samples)
        self.db.execute.return_value.fetchall.return_value=[(VERSION,[],'active'),(USER,[],'active')]
        with self.assertRaises(ValueError):self.service.compare(str(VERSION),str(USER),self.samples)

    def test_invalid_samples_never_open_database(self):
        for samples in ([],[self.samples[0]|{'actor':'fake'}],[self.samples[0]|{'groups':['x']*129}]):
            with self.assertRaises(ValueError):self.service.compare(str(VERSION),str(USER),samples)
        self.pool.connection.assert_not_called()

    def test_record_requires_audit_and_uses_policy_draft_permission(self):
        with self.assertRaises(ValueError):self.service.record(str(VERSION),str(USER),self.samples)
        self.pool.connection.assert_not_called()
        audit=Mock();self.service.audit=audit
        self.db.execute.return_value.fetchall.return_value=[(VERSION,[],'draft')]
        result=self.service.record(str(VERSION),str(USER),self.samples)
        self.assertIn('report_id',result)
        calls=self.db.execute.call_args_list
        self.assertIn('FOR UPDATE',calls[0].args[0])
        self.assertEqual(calls[1].args[1],(TENANT,USER,'policy.draft'))
        self.assertTrue(calls[-1].args[0].startswith('INSERT INTO policy_simulation_reports'))
        self.assertIs(audit.call_args.args[0],self.db)
        self.assertNotIn('show version',str(audit.call_args))

    def test_over_budget_record_never_inserts_report_or_calls_audit(self):
        rules=[dict(rule_id='r'+str(index),groups=[],device_ids=[],command_prefix='show',decision='allow')
               for index in range(4096)]
        self.db.execute.return_value.fetchall.return_value=[(VERSION,rules,'active')]
        audit=Mock();self.service.audit=audit
        with self.assertRaisesRegex(ValueError,'work budget'):
            self.service.record(str(VERSION),str(USER),self.samples*33)
        audit.assert_not_called()
        self.assertFalse(any(call.args[0].startswith('INSERT') for call in self.db.execute.call_args_list))

    def test_list_metadata_is_bounded_read_only_and_cursor_scoped(self):
        now=datetime.now(timezone.utc)
        row=(REPORT,USER,now,VERSION,None,1)
        self.db.execute.return_value.fetchone.side_effect=[(1,),(VERSION,),(now,REPORT)]
        self.db.execute.return_value.fetchall.return_value=[row,row]
        page=self.service.list_records(str(VERSION),str(USER),before=str(REPORT),limit=1)
        self.assertEqual(page['next_before'],str(REPORT));self.assertEqual(len(page['items']),1)
        self.assertEqual(page['items'][0]['integrity_status'],'not-verified')
        self.assertNotIn('report',page['items'][0])
        calls=self.db.execute.call_args_list
        self.assertIn('READ ONLY',calls[0].args[0])
        self.assertEqual(calls[2].args[1],(TENANT,VERSION))
        self.assertEqual(calls[3].args[1],(TENANT,VERSION,REPORT))
        self.assertEqual(calls[4].args[1],(TENANT,VERSION,now,REPORT,2))

    def test_detail_is_scoped_validated_and_never_returns_unknown_record(self):
        report=self.service._evaluate((VERSION,[],'draft'),None,self.service._requests(self.samples))
        row=(REPORT,USER,datetime.now(timezone.utc),VERSION,None,1,'a'*64,'b'*64,'c'*64,report)
        self.db.execute.return_value.fetchone.side_effect=[(1,),row]
        item=self.service.inspect_record(str(VERSION),str(USER),str(REPORT))
        self.assertEqual(item['report'],report);self.assertEqual(item['samples_digest'],'c'*64)
        self.assertEqual(self.db.execute.call_args.args[1],(TENANT,VERSION,REPORT))
        self.db.execute.return_value.fetchone.side_effect=[(1,),None]
        self.assertIsNone(self.service.inspect_record(str(VERSION),str(USER),str(REPORT)))
        self.db.execute.return_value.fetchone.side_effect=[(1,),row[:-1]+(report|{'command':'private'},)]
        with self.assertRaises(RuntimeError):self.service.inspect_record(str(VERSION),str(USER),str(REPORT))

    def test_missing_read_grant_prevents_any_evidence_query(self):
        self.db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):self.service.list_records(str(VERSION),str(USER))
        self.assertEqual(self.db.execute.call_count,2)
        self.db.execute.reset_mock()
        with self.assertRaises(PermissionError):self.service.inspect_record(str(VERSION),str(USER),str(REPORT))
        self.assertEqual(self.db.execute.call_count,2)

    def test_invalid_pagination_or_ids_never_open_database(self):
        for kwargs in ({'limit':0},{'limit':51},{'limit':True},{'before':''},{'before':'invalid'}):
            with self.assertRaises(ValueError):self.service.list_records(str(VERSION),str(USER),**kwargs)
        with self.assertRaises(ValueError):self.service.inspect_record(str(VERSION),str(USER),'invalid')
        self.pool.connection.assert_not_called()

    def test_missing_candidate_or_cursor_never_returns_other_policy_evidence(self):
        self.db.execute.return_value.fetchone.side_effect=[(1,),None]
        self.assertIsNone(self.service.list_records(str(VERSION),str(USER)))
        self.assertEqual(self.db.execute.call_count,3)
        self.db.execute.reset_mock()
        self.db.execute.return_value.fetchone.side_effect=[(1,),(VERSION,),None]
        with self.assertRaises(ValueError):self.service.list_records(str(VERSION),str(USER),before=str(REPORT))
        self.assertEqual(self.db.execute.call_count,4)

    def test_empty_last_page_has_no_cursor(self):
        self.db.execute.return_value.fetchall.return_value=[]
        self.assertEqual(self.service.list_records(str(VERSION),str(USER)),{'items':[],'next_before':None})

    def replay_row(self,baseline=None):
        candidate=(VERSION,[],'draft')
        report=self.service._evaluate(candidate,baseline,self.service._requests(self.samples))
        return (baseline[0] if baseline else None,1,canonical_digest(baseline[1] if baseline else []),
                canonical_digest([]),canonical_digest(self.samples),report)

    def test_replay_matches_without_writes_or_provenance_claim(self):
        self.db.execute.return_value.fetchone.side_effect=[(1,),self.replay_row()]
        self.db.execute.return_value.fetchall.return_value=[(VERSION,[],'archived')]
        result=self.service.verify_record(str(VERSION),str(USER),str(REPORT),self.samples)
        self.assertTrue(result['samples_match']);self.assertTrue(result['rules_match'])
        self.assertTrue(result['decisions_match']);self.assertEqual(result['integrity_status'],'not-verified')
        calls=self.db.execute.call_args_list
        self.assertIn('READ ONLY',calls[0].args[0])
        self.assertEqual(calls[2].args[1],(TENANT,VERSION,REPORT))
        self.assertEqual(calls[3].args[1],(TENANT,VERSION,None))
        self.assertFalse(any('active' in call.args[0] or 'INSERT' in call.args[0] for call in calls))
        self.assertNotIn('show version',str(result))

    def test_replay_sample_or_rule_mismatch_does_not_claim_decision_match(self):
        for samples,rules,expected in (([self.samples[0]|{'command':'show other'}],[],False),
                                      (self.samples,[dict(rule_id='x',groups=[],device_ids=[],command_prefix='show',decision='allow')],True)):
            self.db.execute.return_value.fetchone.side_effect=[(1,),self.replay_row()]
            self.db.execute.return_value.fetchall.return_value=[(VERSION,rules,'draft')]
            result=self.service.verify_record(str(VERSION),str(USER),str(REPORT),samples)
            self.assertEqual(result['samples_match'],expected);self.assertIsNone(result['decisions_match'])

    def test_replay_uses_recorded_baseline_not_current_active(self):
        baseline=(USER,[],'archived')
        self.db.execute.return_value.fetchone.side_effect=[(1,),self.replay_row(baseline)]
        self.db.execute.return_value.fetchall.return_value=[(VERSION,[],'draft'),baseline]
        result=self.service.verify_record(str(VERSION),str(USER),str(REPORT),self.samples)
        self.assertTrue(result['decisions_match']);self.assertEqual(result['baseline_version'],str(USER))
        self.assertEqual(self.db.execute.call_args.args[1],(TENANT,VERSION,USER))

    def test_replay_unknown_corrupt_missing_rules_and_permission(self):
        self.db.execute.return_value.fetchone.side_effect=[(1,),None]
        self.assertIsNone(self.service.verify_record(str(VERSION),str(USER),str(REPORT),self.samples))
        row=self.replay_row()
        self.db.execute.return_value.fetchone.side_effect=[(1,),row[:-1]+(row[-1]|{'command':'private'},)]
        with self.assertRaises(RuntimeError):self.service.verify_record(str(VERSION),str(USER),str(REPORT),self.samples)
        self.db.execute.return_value.fetchone.side_effect=[(1,),row]
        self.db.execute.return_value.fetchall.return_value=[]
        result=self.service.verify_record(str(VERSION),str(USER),str(REPORT),self.samples)
        self.assertFalse(result['rules_match']);self.assertIsNone(result['decisions_match'])
        self.db.execute.return_value.fetchone.side_effect=[None]
        with self.assertRaises(PermissionError):self.service.verify_record(str(VERSION),str(USER),str(REPORT),self.samples)

    def test_replay_invalid_input_never_opens_database(self):
        with self.assertRaises(ValueError):self.service.verify_record(str(VERSION),str(USER),str(REPORT),[])
        self.pool.connection.assert_not_called()

    def test_replay_detects_structurally_valid_decision_disagreement(self):
        row=self.replay_row()
        rule=dict(rule_id='show',groups=[],device_ids=[],command_prefix='show',decision='allow')
        different=self.service._evaluate((VERSION,[rule],'draft'),None,self.service._requests(self.samples))
        self.db.execute.return_value.fetchone.side_effect=[(1,),row[:-1]+(different,)]
        self.db.execute.return_value.fetchall.return_value=[(VERSION,[],'draft')]
        result=self.service.verify_record(str(VERSION),str(USER),str(REPORT),self.samples)
        self.assertTrue(result['samples_match']);self.assertTrue(result['rules_match'])
        self.assertFalse(result['decisions_match'])

    def test_canonical_digest_preserves_array_order_and_duplicates(self):
        self.assertEqual(canonical_digest({'a':1,'b':2}),canonical_digest({'b':2,'a':1}))
        self.assertNotEqual(canonical_digest(['a','b']),canonical_digest(['b','a']))
        self.assertNotEqual(canonical_digest(['a']),canonical_digest(['a','a']))
