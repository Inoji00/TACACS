import unittest
from contextlib import nullcontext
from unittest.mock import Mock
from uuid import UUID
from datetime import datetime, timezone
from tacacs_appliance.admin_logs import AdminLogs, log_filters

TENANT='00000000-0000-0000-0000-000000000001'
ACTOR='00000000-0000-0000-0000-000000000002'
MEMBER='00000000-0000-0000-0000-000000000003'


class LogTests(unittest.TestCase):
    def test_delegated_aaa_query_matches_location_type_and_scope_start(self):
        service, _, db = self.repository()
        scope = {'actions': ['view_aaa_logs'], 'location_id': str(UUID(int=11)),
                 'device_type_id': str(UUID(int=12))}
        db.execute.return_value.fetchone.side_effect = [None, (scope,)]
        db.execute.return_value.fetchall.return_value = []
        service.read(str(UUID(int=13)), kind='aaa')
        query, params = db.execute.call_args.args
        self.assertIn("a.source='tacacs'", query)
        self.assertIn('host(d.address) = a.target', query)
        self.assertIn('d.tenant_id = %s', query)
        self.assertIn('NOT d.deleted', query)
        self.assertIn('a.occurred_at >= d.aaa_log_scope_since', query)
        self.assertIn('d.location_id = %s AND d.device_type_id = %s', query)
        self.assertEqual(params[-3:-1], (scope['location_id'], scope['device_type_id']))
    def repository(self):
        pool, db = Mock(), Mock()
        pool.connection.side_effect=lambda:nullcontext(db)
        db.transaction.side_effect=lambda:nullcontext()
        db.execute.return_value.fetchone.return_value=(1,)
        return AdminLogs(pool,TENANT), pool, db

    def test_invalid_filters_fail_before_database(self):
        service,pool,_=self.repository()
        for fields in ({'kind':'forged'},{'limit':101},{'device':'bad-ip'}, {'before':'-1'},
                       {'search':'line\nbreak'}, {'since':'2026-01-01'},
                       {'since':'2026-01-01T00:00:00Z','until':'2026-03-01T00:00:00Z'}):
            with self.subTest(fields=fields),self.assertRaises(ValueError):service.read(ACTOR,**fields)
        pool.connection.assert_not_called()

    def test_query_is_parameterized_and_exposes_only_metadata(self):
        service,_,db=self.repository()
        row=(UUID(ACTOR),9,datetime.now(timezone.utc),'device','tacacs','aaa.authentication','192.0.2.2','pass','42',None,None,'unknown-user',None,None)
        db.execute.return_value.fetchall.return_value=[row,row]
        result=service.read(ACTOR,kind='aaa',search="' OR 1=1 --",session='42',actor='device',limit=1)
        statement,params=db.execute.call_args.args
        self.assertNotIn("' OR 1=1 --",statement);self.assertIn("' OR 1=1 --",params)
        self.assertEqual(params[0],UUID(TENANT));self.assertEqual(result['next_before'],9)
        self.assertEqual(result['items'][0]['session'],'42')
        self.assertEqual(result['items'][0]['attempted_username'],'unknown-user')
        for name in ('security_context','canonical_data','password','arguments'):self.assertNotIn(name,result['items'][0])

    def test_account_target_snapshot_and_legacy_lookup(self):
        service,_,db=self.repository()
        row=(UUID(ACTOR),9,datetime.now(timezone.utc),ACTOR,'admin-identities','identity.create',
             MEMBER,'success',None,None,'admin',None,'renamed-user')
        db.execute.return_value.fetchall.return_value=[
            (*row,{'target_name':'original-user','identity_group':'ops','password':'private'}),
            (*row,None),
        ]
        first,second=service.read(ACTOR,search='original-user')['items']
        self.assertEqual((first['target_name'],first['target_name_source']),('original-user','event'))
        self.assertEqual(first['identity_details'],{'identity_group':'ops'})
        self.assertEqual((second['target_name'],second['target_name_source']),('renamed-user','current'))
        self.assertIsNone(first['attempted_username'])

    def test_denied_principal_cannot_read_or_aggregate(self):
        service,_,db=self.repository();db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):service.read(ACTOR)
        self.assertEqual(db.execute.call_count,3)

    def test_removed_tenant_filter_cannot_select_another_tenant_or_all(self):
        service, pool, _ = self.repository()
        for target in (MEMBER, 'all'):
            with self.subTest(target=target), self.assertRaises(TypeError):
                service.read(ACTOR, report=True, tenant_id=target)
        pool.connection.assert_not_called()

    def test_activity_excludes_device_accounting_and_issues_exclude_challenges(self):
        where,*_=log_filters(kind='activity');self.assertIn("NOT LIKE 'accounting.%%'",where)
        where,*_=log_filters(kind='issues');self.assertNotIn('challenge',where)
        self.assertIn("'deny'",where)



    def test_web_access_ip_fields_are_normalized_and_searchable(self):
        service,_,db=self.repository()
        row=(UUID(ACTOR),9,datetime.now(timezone.utc),ACTOR,'admin-web','web.login',
             '192.0.2.15','success',None,None,'admin','admin',None,None,None)
        db.execute.return_value.fetchall.return_value=[
            (*row,'2001:0db8:0::1','192.0.2.15'),
            (*row,'not-an-ip','192.0.2.15,192.0.2.22'),
        ]
        first,second=service.read(ACTOR,search='192.0.2.15',device='192.0.2.27')['items']
        statement,params=db.execute.call_args.args
        self.assertIn("security_context->>'source_ip'",statement)
        self.assertIn("security_context->>'destination_ip'",statement)
        self.assertIn('192.0.2.15',params)
        self.assertEqual(params.count('192.0.2.27'),2)
        self.assertEqual(first['source_ip'],'2001:db8::1')
        self.assertEqual(first['destination_ip'],'192.0.2.15')
        self.assertNotIn('source_ip',second)
        self.assertNotIn('destination_ip',second)

    def test_aaa_remote_address_is_distinct_from_device_address(self):
        service,_,db=self.repository()
        row=(UUID(ACTOR),9,datetime.now(timezone.utc),'device','tacacs','aaa.authentication',
             '192.0.2.2','pass','42',None,None,'operator','Switch-01',None,None,None,None)
        db.execute.return_value.fetchall.return_value=[(*row,'2001:db8::27'),(*row,None)]
        first,second=service.read(ACTOR,kind='aaa',search='2001:db8::27')['items']
        statement,params=db.execute.call_args.args
        self.assertIn("security_context->>'remote_address'",statement)
        self.assertIn('2001:db8::27',params)
        self.assertEqual((first['target_name'],first['target'],first['remote_address']),
                         ('Switch-01','192.0.2.2','2001:db8::27'))
        self.assertNotIn('remote_address',second)
