from datetime import datetime,timezone
import unittest
from unittest.mock import MagicMock
from uuid import UUID
from tacacs_appliance.admin_accounting import AdminAccounting

TENANT='00000000-0000-0000-0000-000000000001'
ACTOR='00000000-0000-0000-0000-000000000002'


class AccountingQueryTests(unittest.TestCase):
    def test_delegated_cursor_must_belong_to_visible_device(self):
        pool=MagicMock()
        db=pool.connection.return_value.__enter__.return_value
        scope={'actions':['view_aaa_logs'],'location_id':None,'device_type_id':str(UUID(int=7))}
        db.execute.return_value.fetchone.side_effect=[None,(scope,),None]
        service=AdminAccounting(pool,str(TENANT))
        with self.assertRaisesRegex(ValueError,'cursor unavailable'):
            service.list_events(str(ACTOR),before=str(UUID(int=9)))
        query, params=db.execute.call_args.args
        self.assertIn('host(d.address) = accounting_records.device_id',query)
        self.assertIn('accounting_records.occurred_at >= d.aaa_log_scope_since',query)
        self.assertIn('d.device_type_id = %s',query)
        self.assertEqual(params[-1],scope['device_type_id'])
    def test_invalid_filters_rejected_before_database(self):
        pool=MagicMock();service=AdminAccounting(pool,TENANT)
        for values in (dict(limit=101),dict(limit=True),dict(device='0.0.0.0/0'),dict(username='x\n'),dict(before='not-uuid'),dict(action='allow')):
            with self.assertRaises(ValueError):service.list_events(ACTOR,**values)
        pool.connection.assert_not_called()

    def test_scoped_parameterized_projection_excludes_raw_arguments(self):
        pool=MagicMock();db=pool.connection.return_value.__enter__.return_value
        db.execute.return_value.fetchone.return_value=(1,)
        db.execute.return_value.fetchall.return_value=[(ACTOR,datetime.now(timezone.utc),'session','user','192.0.2.2','start',['cmd=show','cmd-arg=version','task_id=42','priv-lvl=1'])]*2
        page=AdminAccounting(pool,TENANT).list_events(ACTOR,username="x' OR 1=1 --",limit=1)
        self.assertEqual(page['next_before'],ACTOR)
        self.assertEqual(page['items'][0]['command'],'show version')
        self.assertNotIn('arguments',page['items'][0])
        query,values=db.execute.call_args.args
        self.assertIn('tenant_id=%s',query);self.assertIn('arguments',query)
        self.assertNotIn("x' OR 1=1 --",query);self.assertIn("x' OR 1=1 --",values)
        self.assertEqual(set(page['items'][0]),{'id','timestamp','session','username','device','action','kind','command','redacted','task_id','privilege'})

    def test_permission_failure_precedes_accounting_read(self):
        pool=MagicMock();db=pool.connection.return_value.__enter__.return_value
        db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):AdminAccounting(pool,TENANT).list_events(ACTOR)
        self.assertFalse(any('FROM accounting_records' in call.args[0] for call in db.execute.call_args_list))
