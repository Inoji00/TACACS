import unittest
from contextlib import nullcontext
from unittest.mock import Mock
from datetime import datetime,timezone
from uuid import UUID
from tacacs_appliance.admin_audit import PostgresAdminAudit
from tacacs_appliance.admin_api import AdminApi,COOKIE_NAME

TENANT='00000000-0000-0000-0000-000000000001'
ACTOR='00000000-0000-0000-0000-000000000002'


class AdminAuditTests(unittest.TestCase):
    def setup_repository(self):
        pool,db=Mock(),Mock()
        pool.connection.side_effect=lambda:nullcontext(db)
        db.transaction.side_effect=lambda:nullcontext()
        return PostgresAdminAudit(pool,TENANT),pool,db

    def test_page_is_bounded_tenant_scoped_and_excludes_raw_context(self):
        repository,pool,db=self.setup_repository()
        db.execute.return_value.fetchone.return_value=(1,)
        row=(UUID(ACTOR),3,datetime.now(timezone.utc),'actor','source','action','target','success','a'*64)
        db.execute.return_value.fetchall.return_value=[row,row]
        result=repository.list_events(ACTOR,before=4,limit=1)
        self.assertEqual(result['next_before'],3)
        self.assertNotIn('security_context',result['items'][0])
        self.assertEqual(db.execute.call_args.args[1],(UUID(TENANT),4,2))

    def test_missing_grant_and_oversized_page_fail_closed(self):
        repository,pool,db=self.setup_repository()
        with self.assertRaises(ValueError):repository.list_events(ACTOR,limit=101)
        pool.connection.assert_not_called()
        db.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):repository.list_events(ACTOR)
        self.assertEqual(db.execute.call_count,2)

    def test_api_uses_trusted_actor_and_returns_generic_permission_error(self):
        sessions=Mock();sessions.resolve.return_value=ACTOR
        audit=Mock();audit.list_events.side_effect=PermissionError('sensitive diagnostic')
        app=AdminApi(sessions,Mock(),b'k'*32,'https://admin.local',audit=audit)
        start=Mock()
        body=b''.join(app({'wsgi.url_scheme':'https','REQUEST_METHOD':'GET','PATH_INFO':'/api/audit',
            'HTTP_COOKIE':f'{COOKIE_NAME}={"a"*43}'},start))
        audit.list_events.assert_called_once_with(ACTOR)
        self.assertEqual(start.call_args.args[0],'403 Forbidden')
        self.assertNotIn(b'sensitive',body)
