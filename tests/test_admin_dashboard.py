from datetime import datetime,timezone
import unittest
from unittest.mock import MagicMock
from tacacs_appliance.admin_dashboard import AdminDashboard, read_failed_auth

TENANT='00000000-0000-0000-0000-000000000001'
ACTOR='00000000-0000-0000-0000-000000000002'


class DashboardTests(unittest.TestCase):
    def test_denied_actor_cannot_read_inventory_or_events(self):
        pool=MagicMock();connection=pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):AdminDashboard(pool,TENANT).read(ACTOR)
        self.assertEqual(connection.execute.call_count,2)

    def test_all_queries_are_tenant_scoped_and_only_safe_projection_returned(self):
        pool=MagicMock();connection=pool.connection.return_value.__enter__.return_value
        now=datetime(2026,11,4,12,tzinfo=timezone.utc)
        values=[None,(1,),(now,),(4,3,1),(2,),(3,2,1),[('active',1)],[(now.replace(tzinfo=None),'aaa.authentication','pass',5)],[(now.date(),5,2)],[('192.0.2.2',2,now,'lab-user',2,1,1)],[(now,'device.update','192.0.2.2','success')],[(None,7,2,1,3)],[('192.0.2.2',2)],[('lab-user',5)],[(now,'192.0.2.2','pass','aaa.authentication','lab-user')]]
        def execute(query,params=None):
            if params is not None:self.assertEqual(str(params[0]),TENANT)
            result=MagicMock();value=values.pop(0)
            result.fetchone.return_value=value;result.fetchall.return_value=value
            return result
        connection.execute.side_effect=execute
        data=AdminDashboard(pool,TENANT).read(ACTOR)
        self.assertEqual(data['inventory']['pending_devices'],1)
        self.assertEqual(data['activity'][0]['count'],5)
        self.assertEqual(data['activity'][0]['hour'],'2026-11-04T12:00:00Z')
        self.assertEqual(data['failures'][0]['username'],'lab-user')
        self.assertEqual(data['failure_summary'],dict(total=2,users=1,source_ips=1))
        self.assertEqual(data['daily_auth'],[dict(day='2026-11-04',passed=5,failed=2)])
        self.assertEqual(data['totals'],[7,2,1,3])
        self.assertEqual(data['latest'][0]['username'],'lab-user')
        self.assertNotIn('security_context',str(data))
        self.assertEqual(values,[])

    def test_failed_auth_preserves_empty_and_full_window_totals(self):
        connection = MagicMock()
        now = datetime(2026, 11, 4, tzinfo=timezone.utc)
        connection.execute.return_value.fetchall.side_effect = [
            [(None,None,None,None,0,0,0)],
            [('192.0.2.2',5,now,'lab-user',12,8,3), ('192.0.2.2',2,now,None,12,8,3)],
        ]
        self.assertEqual(read_failed_auth(connection,TENANT),([],dict(total=0,users=0,source_ips=0)))
        rows, summary = read_failed_auth(connection,TENANT)
        self.assertEqual(summary,dict(total=12,users=8,source_ips=3))
        self.assertEqual([row['count'] for row in rows],[5,2])
        self.assertIsNone(rows[1]['username'])
