import unittest
from unittest.mock import MagicMock
from uuid import UUID
from tacacs_appliance.policy_lifecycle import PolicyLifecycle,PolicyState
from tacacs_appliance.postgres_policy_lifecycle import PostgresPolicyLifecycle


class TenantPolicyReadTests(unittest.TestCase):
    def test_policy_reads_check_permissions_and_use_configured_tenant(self):
        home, actor = UUID(int=1), UUID(int=3)
        pool = MagicMock()
        connection = pool.connection.return_value.__enter__.return_value
        service = PostgresPolicyLifecycle(pool, str(home), MagicMock())
        connection.execute.return_value.fetchone.return_value = None
        with self.assertRaises(ValueError):
            service.list_versions(str(actor))
        connection.execute.return_value.fetchone.return_value = (home,)
        connection.execute.return_value.fetchall.return_value = []
        self.assertEqual(service.list_versions(str(actor))['items'], [])
        self.assertEqual(connection.execute.call_args.args[1][0], home)


class LifecycleTests(unittest.TestCase):
 def test_immutable_approval_and_activation(self):
  p=PolicyLifecycle("p");v=p.draft("author",())
  with self.assertRaises(ValueError):p.approve(v.version_id,"author")
  p.submit(v.version_id); approved=p.approve(v.version_id,"reviewer")
  active=p.activate(approved.version_id,"operator")
  self.assertEqual(active.state,PolicyState.ACTIVE);self.assertEqual(p.active().rules,())
