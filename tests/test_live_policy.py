from contextlib import nullcontext
import unittest
from unittest.mock import Mock
from tacacs_appliance.authorization import AuthorizationRequest, Decision
from tacacs_appliance.postgres_policy import LivePostgresPolicyEngine

TENANT = "00000000-0000-0000-0000-000000000001"
RULE = dict(rule_id="show", groups=[], device_ids=[], command_prefix="show", decision="allow")


class LivePolicyTests(unittest.TestCase):
    def setUp(self):
        self.pool, self.db = Mock(), Mock()
        self.pool.connection.side_effect = lambda: nullcontext(self.db)
        self.engine = LivePostgresPolicyEngine(self.pool, TENANT)
        self.request = AuthorizationRequest("user", "router", "show version")

    def test_activation_is_visible_on_next_decision(self):
        self.db.execute.return_value.fetchone.side_effect = [("old", [RULE]), ("new", []), ("rollback", [RULE])]
        first = self.engine.evaluate(self.request)
        second = self.engine.evaluate(self.request)
        third = self.engine.evaluate(self.request)
        self.assertEqual((first.decision, second.decision, third.decision), (Decision.ALLOW, Decision.DENY, Decision.ALLOW))
        self.assertEqual((first.policy_version, second.policy_version, third.policy_version), ("old", "new", "rollback"))
        self.assertEqual(self.pool.connection.call_count, 3)

    def test_database_failure_does_not_reuse_previous_allow(self):
        self.db.execute.return_value.fetchone.return_value = ("old", [RULE])
        self.assertEqual(self.engine.evaluate(self.request).decision, Decision.ALLOW)
        self.db.execute.side_effect = OSError("database unavailable")
        with self.assertRaises(OSError):
            self.engine.evaluate(self.request)

    def test_missing_active_policy_is_default_deny(self):
        self.db.execute.return_value.fetchone.return_value = None
        self.assertEqual(self.engine.evaluate(self.request).decision, Decision.DENY)
