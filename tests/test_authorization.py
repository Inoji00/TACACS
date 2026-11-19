import unittest
from tacacs_appliance.authorization import *
class AuthorizationTests(unittest.TestCase):
 def setUp(self):
  self.engine=AuthorizationEngine("v7",(PolicyRule("allow-show",frozenset({"ops"}),frozenset({"r1"}),"show ",Decision.ALLOW),))
 def test_allow_and_default_deny(self):
  allowed=self.engine.evaluate(AuthorizationRequest("a","r1"," show   interfaces ",frozenset({"ops"})))
  denied=self.engine.evaluate(AuthorizationRequest("a","r1","configure terminal",frozenset({"ops"})))
  self.assertEqual(allowed.decision,Decision.ALLOW); self.assertEqual(allowed.policy_version,"v7")
  self.assertEqual(denied.decision,Decision.DENY); self.assertIsNone(denied.matched_rule_id)
 def test_group_cannot_bypass(self):
  self.assertEqual(self.engine.evaluate(AuthorizationRequest("a","r1","show x",frozenset())).decision,Decision.DENY)
