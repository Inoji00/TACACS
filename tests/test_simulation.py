import unittest
from unittest.mock import patch
from tacacs_appliance.authorization import *
from tacacs_appliance.simulation import simulate,compare_policies,MAX_SIMULATION_RULE_CHECKS
class SimulationTests(unittest.TestCase):
 def test_simulation_is_deterministic(self):
  engine=AuthorizationEngine("v1",(PolicyRule("r",frozenset(),frozenset(),"show",Decision.ALLOW),));request=AuthorizationRequest("a","d","show x")
  self.assertEqual(simulate(engine,request),simulate(engine,request))

 def test_missing_risk_and_mfa_assessment_are_not_reported_as_safe(self):
  result=simulate(AuthorizationEngine('default-deny',()),AuthorizationRequest('a','d','reload'))
  self.assertEqual(result.risk,'unassessed');self.assertIsNone(result.required_mfa);self.assertIsNone(result.obligations)

 def test_sample_delta_counts_new_allows_denies_and_unchanged_without_commands(self):
  before=AuthorizationEngine('v1',(PolicyRule('show',frozenset(),frozenset(),'show',Decision.ALLOW),))
  after=AuthorizationEngine('v2',(PolicyRule('reload',frozenset(),frozenset(),'reload',Decision.ALLOW),))
  requests=tuple(AuthorizationRequest('a','d',command) for command in ('show version','reload','secret-password-test'))
  impact=compare_policies(before,after,requests)
  self.assertEqual(impact.newly_allowed,(1,));self.assertEqual(impact.newly_denied,(0,));self.assertEqual(impact.unchanged,1)
  self.assertEqual(impact.coverage,'provided-samples-only')
  self.assertNotIn('secret-password-test',repr(impact))
  self.assertEqual(impact,compare_policies(before,after,requests))
  self.assertEqual(before.evaluate(requests[0]).decision,Decision.ALLOW)

 def test_group_device_scopes_and_invalid_commands_use_live_evaluator(self):
  rule=PolicyRule('r',frozenset({'ops'}),frozenset({'router'}),'show',Decision.ALLOW)
  baseline=AuthorizationEngine('v1',());candidate=AuthorizationEngine('v2',(rule,))
  requests=(AuthorizationRequest('a','router','show version',frozenset({'ops'})),
            AuthorizationRequest('a','other','show version',frozenset({'ops'})),
            AuthorizationRequest('a','router','show version'),
            AuthorizationRequest('a','router','show; reload',frozenset({'ops'})))
  impact=compare_policies(baseline,candidate,requests)
  self.assertEqual(impact.newly_allowed,(0,));self.assertEqual(impact.unchanged,3)

 def test_invalid_or_unbounded_sample_rejected(self):
  engine=AuthorizationEngine('v',());request=AuthorizationRequest('a','d','show')
  for requests in ((),[request],(request,)*1025,(AuthorizationRequest('','d','show'),)):
   with self.assertRaises(ValueError):compare_policies(engine,engine,requests)

 def test_multiplicative_budget_rejected_before_any_evaluation(self):
  rule=PolicyRule('r',frozenset(),frozenset(),'show',Decision.ALLOW)
  engine=AuthorizationEngine('v',(rule,)*4096)
  request=AuthorizationRequest('a','d','show')
  with patch.object(engine,'evaluate') as evaluate:
   with self.assertRaisesRegex(ValueError,'work budget'):compare_policies(engine,engine,(request,)*33)
   evaluate.assert_not_called()

 def test_budget_boundary_counts_both_policy_snapshots(self):
  rule=PolicyRule('r',frozenset(),frozenset(),'show',Decision.ALLOW)
  engine=AuthorizationEngine('v',(rule,)*4096)
  count=MAX_SIMULATION_RULE_CHECKS//(2*engine.rule_count)
  impact=compare_policies(engine,engine,(AuthorizationRequest('a','d','show'),)*count)
  self.assertEqual(impact.total,count);self.assertEqual(impact.unchanged,count)
