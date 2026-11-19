import unittest
from tacacs_appliance.policy_testing import run_policy_tests

RULES = [dict(rule_id="show", groups=["ops"], device_ids=["router"], command_prefix="show", decision="allow")]
CASES = [dict(subject="u", device_id="router", command="show version", groups=["ops"], expected="allow"),
         dict(subject="u", device_id="router", command="reload", groups=["ops"], expected="deny")]


class PolicyTestingTests(unittest.TestCase):
    def test_allow_and_default_deny_report(self):
        report = run_policy_tests("v", RULES, CASES)
        self.assertEqual(report.failures, ())
        self.assertEqual(report.total, 2)
        self.assertEqual(len(report.rules_digest), 64)
        self.assertEqual(report, run_policy_tests("v", RULES, CASES))

    def test_mismatch_is_identified(self):
        report = run_policy_tests("v", [], CASES)
        self.assertEqual(report.failures, (0,))

    def test_allow_only_suite_and_malformed_cases_rejected(self):
        for cases in ([CASES[0], CASES[0]], [], [{"expected": "allow"}, CASES[1]]):
            with self.assertRaises(ValueError):
                run_policy_tests("v", RULES, cases)

    def test_device_and_group_scope_are_evaluated(self):
        cases = [CASES[0], dict(CASES[0], device_id="other", expected="deny"),
                 dict(CASES[0], groups=[], expected="deny")]
        self.assertEqual(run_policy_tests("v", RULES, cases).failures, ())
