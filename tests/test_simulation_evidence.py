"""Stored JSON cannot smuggle raw samples or misleading assessments to API."""
from copy import deepcopy
from dataclasses import asdict
import json
import unittest
from tacacs_appliance.authorization import AuthorizationEngine,AuthorizationRequest,PolicyRule,Decision
from tacacs_appliance.simulation import compare_policies
from tacacs_appliance.simulation_evidence import validate_report


class SimulationEvidenceTests(unittest.TestCase):
    def setUp(self):
        baseline=AuthorizationEngine('default-deny',())
        candidate=AuthorizationEngine('candidate',(PolicyRule('show',frozenset(),frozenset(),'show',Decision.ALLOW),))
        self.report=dict(baseline_version='default-deny',candidate_version='candidate',
            **asdict(compare_policies(baseline,candidate,(AuthorizationRequest('a','d','show'),AuthorizationRequest('a','d','reload')))))

    def check(self,report):
        return validate_report(report,baseline_version='default-deny',candidate_version='candidate',sample_count=2)

    def test_producer_and_json_roundtrip_are_accepted_without_mutation(self):
        original=deepcopy(self.report)
        self.assertIs(self.check(self.report),self.report)
        stored=json.loads(json.dumps(self.report))
        self.assertIs(self.check(stored),stored)
        self.assertEqual(self.report,original)

    def test_extra_fields_at_any_level_never_reach_response(self):
        for target in ('top','comparison','decision'):
            value=deepcopy(self.report)
            mapping=value if target=='top' else value['comparisons'][0] if target=='comparison' else value['comparisons'][0]['candidate']
            mapping['raw_command']='private fixture command'
            with self.assertRaisesRegex(RuntimeError,'evidence unavailable'):self.check(value)

    def test_version_count_coverage_and_boolean_counts_fail_closed(self):
        for changes in ({'candidate_version':'other'},{'baseline_version':'other'},{'total':True},
                        {'total':1},{'unchanged':True},{'coverage':'complete'}):
            with self.assertRaises(RuntimeError):self.check(self.report|changes)

    def test_index_lists_must_match_actual_decision_deltas(self):
        for changes in ({'newly_allowed':[0,0]},{'newly_allowed':[True]},
                        {'newly_allowed':[]},{'newly_denied':[0]},{'unchanged':2}):
            with self.assertRaises(RuntimeError):self.check(self.report|changes)
        value=deepcopy(self.report);value['comparisons'][0]['effect']='unchanged'
        with self.assertRaises(RuntimeError):self.check(value)

    def test_unknown_risk_mfa_or_obligations_are_not_false_security_claims(self):
        for changes in ({'risk':'low'},{'required_mfa':False},{'obligations':[]},
                        {'explanation':'secret input'},{'matched_policy':None},{'decision':'permit'}):
            value=deepcopy(self.report);value['comparisons'][0]['candidate'].update(changes)
            with self.assertRaises(RuntimeError):self.check(value)

    def test_incomplete_or_reordered_comparisons_fail_closed(self):
        value=deepcopy(self.report);value['comparisons']=value['comparisons'][:1]
        with self.assertRaises(RuntimeError):self.check(value)
        value=deepcopy(self.report);value['comparisons'][0]['index']=True
        with self.assertRaises(RuntimeError):self.check(value)
