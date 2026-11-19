import unittest
from tacacs_appliance.postgres_policy import decode_rules

class PolicySchemaTests(unittest.TestCase):
    def test_rejects_invalid_decision_duplicate_and_unknown_field(self):
        rule = dict(rule_id="r", groups=["ops"], device_ids=[], command_prefix="show", decision="allow")
        self.assertEqual(decode_rules([rule])[0].rule_id,"r")
        for value in ([rule,rule], [dict(rule,decision="allow-all")], [dict(rule,extra="x")]):
            with self.subTest(value=value), self.assertRaises(ValueError): decode_rules(value)
