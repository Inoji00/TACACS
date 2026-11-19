import unittest
from contextlib import nullcontext
from unittest.mock import Mock
from uuid import UUID
from tacacs_appliance.postgres_policy_lifecycle import PostgresPolicyLifecycle

TENANT = "00000000-0000-0000-0000-000000000001"
AUTHOR = "00000000-0000-0000-0000-000000000002"
OTHER = "00000000-0000-0000-0000-000000000003"
VERSION = "00000000-0000-0000-0000-000000000004"


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.pool, self.db, self.audit = Mock(), Mock(), Mock()
        self.pool.connection.side_effect = lambda: nullcontext(self.db)
        self.db.transaction.side_effect = lambda: nullcontext()
        self.lifecycle = PostgresPolicyLifecycle(self.pool, TENANT, self.audit)

    def rows(self, state, approver=None):
        self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), (1,),
            (state, UUID(AUTHOR), UUID(approver) if approver else None, [])]

    def test_list_uses_bounded_tenant_scoped_keyset_pagination(self):
        self.db.execute.return_value.fetchone.side_effect=[(UUID(TENANT),),(1,)]
        self.db.execute.return_value.fetchall.return_value=[(UUID(VERSION),3,'draft',UUID(AUTHOR),None),
            (UUID(OTHER),2,'draft',UUID(AUTHOR),None)]
        result=self.lifecycle.list_versions(AUTHOR,before=4,limit=1)
        self.assertEqual(len(result['items']),1);self.assertEqual(result['next_before'],3)
        self.assertEqual(self.db.execute.call_args.args[1],(UUID(TENANT),4,2))
        self.audit.assert_not_called()

    def test_list_rejects_unbounded_limits_before_database(self):
        for values in ({'limit':101},{'limit':True},{'before':0},{'before':2**63}):
            with self.assertRaises(ValueError):self.lifecycle.list_versions(AUTHOR,**values)
        self.pool.connection.assert_not_called()

    def test_author_cannot_approve(self):
        self.rows("approval")
        with self.assertRaises(PermissionError):
            self.lifecycle.transition(VERSION, AUTHOR, "approve")
        self.audit.assert_not_called()

    def test_inspect_scopes_policy_and_evidence_to_tenant(self):
        self.db.execute.return_value.fetchone.side_effect=[(UUID(TENANT),),(1,),
            (1,"draft",UUID(AUTHOR),None,[],None),None]
        policy=self.lifecycle.inspect(VERSION,OTHER)
        self.assertEqual(policy["version_id"],VERSION)
        self.assertEqual(policy["rules"],[])
        self.assertIsNone(policy["test_report"])
        reads=self.db.execute.call_args_list[-2:]
        for call in reads:self.assertEqual(call.args[1],(UUID(VERSION),UUID(TENANT)))
        self.audit.assert_not_called()

    def test_label_only_test_transition_is_rejected(self):
        with self.assertRaises(ValueError):
            self.lifecycle.transition(VERSION, AUTHOR, "test")
        self.pool.connection.assert_not_called()

    def test_failed_regression_never_updates_state(self):
        from test_policy_testing import CASES
        self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), (1,), ("draft", UUID(AUTHOR), [])]
        with self.assertRaises(ValueError):
            self.lifecycle.test_version(VERSION, AUTHOR, CASES)
        self.assertFalse(any(c.args[0].startswith("UPDATE") for c in self.db.execute.call_args_list))
        self.audit.assert_not_called()

    def test_unapproved_policy_cannot_activate(self):
        self.rows("approval")
        with self.assertRaises(ValueError):
            self.lifecycle.transition(VERSION, OTHER, "activate")
        self.audit.assert_not_called()

    def test_submit_requires_test_state(self):
        self.rows("draft")
        with self.assertRaises(ValueError):
            self.lifecycle.transition(VERSION, AUTHOR, "submit")

    def test_activation_archives_previous_and_audits_same_connection(self):
        from test_policy_testing import RULES, CASES
        from tacacs_appliance.policy_testing import run_policy_tests
        report = run_policy_tests(VERSION, RULES, CASES)
        self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), (1,),
            ("approval", UUID(AUTHOR), UUID(OTHER), RULES),
            (report.rules_digest, report.cases_digest, report.total, CASES, UUID(AUTHOR))]
        self.lifecycle.transition(VERSION, OTHER, "activate")
        updates = [c.args[0] for c in self.db.execute.call_args_list if c.args[0].startswith("UPDATE")]
        self.assertEqual(len(updates), 2)
        self.assertIn("state='archived'", updates[0])
        self.audit.assert_called_once_with(self.db, actor=OTHER, action="policy.activate", target=VERSION)

    def test_submit_without_replayable_evidence_is_rejected(self):
        self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), (1,),
            ("test", UUID(AUTHOR), None, []), None]
        with self.assertRaises(ValueError):
            self.lifecycle.transition(VERSION, AUTHOR, "submit")
        self.audit.assert_not_called()

    def test_modified_report_digest_rejected(self):
        from test_policy_testing import RULES, CASES
        self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), (1,),
            ("approval", UUID(AUTHOR), UUID(OTHER), RULES),
            ("0"*64, "0"*64, 2, CASES, UUID(AUTHOR))]
        with self.assertRaises(ValueError):
            self.lifecycle.transition(VERSION, OTHER, "activate")
        self.audit.assert_not_called()

    def test_missing_permission_fails_before_policy_lookup(self):
        self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), None]
        with self.assertRaises(PermissionError):
            self.lifecycle.transition(VERSION, OTHER, "approve")
        self.assertEqual(self.db.execute.call_count, 2)

    def test_draft_validates_rules_before_database_access(self):
        with self.assertRaises(ValueError):
            self.lifecycle.draft(AUTHOR, [{"bad": "rule"}])
        self.pool.connection.assert_not_called()

    def test_rollback_creates_new_draft_with_source_and_audit(self):
        self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), (1,), ("archived", []), (5,)]
        version = self.lifecycle.rollback_draft(VERSION, AUTHOR)
        self.assertNotEqual(version, VERSION)
        insert = next(call for call in self.db.execute.call_args_list if call.args[0].startswith("INSERT"))
        self.assertIn("'draft'", insert.args[0])
        self.assertEqual(insert.args[1][-1], UUID(VERSION))
        self.assertEqual(insert.args[1][2], 5)
        self.audit.assert_called_once_with(self.db, actor=AUTHOR, action="policy.rollback_draft", target=version)
        self.assertFalse(any(call.args[0].startswith("UPDATE") for call in self.db.execute.call_args_list))

    def test_rollback_rejects_unactivated_or_missing_source(self):
        for row in (None, ("draft", []), ("approval", [])):
            self.db.execute.return_value.fetchone.side_effect = [(UUID(TENANT),), (1,), row]
            with self.assertRaises(ValueError):
                self.lifecycle.rollback_draft(VERSION, AUTHOR)
        self.audit.assert_not_called()
