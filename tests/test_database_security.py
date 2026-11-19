import unittest
from unittest.mock import Mock
from tacacs_appliance.database_security import validate_runtime_role,validate_admin_role


class DatabaseRoleTests(unittest.TestCase):
    def test_admin_profile_rejects_evidence_mutation(self):
        connection=Mock()
        connection.execute.return_value.fetchone.side_effect=[(False,),(False,),(True,)]
        with self.assertRaises(ValueError):validate_admin_role(connection)

    def test_admin_profile_allows_clean_role_without_policy_write_rejection(self):
        connection=Mock()
        connection.execute.return_value.fetchone.return_value=(False,)
        validate_admin_role(connection)
        calls=connection.execute.call_args_list
        self.assertTrue(any(c.args[1]==("schema_migrations","INSERT") for c in calls if len(c.args)>1))
    def test_restricted_role_passes_all_checks(self):
        connection = Mock()
        connection.execute.return_value.fetchone.side_effect = [(False,), (False,), (False,)]
        validate_runtime_role(connection)
        self.assertEqual(connection.execute.call_count, 3)
        self.assertIn('has_any_column_privilege',connection.execute.call_args.args[0])
        self.assertIn('policy_simulation_reports',connection.execute.call_args.args[0])

    def test_admin_profile_rejects_simulation_evidence_column_update(self):
        connection=Mock()
        def execute(*args):
            row=Mock();row.fetchone.return_value=(len(args)>1 and args[1]==('policy_simulation_reports','UPDATE'),)
            return row
        connection.execute.side_effect=execute
        with self.assertRaises(ValueError):validate_admin_role(connection)

    def test_privileged_owner_and_mutation_roles_rejected(self):
        for rows in ([(True,)], [(False,), (True,)], [(False,), (False,), (True,)], [None]):
            connection = Mock()
            connection.execute.return_value.fetchone.side_effect = rows
            with self.assertRaises(ValueError):
                validate_runtime_role(connection)
