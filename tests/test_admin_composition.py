from contextlib import nullcontext
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
from tacacs_appliance.admin_composition import LocalReferenceResolver,build_admin_api

ID="00000000-0000-0000-0000-000000000001"


class AdminCompositionTests(unittest.TestCase):
    def test_reference_cannot_become_arbitrary_file_path(self):
        resolver=LocalReferenceResolver({"secret://mfa/admin":Path("protected")})
        with patch("tacacs_appliance.admin_composition.read_secret",return_value=b"m"*32) as reader:
            self.assertEqual(resolver("secret://mfa/admin"),b"m"*32)
            with self.assertRaises(ValueError):resolver("secret://../../other")
            reader.assert_called_once_with(Path("protected"))

    def test_complete_composition_includes_login_policies_and_audit(self):
        pool,connection=Mock(),Mock();pool.connection.side_effect=lambda:nullcontext(connection)
        connection.execute.return_value.fetchone.return_value=(ID,)
        with patch("tacacs_appliance.admin_composition.read_secret",return_value=b"k"*32), \
             patch("tacacs_appliance.admin_composition.validate_schema"), \
             patch("tacacs_appliance.admin_composition.PostgresLocalProvider"), \
             patch("tacacs_appliance.admin_composition.validate_admin_role"):
            app=build_admin_api(pool,tenant_id=ID,origin="https://admin.local",csrf_key_file=Path("csrf"),
                                mfa_references={"secret://mfa/admin":Path("mfa")})
        self.assertIsNotNone(app._login)
        self.assertIsNotNone(app._policies)
        self.assertEqual(app._policies._audit.__self__._tenant,app._sessions._tenant)
        self.assertIsNotNone(app._simulation)
        self.assertIs(app._simulation.pool,pool)
        self.assertEqual(app._simulation.audit.__self__._tenant,app._sessions._tenant)
