from contextlib import nullcontext
import unittest
from unittest.mock import Mock,patch
from tacacs_appliance.mfa_enrollment import confirm_pending_factor
from tacacs_appliance.mfa import totp

ID="00000000-0000-0000-0000-000000000001"


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.connection=Mock();self.connection.transaction.side_effect=lambda:nullcontext()
        self.secret=b"m"*32;self.now=1700000010

    def confirm(self,code):
        return confirm_pending_factor(self.connection,tenant_id=ID,user_id=ID,factor_id=ID,
                                      code=code,resolve_secret=lambda _:self.secret,now=self.now)

    def test_confirm_enables_factor_and_consumes_step_with_audit(self):
        self.connection.execute.return_value.fetchone.side_effect=[(ID,),(ID,),("secret://mfa/pending",False,-1)]
        with patch("tacacs_appliance.mfa_enrollment.PostgresAuditWriter") as writer:
            self.assertTrue(self.confirm(totp(self.secret,self.now)))
        update=self.connection.execute.call_args
        self.assertIn("enabled=TRUE",update.args[0])
        self.assertEqual(update.args[1][0],self.now//30)
        self.assertIs(writer.return_value.append_in_transaction.call_args.args[0],self.connection)

    def test_enabled_factor_cannot_be_reenrolled(self):
        self.connection.execute.return_value.fetchone.side_effect=[(ID,),(ID,),("secret://mfa/pending",True,-1)]
        self.assertFalse(self.confirm(totp(self.secret,self.now)))
        self.assertEqual(self.connection.execute.call_count,3)

    def test_wrong_code_does_not_enable_factor(self):
        self.connection.execute.return_value.fetchone.side_effect=[(ID,),(ID,),("secret://mfa/pending",False,999999999)]
        self.assertFalse(self.confirm("000000"))
        self.assertEqual(self.connection.execute.call_count,3)

    def test_audit_failure_propagates_to_transaction(self):
        self.connection.execute.return_value.fetchone.side_effect=[(ID,),(ID,),("secret://mfa/pending",False,-1)]
        with patch("tacacs_appliance.mfa_enrollment.PostgresAuditWriter") as writer:
            writer.return_value.append_in_transaction.side_effect=OSError("audit failed")
            with self.assertRaises(OSError):self.confirm(totp(self.secret,self.now))
