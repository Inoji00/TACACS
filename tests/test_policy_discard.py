import unittest
from unittest.mock import MagicMock
from uuid import UUID,uuid4
from tacacs_appliance.postgres_policy_lifecycle import PostgresPolicyLifecycle


class PolicyDiscardTests(unittest.TestCase):
    def test_only_author_unapproved_inactive_versions_can_be_discarded(self):
        tenant,actor,version=uuid4(),uuid4(),uuid4()
        for state,author,approver,error in [('active',actor,None,ValueError),('archived',actor,None,ValueError),('approval',actor,uuid4(),ValueError),('draft',uuid4(),None,PermissionError),('draft',actor,None,None)]:
            pool=MagicMock();db=pool.connection.return_value.__enter__.return_value
            db.execute.return_value.fetchone.side_effect=[(tenant,),(1,),None,(state,author,approver)]
            audit=MagicMock();service=PostgresPolicyLifecycle(pool,str(tenant),audit)
            if error:
                with self.assertRaises(error):service.discard(str(version),str(actor))
                audit.assert_not_called()
            else:
                service.discard(str(version),str(actor))
                audit.assert_called_once()
                self.assertTrue(any('INSERT INTO policy_retirements' in call.args[0] for call in db.execute.call_args_list))
            self.assertFalse(any('DELETE FROM policy_versions' in call.args[0] for call in db.execute.call_args_list))
