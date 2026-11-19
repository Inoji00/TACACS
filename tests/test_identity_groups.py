import unittest
from unittest.mock import MagicMock
from uuid import uuid4
from tacacs_appliance.identity_groups import IdentityGroups


class IdentityGroupManagementTests(unittest.TestCase):
    def test_referenced_group_cannot_be_renamed_or_deleted(self):
        identities=MagicMock();identities.tenant=uuid4()
        db=identities.pool.connection.return_value.__enter__.return_value
        for operation in ('rename','delete'):
            db.reset_mock();db.execute.return_value.fetchone.side_effect=[('ops',),(1,),(0,),(0,)]
            payload=dict(operation=operation,id=str(uuid4()))
            if operation=='rename':payload['name']='renamed'
            with self.assertRaises(ValueError):IdentityGroups(identities).save(str(uuid4()),payload)
            self.assertFalse(any('UPDATE identity_groups' in call.args[0] or 'DELETE FROM identity_groups' in call.args[0] for call in db.execute.call_args_list))
        identities.audit.assert_not_called()

    def test_unused_group_rename_is_tenant_scoped_and_audited(self):
        identities=MagicMock();identities.tenant=uuid4()
        db=identities.pool.connection.return_value.__enter__.return_value
        db.execute.return_value.fetchone.side_effect=[('ops',),(0,),(0,),(0,),None]
        identifier,actor=str(uuid4()),str(uuid4())
        IdentityGroups(identities).save(actor,dict(operation='rename',id=identifier,name='operators'))
        identities._authorize.assert_called_once()
        identities.audit.assert_called_once()
        statement,values=db.execute.call_args.args
        self.assertIn('tenant_id=%s AND id=%s',statement)
        self.assertEqual(values[1],identities.tenant)

