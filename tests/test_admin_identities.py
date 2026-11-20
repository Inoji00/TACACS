import unittest
from unittest.mock import MagicMock
from psycopg.errors import ForeignKeyViolation
from tacacs_appliance.admin_identities import AdminIdentities

TENANT='00000000-0000-0000-0000-000000000001'
ACTOR='00000000-0000-0000-0000-000000000002'


class IdentityTests(unittest.TestCase):
    def test_unlock_resets_counter_and_rotates_delegated_session_grant(self):
        connection = self.pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.side_effect = [('operator', True), (True,), (True,)]
        connection.execute.return_value.fetchall.return_value = [('console.read',), ('devices.manage',)]
        with unittest.mock.patch.object(self.service, '_authorize'):
            self.assertEqual(self.service.unlock(ACTOR, TENANT), {'status': 'committed'})
        queries = connection.execute.call_args_list
        rotations = [call.args[1][-1] for call in queries if 'set_device_console_access' in call.args[0]]
        self.assertEqual(rotations, [False, True])
        self.assertIn('SET locked=false,failed_logins=0', queries[-1].args[0])
        self.audit.assert_called_once_with(connection, actor=ACTOR, source='admin-identities',
            action='identity.unlock', target=TENANT, result='success',
            security_context={'target_name': 'operator'})

    def test_unlock_protects_elevated_account_and_does_not_audit_noop(self):
        connection = self.pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.return_value = ('operator', True)
        connection.execute.return_value.fetchall.return_value = [('users.manage',)]
        with unittest.mock.patch.object(self.service, '_authorize'):
            with self.assertRaisesRegex(ValueError, 'identity protected'):
                self.service.unlock(ACTOR, TENANT)
            connection.execute.return_value.fetchone.return_value = ('operator', False)
            connection.execute.return_value.fetchall.return_value = []
            self.assertEqual(self.service.unlock(ACTOR, TENANT), {'status': 'already_unlocked'})
        self.assertFalse(any('UPDATE users' in call.args[0] for call in connection.execute.call_args_list))
        self.audit.assert_not_called()

    def test_delete_revokes_access_and_keeps_referenced_identity(self):
        connection=self.pool.connection.return_value.__enter__.return_value

        def execute(statement, params):
            if statement.startswith('DELETE FROM users'):
                raise ForeignKeyViolation()

        connection.execute.side_effect=execute
        with unittest.mock.patch.object(self.service,'_authorize'),unittest.mock.patch.object(self.service,'_device_user'):
            self.service.delete(ACTOR,TENANT)
        statements=[call.args[0] for call in connection.execute.call_args_list]
        self.assertTrue(any("username=':deleted:' || id::text" in statement and
                            'enabled=false, deleted=true' in statement for statement in statements))
        self.assertTrue(any('DELETE FROM user_groups' in statement for statement in statements))
        self.assertTrue(any('DELETE FROM admin_sessions' in statement for statement in statements))
        self.assertTrue(any('DELETE FROM users' in statement for statement in statements))
        self.audit.assert_called_once()

    def setUp(self):
        self.pool=MagicMock();self.audit=MagicMock()
        self.service=AdminIdentities(self.pool,TENANT,self.audit)

    def test_validation_before_database(self):
        for username,password,group in [('bad user','long-test-password','ops'),('valid','short','ops'),('valid','long-test-password','*')]:
            with self.assertRaises(ValueError):self.service.create(ACTOR,username,password,group)
        self.pool.connection.assert_not_called()

    def test_cannot_disable_self_or_use_non_boolean(self):
        for user,enabled in [(ACTOR,False),(TENANT,1)]:
            with self.assertRaises(ValueError):self.service.set_enabled(ACTOR,user,enabled)
        self.pool.connection.assert_not_called()

    def test_missing_grant_blocks_mutation_and_audit(self):
        connection=self.pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):self.service.set_enabled(ACTOR,TENANT,False)
        self.assertFalse(any('UPDATE users' in call.args[0] for call in connection.execute.call_args_list))
        self.audit.assert_not_called()

    def test_edit_validation_and_self_delete_are_protected(self):
        with self.assertRaises(ValueError):
            self.service.update(ACTOR,TENANT,'valid','1234567','ops',True)
        with self.assertRaises(ValueError):
            self.service.update(ACTOR,TENANT,'bad name','Valid-pass-42!','ops',True)
        connection=self.pool.connection.return_value.__enter__.return_value
        with self.assertRaises(ValueError):self.service._device_user(connection,ACTOR,ACTOR)
        self.assertFalse(any('DELETE' in str(call) for call in connection.execute.call_args_list))

    def test_eight_character_creation_and_update_hash_without_auditing_password(self):
        connection=self.pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.side_effect=[None,(TENANT,)]
        with unittest.mock.patch.object(self.service,'_authorize'):
            self.service.create(ACTOR,'operator','Valid-pass-42!','ops')
        self.assertNotIn('Valid-pass-42!',str(self.audit.call_args))
        self.assertEqual(self.audit.call_args.kwargs['security_context'],
                         {'target_name':'operator','identity_group':'ops'})
        connection.execute.return_value.fetchone.side_effect=[None,(TENANT,)]
        with unittest.mock.patch.object(self.service,'_authorize'),unittest.mock.patch.object(self.service,'_device_user',return_value='old-operator'):
            self.service.update(ACTOR,TENANT,'operator','Valid-pass-42!','ops',False)
        self.assertNotIn('Valid-pass-42!',str(self.audit.call_args))
        self.assertEqual(self.audit.call_args.kwargs['security_context']['previous_name'],'old-operator')
        self.assertIs(self.audit.call_args.kwargs['security_context']['password_changed'],True)
