import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock,patch
from tacacs_appliance.install_database import initialize_database


class InstallDatabaseTests(unittest.TestCase):
    def arguments(self):
        return dict(migration_directory=Path('migrations'),aaa_role='aaa',admin_role='admin',
            aaa_password='a'*48,admin_password='b'*48,tenant_id='tenant',name='Local',
            username='operator',password='Operator-password-42!',mfa_reference='secret://mfa/operator')

    def test_migrations_precede_shared_bootstrap_transaction(self):
        connection=Mock();connection.transaction.side_effect=lambda:nullcontext()
        order=[]
        with patch('tacacs_appliance.install_database.migrate',side_effect=lambda *a:order.append('migrate')), \
             patch('tacacs_appliance.install_database.provision_new_login',side_effect=lambda *a,**k:order.append(k['profile'])), \
             patch('tacacs_appliance.install_database.bootstrap_tenant',side_effect=lambda *a,**k:order.append('tenant') or ('user','factor')):
            self.assertEqual(initialize_database(connection,**self.arguments()),('user','factor'))
        self.assertEqual(order,['migrate','aaa','admin','tenant'])
        connection.transaction.assert_called_once()

    def test_shared_role_rejected_before_migration(self):
        args=self.arguments();args['admin_role']='aaa'
        with patch('tacacs_appliance.install_database.migrate') as migrate:
            with self.assertRaises(ValueError):initialize_database(Mock(),**args)
        migrate.assert_not_called()
