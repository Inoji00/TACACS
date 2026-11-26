"""Opt-in real PostgreSQL tests isolated in a newly-created private schema."""
import os
import secrets
import socket
import struct
import threading
import tempfile
from contextlib import contextmanager
from pathlib import Path
import unittest
from uuid import uuid4
import psycopg
from psycopg import sql
from argon2 import PasswordHasher
from psycopg_pool import ConnectionPool
from tacacs_appliance.migrations import migrate
from tacacs_appliance.install_database import initialize_database
from tacacs_appliance.postgres_identity import PostgresLocalProvider
from tacacs_appliance.admin_sessions import PostgresAdminSessions
from tacacs_appliance.admin_rbac import PostgresAdminPermissions
from tacacs_appliance.runtime import read_secret
from tacacs_appliance.postgres_audit import PostgresAuditWriter
from tacacs_appliance.postgres_accounting import PostgresAccountingStore
from tacacs_appliance.accounting import AccountingRecord
from tacacs_appliance.postgres_policy_lifecycle import PostgresPolicyLifecycle
from unittest.mock import Mock
from psycopg.conninfo import make_conninfo
from tacacs_appliance.provision_role import provision_aaa_role,provision_admin_role,provision_new_login
from tacacs_appliance.database_security import validate_runtime_role,validate_admin_role
from tacacs_appliance.runtime import RuntimeConfig,build_listener
from tacacs_appliance.server import ListenerConfig
from tacacs_appliance.protocol import Header,Frame,Limits,parse_frame
from tacacs_appliance.obfuscation import xor_body
from psycopg.types.json import Jsonb
from concurrent.futures import ThreadPoolExecutor
from tacacs_appliance.postgres_mfa import PostgresTotpVerifier
from tacacs_appliance.mfa import totp
from tacacs_appliance.postgres_simulation import PostgresPolicySimulation


@unittest.skipUnless(os.environ.get("TACACS_TEST_DSN_FILE"), "real PostgreSQL DSN file not configured")
class PostgresIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = read_secret(Path(os.environ["TACACS_TEST_DSN_FILE"])).decode().strip()
        cls.schema = "tacacs_test_" + uuid4().hex
        cls.owner = psycopg.connect(cls.dsn, autocommit=True, connect_timeout=5)
        cls.pool = None
        try:
            cls.owner.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
            with psycopg.connect(cls.dsn, options=f"-c search_path={cls.schema}") as connection:
                directory = Path(__file__).resolve().parents[1] / "migrations"
                migrate(connection, directory)
                migrate(connection, directory)  # checksum/idempotency against real database
            cls.pool = ConnectionPool(cls.dsn, min_size=1, max_size=2, open=True,
                                      kwargs={"options": f"-c search_path={cls.schema}"})
            cls.pool.wait(timeout=10)
        except BaseException:
            cls.clean()
            raise

    @classmethod
    def clean(cls):
        if cls.pool is not None:
            cls.pool.close()
        # Exact generated identifier, never public schema or operator tables.
        cls.owner.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(cls.schema)))
        cls.owner.close()

    @classmethod
    def tearDownClass(cls):
        cls.clean()

    def provision(self):
        tenant, user = uuid4(), uuid4()
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute("INSERT INTO tenants(id,name) VALUES (%s,%s)", (tenant, str(tenant)))
                connection.execute("INSERT INTO users(id,tenant_id,username,password_hash) VALUES (%s,%s,%s,%s)",
                                   (user, tenant, "admin", PasswordHasher().hash("integration-password")))
        return tenant, user

    def test_accounting_read_filters_cursor_and_restricted_admin(self):
        from tacacs_appliance.admin_accounting import AdminAccounting
        tenant,user=self.provision();other,other_user=self.provision()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'audit.read')",(tenant,user))
        for action in ('start','stop'):
            PostgresAccountingStore(self.pool,str(tenant)).append(AccountingRecord(str(tenant),'session-a','operator','192.0.2.2',action,('secret=hidden',)))
        PostgresAccountingStore(self.pool,str(other)).append(AccountingRecord(str(other),'other-session','operator','192.0.2.2','start',()))
        with self.restricted_pool('admin') as pool:
            service=AdminAccounting(pool,str(tenant))
            first=service.list_events(str(user),username='operator',device='192.0.2.2',session='session-a',limit=1)
            self.assertEqual(len(first['items']),1);self.assertIsNotNone(first['next_before'])
            second=service.list_events(str(user),before=first['next_before'],limit=1)
            self.assertEqual(len(second['items']),1);self.assertNotEqual(first['items'][0]['id'],second['items'][0]['id'])
            self.assertEqual(len(service.list_events(str(user),action='start')['items']),1)
            self.assertNotIn('hidden',str(first));self.assertNotIn('arguments',str(first))
            self.assertEqual(service.list_events(str(user),username="x' OR 1=1 --")['items'],[])
            with self.assertRaises(PermissionError):service.list_events(str(other_user))
            with self.assertRaises(ValueError):service.list_events(str(user),before=str(uuid4()))

    def test_accounting_command_projection_redacts_historical_and_stored_data(self):
        from tacacs_appliance.admin_accounting import AdminAccounting
        tenant,user=self.provision()
        with self.pool.connection() as db:
            db.execute("INSERT INTO admin_grants VALUES (%s,%s,'audit.read')",(tenant,user))
        store=PostgresAccountingStore(self.pool,str(tenant))
        store.append(AccountingRecord(str(tenant),'100','operator','192.0.2.2','stop',
            ('service=shell','cmd=show','cmd-arg=version','task_id=task-42','priv-lvl=15')))
        store.append(AccountingRecord(str(tenant),'101','operator','192.0.2.2','stop',
            ('cmd=test','cmd-arg=aaa','cmd-arg=group LAB user NEVER-LEAK legacy')))
        # Legacy rows may predate redaction fixes: the API must redact again.
        from psycopg.types.json import Jsonb
        with self.pool.connection() as db:
            db.execute("INSERT INTO accounting_records(id,tenant_id,session_id,username,device_id,action,arguments) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (uuid4(),tenant,'102','operator','192.0.2.2','stop',Jsonb(['cmd=test aaa group LAB user HISTORICAL-LEAK legacy'])))
        with self.restricted_pool('admin') as pool:
            page=AdminAccounting(pool,str(tenant)).list_events(str(user),device='192.0.2.2')
            self.assertEqual(len(page['items']),3)
            rows={row['session']:row for row in page['items']}
            self.assertEqual(rows['100']['command'],'show version')
            self.assertEqual(rows['100']['task_id'],'task-42')
            self.assertEqual(rows['100']['privilege'],15)
            for session in ('101','102'):
                self.assertTrue(rows[session]['redacted']);self.assertIsNone(rows[session]['command'])
            self.assertNotIn('LEAK',str(page));self.assertNotIn('arguments',str(page))
            with pool.connection() as db:
                for privilege in ('INSERT','UPDATE','DELETE','TRUNCATE'):
                    function='has_any_column_privilege' if privilege in ('INSERT','UPDATE') else 'has_table_privilege'
                    self.assertFalse(db.execute("SELECT "+function+"(current_user,'accounting_records',%s)",(privilege,)).fetchone()[0])

    def test_device_authentication_leaves_web_only_identity_unchanged(self):
        tenant, user = self.provision()
        with self.pool.connection() as db:
            username, failures, locked = db.execute(
                "SELECT username,failed_logins,locked FROM users WHERE tenant_id=%s AND id=%s",
                (tenant, user),
            ).fetchone()
        with self.restricted_pool("aaa") as pool:
            provider = PostgresLocalProvider(
                pool, str(tenant), lockout_after=4, require_device_group=True
            )
            self.assertFalse(provider.authenticate(username, "Invalid-test-42!").authenticated)
        with self.pool.connection() as db:
            self.assertEqual(
                db.execute("SELECT failed_logins,locked FROM users WHERE tenant_id=%s AND id=%s",
                           (tenant, user)).fetchone(),
                (failures, locked),
            )

    def test_unknown_authentication_username_reaches_logs_without_password(self):
        import contextlib,io
        from tacacs_appliance.aaa_events import AaaEvents,ObservedRouter
        from tacacs_appliance.router import TacacsRouter
        from tacacs_appliance.tacacs_handler import TacacsAuthenticationHandler
        from tacacs_appliance.authentication_service import AuthenticationService
        from tacacs_appliance.postgres_identity import PostgresLocalProvider
        from tacacs_appliance.secrets import StaticDeviceSecretProvider
        from tacacs_appliance.protocol import Frame,Header,parse_frame
        from tacacs_appliance.obfuscation import xor_body
        from tacacs_appliance.admin_logs import AdminLogs
        tenant,user=self.provision()
        with self.pool.connection() as db:db.execute("INSERT INTO admin_grants VALUES (%s,%s,'audit.read')",(tenant,user))
        secret=b'a'*32;keys=StaticDeviceSecretProvider({'192.0.2.2':secret})
        with self.restricted_pool('aaa') as aaa_pool,self.restricted_pool('admin') as admin_pool:
            provider=PostgresLocalProvider(aaa_pool,str(tenant))
            router=ObservedRouter(TacacsRouter(TacacsAuthenticationHandler(keys,AuthenticationService(provider)),lambda *a:None,lambda *a:None),keys,AaaEvents(aaa_pool,str(tenant))).new_connection()
            name=b'nonexistent-test-user';password=b'NEVER-LOG-PASSWORD'
            bodies=[(1,bytes((1,1,1,1,len(name),0,0,0))+name,5),(3,len(password).to_bytes(2,'big')+b'\0\0\0'+password,2)]
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                for sequence,body,status in bodies:
                    frame=Frame(Header(0xc0,1,sequence,0,123,len(body)),body)
                    response=parse_frame(router('192.0.2.2',Frame(frame.header,xor_body(frame,secret))))
                    self.assertEqual(xor_body(response,secret)[0],status)
            self.assertNotIn(password.decode(),output.getvalue())
            page=AdminLogs(admin_pool,str(tenant)).read(str(user),kind='aaa',search=name.decode())
            self.assertEqual(len(page['items']),2)
            self.assertEqual({r['result'] for r in page['items']},{'challenge','fail'})
            for row in page['items']:
                self.assertEqual(row['attempted_username'],name.decode());self.assertEqual(row['actor'],'device')
                self.assertNotIn('security_context',row)
            self.assertNotIn(password.decode(),str(page))
        with self.pool.connection() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM users WHERE tenant_id=%s AND username=%s',(tenant,name.decode())).fetchone())
        self.assertTrue(PostgresAuditWriter(self.pool,str(tenant)).verify())

    def test_logging_reports_are_tenant_scoped_filtered_and_redacted(self):
        from tacacs_appliance.admin_logs import AdminLogs
        tenant,user=self.provision();other,other_user=self.provision()
        with self.pool.connection() as db:db.execute("INSERT INTO admin_grants VALUES (%s,%s,'audit.read')",(tenant,user))
        writer=PostgresAuditWriter(self.pool,str(tenant))
        for result in ('challenge','pass','error'):
            writer.append(actor='device',source='tacacs',action='aaa.authentication',target='192.0.2.2',result=result,session_id='42',security_context={'secret':'never-return'})
        writer.append(actor=str(user),source='admin-policy',action='policy.create',target='draft',result='success')
        PostgresAccountingStore(self.pool,str(tenant)).append(AccountingRecord(str(tenant),'42','operator','192.0.2.2','start',('secret=never-return',)))
        PostgresAuditWriter(self.pool,str(other)).append(actor='device',source='tacacs',action='aaa.authentication',target='192.0.2.99',result='pass')
        with self.restricted_pool('admin') as pool:
            service=AdminLogs(pool,str(tenant))
            page=service.read(str(user),kind='aaa',device='192.0.2.2',session='42',limit=1)
            self.assertEqual(len(page['items']),1);self.assertIsNotNone(page['next_before'])
            second=service.read(str(user),kind='aaa',before=page['next_before'],limit=1,since=page['window']['since'],until=page['window']['until'])
            self.assertNotEqual(page['items'][0]['event_id'],second['items'][0]['event_id'])
            activity=service.read(str(user),kind='activity')['items']
            self.assertEqual(len(activity),1);self.assertEqual(activity[0]['actor_name'],'admin')
            self.assertEqual(len(service.read(str(user),kind='issues')['items']),1)
            self.assertEqual(service.read(str(user),search="x' OR 1=1 --")['items'],[])
            self.assertEqual(service.read(str(user),search='%')['items'],[])
            report=service.read(str(user),report=True)
            self.assertEqual((report['total'],report['aaa_events'],report['issues']),(5,3,1))
            self.assertEqual(sum(row['count'] for row in report['breakdown']),5)
            self.assertNotIn('192.0.2.99',str(report));self.assertNotIn('never-return',str(page))
            self.assertEqual(len(service.read(str(user),actor='device')['items']),3)
            with self.assertRaises(PermissionError):service.read(str(other_user))

    def test_removing_identity_preserves_policy_author_and_releases_username(self):
        from tacacs_appliance.admin_identities import AdminIdentities
        from tacacs_appliance.admin_inventory import AdminInventory
        tenant,actor=self.provision()
        with self.pool.connection() as db:db.execute("INSERT INTO admin_grants VALUES (%s,%s,'users.manage')",(tenant,actor))
        with self.restricted_pool('admin') as pool:
            writer=PostgresAuditWriter(pool,str(tenant));manager=AdminIdentities(pool,str(tenant),writer.append_in_transaction)
            user=manager.create(str(actor),'history-user','First-test-42!','ops')['id']
            version=uuid4()
            with self.pool.connection() as db:db.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,1,'draft',%s,'[]')",(version,tenant,user))
            manager.delete(str(actor),user)
            self.assertFalse(any(row['id']==user for row in manager.list_users(str(actor))['users']))
            self.assertFalse(any(row['id']==user for row in AdminInventory(pool,str(tenant)).read()['users']))
            self.assertFalse(PostgresLocalProvider(pool,str(tenant)).authenticate('history-user','First-test-42!').authenticated)
            with pool.connection() as db:
                self.assertEqual(db.execute('SELECT enabled,deleted FROM users WHERE id=%s',(user,)).fetchone(),(False,True))
                self.assertEqual(str(db.execute('SELECT author_id FROM policy_versions WHERE id=%s',(version,)).fetchone()[0]),user)
            replacement=manager.create(str(actor),'history-user','Second-test-42!','ops')['id']
            self.assertNotEqual(replacement,user)
            self.assertFalse(PostgresLocalProvider(pool,str(tenant)).authenticate('history-user','First-test-42!').authenticated)
            self.assertTrue(PostgresLocalProvider(pool,str(tenant)).authenticate('history-user','Second-test-42!').authenticated)
            manager.delete(str(actor),replacement)
            with pool.connection() as db:
                self.assertIsNone(db.execute('SELECT id FROM users WHERE id=%s',(replacement,)).fetchone())
            with self.assertRaises(ValueError):manager.set_enabled(str(actor),user,True)
            self.assertTrue(writer.verify())

    def test_device_removal_group_management_and_restore_secret_constraints(self):
        from tacacs_appliance.device_registry import DeviceRegistry
        from tacacs_appliance.admin_identities import AdminIdentities
        from tacacs_appliance.identity_groups import IdentityGroups
        tenant,actor=self.provision()
        with self.pool.connection() as db:
            for permission in ('users.manage','devices.manage'):db.execute('INSERT INTO admin_grants VALUES (%s,%s,%s)',(tenant,actor,permission))
        with self.restricted_pool('admin') as pool:
            writer=PostgresAuditWriter(pool,str(tenant));groups=IdentityGroups(AdminIdentities(pool,str(tenant),writer.append_in_transaction))
            group=groups.save(str(actor),dict(operation='create',name='ops'))['id']
            groups.save(str(actor),dict(operation='rename',id=group,name='operators'))
            registry=DeviceRegistry(pool,str(tenant),secrets.token_bytes(32))
            payload=dict(address='192.0.2.12',name='SW',enabled=True,secret='A'*32,shell_group='operators',privilege=1)
            registry.save(str(actor),payload,writer.append_in_transaction)
            with self.assertRaises(ValueError):registry.delete(str(actor),'192.0.2.12',writer.append_in_transaction)
            with self.assertRaises(ValueError):groups.save(str(actor),dict(operation='delete',id=group))
            registry.save(str(actor),dict(payload,enabled=False),writer.append_in_transaction)
            def fail(*args,**kwargs):raise RuntimeError('audit unavailable')
            with self.assertRaises(RuntimeError):registry.delete(str(actor),'192.0.2.12',fail)
            self.assertEqual(len(registry.list_devices()['devices']),1)
            registry.delete(str(actor),'192.0.2.12',writer.append_in_transaction)
            self.assertEqual(registry.list_devices()['devices'],[])
            self.assertFalse(registry.source_state('192.0.2.12'))
            groups.save(str(actor),dict(operation='delete',id=group))
            with self.assertRaises(ValueError):registry.save(str(actor),dict(payload,secret='',shell_group=''),writer.append_in_transaction)
            with self.assertRaises(ValueError):registry.save(str(actor),dict(payload,shell_group=''),writer.append_in_transaction)
            registry.save(str(actor),dict(payload,secret='B'*32,shell_group=''),writer.append_in_transaction)
            self.assertTrue(registry.source_state('192.0.2.12'))
            self.assertTrue(writer.verify())

    def test_policy_discard_keeps_history_hides_list_and_rolls_back_on_audit_failure(self):
        tenant,actor=self.provision()
        with self.pool.connection() as db:
            for permission in ("policy.draft","console.read"):db.execute("INSERT INTO admin_grants VALUES (%s,%s,%s)",(tenant,actor,permission))
        with self.restricted_pool('admin') as pool:
            writer=PostgresAuditWriter(pool,str(tenant));service=PostgresPolicyLifecycle(pool,str(tenant),writer.policy_callback)
            rules=[dict(rule_id='show',groups=[],device_ids=[],command_prefix='show',decision='allow')]
            version=service.draft(str(actor),rules)
            service.discard(version,str(actor))
            self.assertNotIn(version,[row['version_id'] for row in service.list_versions(str(actor))['items']])
            with self.assertRaises(ValueError):service.transition(version,str(actor),'submit')
            with pool.connection() as db:
                self.assertEqual(db.execute('SELECT state FROM policy_versions WHERE id=%s',(version,)).fetchone()[0],'draft')
                with self.assertRaises(psycopg.Error):db.execute("UPDATE policy_versions SET state='test' WHERE id=%s",(version,))
                db.rollback()
            remaining=service.draft(str(actor),rules)
            def fail(*args,**kwargs):raise RuntimeError('audit failed')
            service._audit=fail
            with self.assertRaises(RuntimeError):service.discard(remaining,str(actor))
            self.assertIn(remaining,[row['version_id'] for row in service.list_versions(str(actor))['items']])
            self.assertTrue(writer.verify())

    def test_switch_admin_readonly_conflict_and_user_access_projection(self):
        from tacacs_appliance.device_registry import DeviceRegistry
        from tacacs_appliance.postgres_authorization import PostgresAuthorizationService
        from tacacs_appliance.admin_identities import AdminIdentities
        tenant,actor=self.provision();admin_group,reader_group=uuid4(),uuid4()
        with self.pool.connection() as db:
            for permission in ('devices.manage','users.manage'):db.execute('INSERT INTO admin_grants VALUES (%s,%s,%s)',(tenant,actor,permission))
            for group,name in ((admin_group,'admins'),(reader_group,'readers')):db.execute('INSERT INTO identity_groups VALUES (%s,%s,%s)',(group,tenant,name))
            db.execute('INSERT INTO user_groups VALUES (%s,%s,%s)',(tenant,actor,admin_group))
        with self.restricted_pool('admin') as admin_pool,self.restricted_pool('aaa') as aaa_pool:
            audit=PostgresAuditWriter(admin_pool,str(tenant));registry=DeviceRegistry(admin_pool,str(tenant),secrets.token_bytes(32))
            mappings=[dict(group='admins',privilege=15,mode='policy'),dict(group='readers',privilege=1,mode='read_only')]
            payload=dict(address='192.0.2.22',name='SW',enabled=True,secret='A'*32,shell_group='',privilege=1,access_mappings=mappings)
            registry.save(str(actor),payload,audit.append_in_transaction)
            service=PostgresAuthorizationService(aaa_pool,str(tenant))
            self.assertEqual(service.authorize_shell('admin','192.0.2.22'),('service=shell','priv-lvl=15'))
            with self.pool.connection() as db:
                db.execute('DELETE FROM user_groups WHERE tenant_id=%s AND user_id=%s',(tenant,actor))
                db.execute('INSERT INTO user_groups VALUES (%s,%s,%s)',(tenant,actor,reader_group))
            self.assertEqual(service.authorize_shell('admin','192.0.2.22'),('service=shell','priv-lvl=1'))
            self.assertEqual(service.authorize('admin','192.0.2.22','configure terminal').decision.value,'deny')
            with self.pool.connection() as db:db.execute('INSERT INTO user_groups VALUES (%s,%s,%s)',(tenant,actor,admin_group))
            self.assertEqual(service.authorize_shell('admin','192.0.2.22'),())
            page=AdminIdentities(admin_pool,str(tenant),audit.append_in_transaction).list_users(str(actor))
            summary=next(user for user in page['users'] if user['id']==str(actor))
            self.assertEqual(summary['switch_access']['items'][0]['state'],'conflict')
            self.assertIn('users.manage',summary['console_permissions'])
            self.assertTrue(audit.verify())

    def test_device_group_hierarchy_assignment_constraints_and_audit_rollback(self):
        from tacacs_appliance.device_groups import DeviceGroups
        from tacacs_appliance.device_registry import DeviceRegistry
        tenant,actor=self.provision()
        other,_=self.provision()
        with self.pool.connection() as db:db.execute("INSERT INTO admin_grants VALUES (%s,%s,'devices.manage')",(tenant,actor))
        with self.restricted_pool('admin') as pool:
            groups=DeviceGroups(pool,tenant);audit=PostgresAuditWriter(pool,str(tenant))
            template=dict(operation='save',id=None,kind='location',name='HCM',description='Site',parent_id=None)
            root=groups.save(str(actor),template,audit.append_in_transaction)['id']
            child=groups.save(str(actor),dict(template,name='DC',parent_id=root),audit.append_in_transaction)['id']
            typ=groups.save(str(actor),dict(template,kind='device_type',name='Switch'),audit.append_in_transaction)['id']
            with self.assertRaises(ValueError):groups.save(str(actor),dict(template,id=root,parent_id=child),audit.append_in_transaction)
            with self.assertRaises(ValueError):groups.save(str(actor),dict(template,parent_id=typ),audit.append_in_transaction)
            with self.assertRaises(PermissionError):DeviceGroups(pool,other).save(str(actor),template,audit.append_in_transaction)
            registry=DeviceRegistry(pool,str(tenant),secrets.token_bytes(32))
            device=dict(address='192.0.2.32',name='SW',enabled=True,secret='A'*32,shell_group='',privilege=1,description='Lab',location_id=child,device_type_id=typ)
            registry.save(str(actor),device,audit.append_in_transaction)
            self.assertEqual(registry.list_devices()['devices'][0]['location_id'],child)
            with self.assertRaises(ValueError):registry.save(str(actor),dict(device,location_id=typ),audit.append_in_transaction)
            with self.assertRaises(ValueError):groups.save(str(actor),dict(operation='delete',id=child),audit.append_in_transaction)
            def fail(*args,**kwargs):raise RuntimeError('audit unavailable')
            with self.assertRaises(RuntimeError):groups.save(str(actor),dict(template,name='rollback'),fail)
            self.assertEqual(len(groups.list()['groups']),3)
            registry.save(str(actor),dict(device,location_id=None),audit.append_in_transaction)
            groups.save(str(actor),dict(operation='delete',id=child),audit.append_in_transaction)
            self.assertTrue(audit.verify())

    def test_dashboard_aggregates_tenant_events_without_challenges_or_other_tenants(self):
        from tacacs_appliance.admin_dashboard import AdminDashboard
        tenant,actor=self.provision()
        other,_=self.provision()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'audit.read')",(tenant,actor))
        audit=PostgresAuditWriter(self.pool,str(tenant))
        for result in ('challenge','pass','fail'):
            audit.append(actor='device',source='tacacs',action='aaa.authentication',target='192.0.2.2',result=result)
        for index in range(6):
            audit.append(actor='device',source='tacacs',action='aaa.authentication',target='192.0.2.2',
                         result='fail',security_context={'attempted_username':f'lab-{index}'})
        audit.append(actor='device',source='tacacs',action='aaa.authentication',target='192.0.2.4',
                     result='fail',security_context={'attempted_username':'lab-0'})
        PostgresAuditWriter(self.pool,str(other)).append(actor='device',source='tacacs',action='aaa.authentication',target='192.0.2.3',result='fail')
        with self.restricted_pool('admin') as pool:
            data=AdminDashboard(pool,str(tenant)).read(str(actor))
            self.assertEqual(sum(row['count'] for row in data['activity'] if row['result']=='pass'),1)
            self.assertEqual(data['failures'][0]['count'],1)
            self.assertEqual(data['failures'][0]['device'],'192.0.2.2')
            self.assertEqual(len(data['failures']),5)
            self.assertEqual(data['failure_summary'],dict(total=8,users=6,source_ips=2))
            with self.assertRaises(PermissionError):AdminDashboard(pool,str(other)).read(str(actor))

    def test_live_device_registry_encryption_rotation_disable_shell_and_audit_rollback(self):
        from tacacs_appliance.device_registry import DeviceRegistry
        from tacacs_appliance.secrets import SecretNotFoundError
        from tacacs_appliance.postgres_authorization import PostgresAuthorizationService
        tenant,actor=self.provision()
        group=uuid4()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'devices.manage')",(tenant,actor))
            connection.execute('INSERT INTO identity_groups VALUES (%s,%s,%s)',(group,tenant,'operators'))
            connection.execute('INSERT INTO user_groups VALUES (%s,%s,%s)',(tenant,actor,group))
        key=secrets.token_bytes(32)
        payload=dict(address='192.0.2.42',name='lab-switch',enabled=True,secret='A'*14,shell_group='operators',privilege=1)
        with self.restricted_pool('admin') as admin_pool,self.restricted_pool('aaa') as aaa_pool:
            audit=PostgresAuditWriter(admin_pool,str(tenant))
            registry=DeviceRegistry(admin_pool,str(tenant),key)
            runtime=DeviceRegistry(aaa_pool,str(tenant),key,observe_runtime=True)
            registry.save(str(actor),payload,audit.append_in_transaction)
            self.assertEqual(registry.list_devices()['devices'][0]['runtime_state'],'pending')
            self.assertTrue(runtime.source_state('192.0.2.42'))
            self.assertEqual(registry.list_devices()['devices'][0]['runtime_state'],'observed')
            self.assertEqual(runtime.resolve('192.0.2.42'),b'A'*14)
            self.assertNotIn('A'*14,str(registry.list_devices()))
            service=PostgresAuthorizationService(aaa_pool,str(tenant))
            self.assertEqual(service.authorize_shell('admin','192.0.2.42'),('service=shell','priv-lvl=1'))
            self.assertEqual(service.authorize_shell('unknown','192.0.2.42'),())
            registry.save(str(actor),dict(payload,secret='B'*32),audit.append_in_transaction)
            self.assertEqual(registry.list_devices()['devices'][0]['revision'],2)
            self.assertEqual(registry.list_devices()['devices'][0]['runtime_state'],'pending')
            self.assertEqual(runtime.resolve('192.0.2.42'),b'B'*32)
            with self.assertRaises(ValueError):registry.save(str(actor),dict(payload,address='192.0.2.43',secret='B'*32),audit.append_in_transaction)
            def fail(*args,**kwargs):raise RuntimeError('audit failed')
            with self.assertRaises(RuntimeError):registry.save(str(actor),dict(payload,secret='C'*32),fail)
            self.assertEqual(runtime.resolve('192.0.2.42'),b'B'*32)
            registry.save(str(actor),dict(payload,enabled=False,secret=''),audit.append_in_transaction)
            self.assertFalse(runtime.source_state('192.0.2.42'))
            observation=registry.list_devices()['devices'][0]
            self.assertEqual(observation['runtime_state'],'observed')
            with aaa_pool.connection() as connection:
                connection.execute('INSERT INTO device_runtime_observations(tenant_id,address,revision) VALUES (%s,%s,1) '
                    'ON CONFLICT (tenant_id,address) DO UPDATE SET revision=EXCLUDED.revision '
                    'WHERE device_runtime_observations.revision<=EXCLUDED.revision',(tenant,'192.0.2.42'))
            self.assertEqual(registry.list_devices()['devices'][0]['runtime_revision'],observation['revision'])
            with admin_pool.connection() as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute('UPDATE device_runtime_observations SET revision=1 WHERE tenant_id=%s',(tenant,))
                connection.rollback()
            with self.assertRaises(SecretNotFoundError):runtime.resolve('192.0.2.42')
            self.assertEqual(service.authorize_shell('admin','192.0.2.42'),())
            registry.save(str(actor),dict(payload,address='192.0.2.43',name='edge_100',secret='D'*32),audit.append_in_transaction)
            first=registry.list_devices(limit=1)
            self.assertEqual(first['next_after'],'192.0.2.42')
            self.assertEqual(registry.list_devices(after=first['next_after'],limit=1)['devices'][0]['address'],'192.0.2.43')
            self.assertEqual(len(registry.list_devices(search='_')['devices']),1)
            self.assertEqual(registry.list_devices(search='%')['devices'],[])
            self.assertEqual(DeviceRegistry(admin_pool,str(uuid4()),key).list_devices()['devices'],[])
            with self.assertRaises(PermissionError):DeviceRegistry(admin_pool,str(uuid4()),key).save(str(actor),payload,audit.append_in_transaction)
            with aaa_pool.connection() as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute('UPDATE network_devices SET enabled=true WHERE tenant_id=%s',(tenant,))
                connection.rollback()
            self.assertTrue(audit.verify())

    def test_device_identity_management_audit_rollback_and_tenant_boundaries(self):
        from tacacs_appliance.admin_identities import AdminIdentities
        tenant,actor=self.provision()
        other_tenant,other_user=self.provision()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'users.manage')",(tenant,actor))
        with self.restricted_pool('admin') as pool:
            audit=PostgresAuditWriter(pool,str(tenant))
            manager=AdminIdentities(pool,str(tenant),audit.append_in_transaction)
            user=manager.create(str(actor),'switch-operator','Device-test-42!','operators')['id']
            self.assertTrue(PostgresLocalProvider(pool,str(tenant)).authenticate('switch-operator','Device-test-42!').authenticated)
            with self.assertRaises(ValueError):manager.create(str(actor),'switch-operator','Other-test-42!','operators')
            manager.set_enabled(str(actor),user,False)
            self.assertFalse(PostgresLocalProvider(pool,str(tenant)).authenticate('switch-operator','Device-test-42!').authenticated)
            with self.assertRaises(ValueError):manager.set_enabled(str(actor),str(other_user),False)
            with self.assertRaises(ValueError):manager.set_enabled(str(actor),str(actor),False)
            with self.assertRaises(PermissionError):manager.create(str(other_user),'forged','Device-test-42!','operators')
            def fail(*args,**kwargs):raise RuntimeError('audit failure')
            with self.assertRaises(RuntimeError):AdminIdentities(pool,str(tenant),fail).create(str(actor),'rolled-back','Device-test-42!','operators')
            with pool.connection() as connection:
                self.assertIsNone(connection.execute('SELECT id FROM users WHERE tenant_id=%s AND username=%s',(tenant,'rolled-back')).fetchone())
                self.assertIsNone(connection.execute('SELECT 1 FROM admin_grants WHERE tenant_id=%s AND user_id=%s',(tenant,user)).fetchone())
            self.assertTrue(audit.verify())

    def test_user_edit_delete_and_audit_with_restricted_role(self):
        from tacacs_appliance.admin_identities import AdminIdentities
        tenant,actor=self.provision()
        other_tenant,other_actor=self.provision()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'users.manage')",(tenant,actor))
        with self.restricted_pool('admin') as pool:
            audit=PostgresAuditWriter(pool,str(tenant))
            manager=AdminIdentities(pool,str(tenant),audit.append_in_transaction)
            user=manager.create(str(actor),'edit-lab','First-test-42!','ops')['id']
            listed=manager.list_users(str(actor))
            self.assertTrue(any(row['id']==user and row['groups']==['ops'] for row in listed['users']))
            manager.update(str(actor),user,'renamed-lab','Changed-test-42!','new-ops',True)
            self.assertTrue(PostgresLocalProvider(pool,str(tenant)).authenticate('renamed-lab','Changed-test-42!').authenticated)
            with self.assertRaises(ValueError):
                manager.update(str(actor),str(other_actor),'forged','Changed-test-42!','ops',True)
            with self.assertRaises(ValueError):manager.delete(str(actor),str(actor))
            def fail(*args,**kwargs):raise RuntimeError('audit unavailable')
            with self.assertRaises(RuntimeError):
                AdminIdentities(pool,str(tenant),fail).delete(str(actor),user)
            self.assertTrue(any(row['id']==user for row in manager.list_users(str(actor))['users']))
            manager.delete(str(actor),user)
            self.assertFalse(any(row['id']==user for row in manager.list_users(str(actor))['users']))
            self.assertTrue(audit.verify())

    def test_console_delegation_uses_restricted_role_and_revokes_sessions(self):
        from tacacs_appliance.admin_identities import AdminIdentities, IdentityProtectedError
        from tacacs_appliance.local_password_sessions import LocalPasswordSessions
        tenant,actor=self.provision()
        _,other_user=self.provision()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants(tenant_id,user_id,permission) VALUES (%s,%s,'users.manage')",
                               (tenant,actor))
        with self.restricted_pool('admin') as pool:
            writer=PostgresAuditWriter(pool,str(tenant))
            manager=AdminIdentities(pool,str(tenant),writer.append_in_transaction)
            user=manager.create(str(actor),'delegation-lab','First-test-42!','ops')['id']
            permissions=PostgresAdminPermissions(pool,str(tenant))
            sessions=LocalPasswordSessions(pool,str(tenant))
            self.assertFalse(permissions(user,'console.read'))
            with self.assertRaises(IdentityProtectedError):
                manager.set_console_access(str(actor),str(other_user),True)
            failing=AdminIdentities(pool,str(tenant),Mock(side_effect=RuntimeError('audit unavailable')))
            with self.assertRaises(RuntimeError):
                failing.set_console_access(str(actor),user,True)
            self.assertFalse(permissions(user,'console.read'))
            manager.set_console_access(str(actor),user,True)
            self.assertTrue(permissions.device_operator(user))
            self.assertFalse(permissions(user,'users.manage'))
            token=sessions.create_password_only(user)
            manager.set_console_access(str(actor),user,False)
            self.assertFalse(permissions(user,'console.read'))
            manager.set_console_access(str(actor),user,True)
            self.assertIsNone(sessions.resolve(token))
            self.assertTrue(writer.verify())

    def test_device_console_scope_is_enforced_with_restricted_database_role(self):
        from tacacs_appliance.admin_identities import AdminIdentities
        from tacacs_appliance.device_groups import DeviceGroups
        from tacacs_appliance.device_registry import DeviceRegistry
        from tacacs_appliance.local_password_sessions import LocalPasswordSessions

        tenant,admin=self.provision()
        admin=str(admin)
        with self.pool.connection() as db:
            db.execute("INSERT INTO admin_grants(tenant_id,user_id,permission) VALUES (%s,%s,'users.manage'),(%s,%s,'devices.manage')",
                       (tenant,admin,tenant,admin))
        with self.restricted_pool('admin') as pool:
            writer=PostgresAuditWriter(pool,str(tenant))
            audit=writer.append_in_transaction
            identities=AdminIdentities(pool,str(tenant),audit)
            operator=identities.create(admin,'scoped-operator','First-test-42!','ops')['id']
            groups=DeviceGroups(pool,tenant)
            location=groups.save(admin,dict(operation='save',id=None,kind='location',name='HQ',description='',parent_id=None),audit)['id']
            child=groups.save(admin,dict(operation='save',id=None,kind='location',name='Branch',description='',parent_id=location),audit)['id']
            kind=groups.save(admin,dict(operation='save',id=None,kind='device_type',name='Switch',description='',parent_id=None),audit)['id']
            registry=DeviceRegistry(pool,str(tenant),b'k'*32)
            allowed=dict(address='192.0.2.2',name='hq',enabled=False,secret='s'*32,shell_group='',privilege=1,location_id=location,device_type_id=kind)
            registry.save(admin,allowed,audit)
            registry.save(admin,dict(allowed,address='192.0.2.3',secret='t'*32,location_id=child),audit)
            registry.save(admin,dict(allowed,address='192.0.2.4',secret='u'*32,device_type_id=None),audit)
            scope=dict(location_id=location,device_type_id=kind,actions=['edit','reveal_secret'])
            identities.set_console_access(admin,operator,True,scope)
            sessions=LocalPasswordSessions(pool,str(tenant))
            token=sessions.create_password_only(operator)
            with self.pool.connection() as db:
                db.execute('UPDATE users SET locked=true,failed_logins=5 WHERE tenant_id=%s AND id=%s',
                           (tenant,operator))
            self.assertEqual(identities.unlock(admin,operator), {'status':'committed'})
            self.assertIsNone(sessions.resolve(token))
            self.assertEqual(identities.unlock(admin,operator), {'status':'already_unlocked'})
            token=sessions.create_password_only(operator)
            self.assertEqual([r['address'] for r in registry.list_devices(actor=operator)['devices']],['192.0.2.2'])
            self.assertTrue(groups.list(actor=operator)['read_only'])
            registry.save(operator,dict(allowed,name='new name',secret=''),audit)
            self.assertEqual(registry.reveal_secret(operator,allowed['address'],audit,password='First-test-42!'),{'secret':'s'*32})
            with self.assertRaises(PermissionError):registry.reveal_secret(operator,'192.0.2.3',audit,password='First-test-42!')
            with self.assertRaises(PermissionError):registry.save(operator,dict(allowed,location_id=child,secret=''),audit)
            with self.assertRaises(PermissionError):registry.delete(operator,allowed['address'],audit)
            with self.assertRaises(PermissionError):groups.save(operator,dict(operation='delete',id=child),audit)
            identities.set_console_access(admin,operator,True,dict(scope,actions=[]))
            self.assertIsNone(sessions.resolve(token))
            with self.assertRaises(PermissionError):registry.reveal_secret(operator,allowed['address'],audit,password='First-test-42!')
            creation=dict(scope,actions=['create'],creation_addresses=['192.0.2.5'])
            identities.set_console_access(admin,operator,True,creation)
            new=dict(allowed,operation='create',address='192.0.2.5',secret='v'*32)
            with self.assertRaises(PermissionError):
                registry.save(operator,dict(new,address='192.0.2.6'),audit)
            registry.save(operator,new,audit)
            self.assertEqual([r['address'] for r in registry.list_devices(actor=operator)['devices']],
                             ['192.0.2.2','192.0.2.5'])
            from tacacs_appliance.admin_logs import AdminLogs
            from tacacs_appliance.admin_accounting import AdminAccounting

            logs, accounting = AdminLogs(pool, str(tenant)), AdminAccounting(pool, str(tenant))
            with self.assertRaises(PermissionError):
                logs.read(operator, kind='aaa')
            with self.assertRaises(PermissionError):
                accounting.list_events(operator)
            identities.set_console_access(admin, operator, True, dict(scope, actions=['view_aaa_logs']))
            for address in ('192.0.2.2', '192.0.2.3', '192.0.2.4'):
                writer.append(actor='device', source='tacacs', action='aaa.authentication',
                              target=address, result='pass')
                PostgresAccountingStore(self.pool, str(tenant)).append(
                    AccountingRecord(str(tenant), 'scoped-test', 'operator', address, 'start', ()))
            self.assertEqual([r['target'] for r in logs.read(operator, kind='aaa')['items']], ['192.0.2.2'])
            self.assertEqual([r['device'] for r in accounting.list_events(operator)['items']], ['192.0.2.2'])
            for args in ({'kind': 'activity'}, {'report': True, 'kind': 'aaa'}):
                with self.assertRaises(PermissionError):
                    logs.read(operator, **args)
            registry.save(admin, dict(allowed, location_id=child, secret=''), audit)
            registry.save(admin, dict(allowed, secret=''), audit)
            self.assertEqual(logs.read(operator, kind='aaa')['items'], [])
            self.assertEqual(accounting.list_events(operator)['items'], [])
            self.assertTrue(writer.verify())

    def test_self_service_password_change_is_atomic_with_restricted_role(self):
        from tacacs_appliance.admin_password import AdminPasswordChange
        from tacacs_appliance.local_password_sessions import LocalPasswordSessions
        tenant,user=self.provision()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'console.read')",(tenant,user))
        with self.restricted_pool('admin') as pool:
            sessions=LocalPasswordSessions(pool,str(tenant))
            token=sessions.create_password_only(str(user))
            failing=AdminPasswordChange(pool,str(tenant),Mock(side_effect=RuntimeError('audit unavailable')))
            with self.assertRaises(RuntimeError):
                failing.change(str(user),'integration-password','Replacement-test-42!')
            self.assertIsNotNone(sessions.resolve(token))
            writer=PostgresAuditWriter(pool,str(tenant))
            service=AdminPasswordChange(pool,str(tenant),writer.append_in_transaction)
            with self.assertRaises(PermissionError):
                service.change(str(user),'wrong-password','Replacement-test-42!')
            service.change(str(user),'integration-password','Replacement-test-42!')
            self.assertIsNone(sessions.resolve(token))
            with pool.connection() as connection:
                stored=connection.execute('SELECT password_hash FROM users WHERE id=%s',(user,)).fetchone()[0]
            self.assertTrue(PasswordHasher().verify(stored,'Replacement-test-42!'))

    def test_inventory_uses_restricted_role_and_never_crosses_tenants(self):
        from tacacs_appliance.admin_inventory import AdminInventory
        tenant,user=self.provision();other,_=self.provision()
        with self.pool.connection() as connection:
            connection.execute('INSERT INTO identity_groups(id,tenant_id,name) VALUES (%s,%s,%s)',(uuid4(),other,'hidden-other-tenant'))
        with self.restricted_pool('admin') as pool:
            result=AdminInventory(pool,str(tenant)).read()
        self.assertEqual([row['id'] for row in result['users']],[str(user)])
        self.assertEqual(result['groups'],[])
        self.assertNotIn('password',str(result))

    def test_cisco_shell_grants_require_live_group_and_enabled_identity(self):
        from tacacs_appliance.postgres_authorization import PostgresAuthorizationService
        from tacacs_appliance.shell_profiles import ShellGrant
        tenant,user=self.provision();group=uuid4()
        with self.pool.connection() as connection:
            connection.execute('INSERT INTO identity_groups(id,tenant_id,name) VALUES (%s,%s,%s)',(group,tenant,'ops'))
            connection.execute('INSERT INTO user_groups VALUES (%s,%s,%s)',(tenant,user,group))
        with self.restricted_pool('aaa') as pool:
            service=PostgresAuthorizationService(pool,str(tenant),(ShellGrant('192.0.2.2','ops',1),))
            self.assertEqual(service.authorize_shell('admin','192.0.2.2'),('service=shell','priv-lvl=1'))
            self.assertEqual(service.authorize_shell('admin','192.0.2.3'),())
            self.assertEqual(service.authorize_shell('missing','192.0.2.2'),())
            conflict=PostgresAuthorizationService(pool,str(tenant),(ShellGrant('192.0.2.2','ops',1),ShellGrant('192.0.2.2','ops',15)))
            self.assertEqual(conflict.authorize_shell('admin','192.0.2.2'),())
            with self.pool.connection() as connection:
                connection.execute('UPDATE users SET enabled=false WHERE id=%s',(user,))
            self.assertEqual(service.authorize_shell('admin','192.0.2.2'),())

    @contextmanager
    def restricted_pool(self,profile):
        role='tacacs_role_'+uuid4().hex
        password=secrets.token_urlsafe(32)
        pool=None
        self.owner.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(role),sql.Literal(password)))
        try:
            with psycopg.connect(self.dsn) as connection:
                (provision_admin_role if profile=='admin' else provision_aaa_role)(connection,role,self.schema)
            dsn=make_conninfo(self.dsn,user=role,password=password)
            pool=ConnectionPool(dsn,min_size=1,max_size=2,open=True,
                kwargs={'options':f'-c search_path={self.schema}'})
            pool.wait(timeout=10)
            yield pool
        finally:
            if pool is not None:pool.close()
            # Exact generated test login: remove its grants, then its identity.
            self.owner.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
            self.owner.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))

    def session_factor(self,tenant,user):
        factor=uuid4()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO mfa_factors(id,tenant_id,user_id,secret_reference,enabled,last_accepted_step) VALUES (%s,%s,%s,'secret://session-fixture',true,0)",(factor,tenant,user))
        return str(factor)

    def test_recorded_simulation_and_audit_commit_or_roll_back_together(self):
        tenant,user=self.provision();version=uuid4()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,1,'draft',%s,'[]')",(version,tenant,user))
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'policy.draft')",(tenant,user))
        samples=[dict(subject='hypothetical',device_id='router',command='test-only-private-command',groups=[])]
        with self.restricted_pool('admin') as pool:
            writer=PostgresAuditWriter(pool,str(tenant))
            service=PostgresPolicySimulation(pool,str(tenant),writer.append_in_transaction)
            result=service.record(str(version),str(user),samples)
            with pool.connection() as connection:
                row=connection.execute('SELECT report,samples_digest FROM policy_simulation_reports WHERE id=%s',(result['report_id'],)).fetchone()
                self.assertNotIn('test-only-private-command',str(row));self.assertNotIn('hypothetical',str(row))
            self.assertTrue(writer.verify())
            def reject_audit(*args,**kwargs):raise RuntimeError('test-only audit failure')
            failing=PostgresPolicySimulation(pool,str(tenant),reject_audit)
            with self.assertRaises(RuntimeError):failing.record(str(version),str(user),samples)
            with pool.connection() as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM policy_simulation_reports WHERE tenant_id=%s',(tenant,)).fetchone()[0],1)
                self.assertEqual(connection.execute("SELECT count(*) FROM audit_events WHERE tenant_id=%s AND action='policy.simulation.record'",(tenant,)).fetchone()[0],1)
            with self.pool.connection() as connection:
                self.assertEqual(connection.execute('SELECT state FROM policy_versions WHERE id=%s',(version,)).fetchone()[0],'draft')
                connection.execute("DELETE FROM admin_grants WHERE tenant_id=%s AND user_id=%s AND permission='policy.draft'",(tenant,user))
            with self.assertRaises(PermissionError):service.record(str(version),str(user),samples)

    def test_simulation_evidence_database_immutability_and_tenant_constraints(self):
        tenant,user=self.provision();version=uuid4();report_id=uuid4()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,1,'draft',%s,'[]')",(version,tenant,user))
        statement=('INSERT INTO policy_simulation_reports(id,tenant_id,simulated_by,candidate_id,baseline_rules_digest,'
            'candidate_rules_digest,samples_digest,sample_count,report) VALUES (%s,%s,%s,%s,%s,%s,%s,1,%s)')
        report=Jsonb(dict(coverage='provided-samples-only',total=1))
        values=(report_id,tenant,user,version,'a'*64,'b'*64,'c'*64,report)
        with self.restricted_pool('admin') as pool:
            with pool.connection() as connection:connection.execute(statement,values)
            for mutation in ('UPDATE policy_simulation_reports SET samples_digest=%s WHERE id=%s',
                             'DELETE FROM policy_simulation_reports WHERE id=%s','TRUNCATE policy_simulation_reports'):
                with pool.connection() as connection:
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        connection.execute(mutation,('d'*64,report_id) if mutation.startswith('UPDATE') else (report_id,) if mutation.startswith('DELETE') else None)
        # Owner-level writes still encounter append-only triggers.
        for mutation in ('UPDATE policy_simulation_reports SET sample_count=1 WHERE id=%s',
                         'DELETE FROM policy_simulation_reports WHERE id=%s','TRUNCATE policy_simulation_reports'):
            with self.pool.connection() as connection:
                with self.assertRaises(psycopg.errors.RaiseException):connection.execute(mutation,(report_id,) if '%s' in mutation else None)
        with self.pool.connection() as connection:
            with self.assertRaises(psycopg.errors.CheckViolation):connection.execute(statement,(uuid4(),*values[1:-1],Jsonb({})))
        other_tenant,other_user=self.provision()
        with self.pool.connection() as connection:
            with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                connection.execute(statement,(uuid4(),other_tenant,other_user,version,*values[4:]))

    def test_simulation_evidence_reads_paginate_and_enforce_tenant_policy_and_schema(self):
        tenant,user=self.provision();version,other_version=uuid4(),uuid4()
        other_tenant,other_user=self.provision()
        with self.pool.connection() as connection:
            for revision,candidate in enumerate((version,other_version),1):
                connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,%s,'draft',%s,'[]')",
                                   (candidate,tenant,revision,user))
            for permission in ('policy.draft','console.read'):
                connection.execute('INSERT INTO admin_grants VALUES (%s,%s,%s)',(tenant,user,permission))
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'console.read')",(other_tenant,other_user))
        samples=[dict(subject='private-fixture-subject',device_id='router',command='private-fixture-command',groups=[])]
        with self.restricted_pool('admin') as pool:
            writer=PostgresAuditWriter(pool,str(tenant))
            service=PostgresPolicySimulation(pool,str(tenant),writer.append_in_transaction)
            identifiers={service.record(str(version),str(user),samples)['report_id'] for _ in range(3)}
            other=service.record(str(other_version),str(user),samples)['report_id']
            seen=[];cursor=None
            while True:
                page=service.list_records(str(version),str(user),before=cursor,limit=1)
                self.assertEqual(len(page['items']),1)
                self.assertNotIn('private-fixture',str(page))
                seen.append(page['items'][0]['report_id']);cursor=page['next_before']
                if cursor is None:break
                self.assertLess(len(seen),4)
            self.assertEqual(set(seen),identifiers);self.assertEqual(len(seen),3)
            item=service.inspect_record(str(version),str(user),seen[0])
            self.assertEqual(item['integrity_status'],'not-verified');self.assertEqual(item['report']['total'],1)
            self.assertEqual(len(item['samples_digest']),64);self.assertNotIn('private-fixture',str(item))
            replay=service.verify_record(str(version),str(user),seen[0],samples)
            self.assertTrue(replay['samples_match']);self.assertTrue(replay['rules_match'])
            self.assertTrue(replay['decisions_match']);self.assertEqual(replay['integrity_status'],'not-verified')
            mismatch=service.verify_record(str(version),str(user),seen[0],
                [samples[0]|{'command':'different command'}])
            self.assertFalse(mismatch['samples_match']);self.assertIsNone(mismatch['decisions_match'])
            self.assertIsNone(service.verify_record(str(other_version),str(user),seen[0],samples))
            self.assertIsNone(service.inspect_record(str(other_version),str(user),seen[0]))
            with self.assertRaises(ValueError):service.list_records(str(version),str(user),before=other)
            foreign=PostgresPolicySimulation(pool,str(other_tenant))
            self.assertIsNone(foreign.list_records(str(version),str(other_user)))
            self.assertIsNone(foreign.inspect_record(str(version),str(other_user),seen[0]))
            self.assertIsNone(foreign.verify_record(str(version),str(other_user),seen[0],samples))
            # A privileged/service DB INSERT is not a safe API response schema.
            corrupt=uuid4()
            with pool.connection() as connection:
                connection.execute('INSERT INTO policy_simulation_reports(id,tenant_id,simulated_by,candidate_id,'
                    'baseline_rules_digest,candidate_rules_digest,samples_digest,sample_count,report) VALUES (%s,%s,%s,%s,%s,%s,%s,1,%s)',
                    (corrupt,tenant,user,version,'a'*64,'b'*64,'c'*64,Jsonb(dict(coverage='provided-samples-only',total=1,command='private-fixture'))))
            with self.assertRaises(RuntimeError):service.inspect_record(str(version),str(user),str(corrupt))
            with self.assertRaises(RuntimeError):service.verify_record(str(version),str(user),str(corrupt),samples)
            self.assertTrue(writer.verify())
            with self.pool.connection() as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM audit_events WHERE tenant_id=%s',(tenant,)).fetchone()[0],4)
                self.assertEqual(connection.execute('SELECT state FROM policy_versions WHERE id=%s',(version,)).fetchone()[0],'draft')
                connection.execute("DELETE FROM admin_grants WHERE tenant_id=%s AND user_id=%s AND permission='console.read'",(tenant,user))
            with self.assertRaises(PermissionError):service.list_records(str(version),str(user))
            with self.assertRaises(PermissionError):service.inspect_record(str(version),str(user),seen[0])
            with self.assertRaises(PermissionError):service.verify_record(str(version),str(user),seen[0],samples)

    def test_read_only_policy_simulation_with_restricted_admin_and_tenant_grant(self):
        tenant,user=self.provision();candidate=uuid4()
        rules=[dict(rule_id='show',groups=['ops'],device_ids=['router'],command_prefix='show',decision='allow')]
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants(tenant_id,user_id,permission) VALUES (%s,%s,'console.read')",(tenant,user))
            connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,1,'draft',%s,%s)",
                (candidate,tenant,user,Jsonb(rules)))
            count=connection.execute('SELECT count(*) FROM audit_events WHERE tenant_id=%s',(tenant,)).fetchone()[0]
        samples=[dict(subject='simulated-user',device_id='router',command='show version',groups=['ops']),
                 dict(subject='simulated-user',device_id='router',command='reload',groups=['ops'])]
        with self.restricted_pool('admin') as pool:
            service=PostgresPolicySimulation(pool,str(tenant))
            result=service.compare(str(candidate),str(user),samples)
            self.assertEqual(result['newly_allowed'],(0,));self.assertEqual(result['unchanged'],1)
            self.assertEqual(result['baseline_version'],'default-deny')
            self.assertEqual(result['comparisons'][0]['candidate']['risk'],'unassessed')
            self.assertNotIn('simulated-user',str(result))
            with self.assertRaises(ValueError):service.compare(str(uuid4()),str(user),samples)
            with self.assertRaises(PermissionError):PostgresPolicySimulation(pool,str(uuid4())).compare(str(candidate),str(user),samples)
            with self.pool.connection() as connection:
                self.assertEqual(connection.execute('SELECT state FROM policy_versions WHERE id=%s',(candidate,)).fetchone()[0],'draft')
                self.assertEqual(connection.execute('SELECT count(*) FROM audit_events WHERE tenant_id=%s',(tenant,)).fetchone()[0],count)
                connection.execute("DELETE FROM admin_grants WHERE tenant_id=%s AND user_id=%s AND permission='console.read'",(tenant,user))
            with self.assertRaises(PermissionError):service.compare(str(candidate),str(user),samples)

    def test_database_initializer_rolls_back_both_roles_and_bootstraps_pending_mfa(self):
        roles=['tacacs_install_'+uuid4().hex for _ in range(2)]
        tenant=str(uuid4())
        arguments=dict(migration_directory=Path(__file__).resolve().parents[1]/'migrations',
            aaa_role=roles[0],admin_role=roles[1],aaa_password=secrets.token_urlsafe(32),
            admin_password=secrets.token_urlsafe(32),tenant_id=tenant,name=tenant,
            username='installer-admin',password='Installer-test-42!',
            mfa_reference='secret://installer/mfa',schema=self.schema)
        try:
            with psycopg.connect(self.dsn) as connection:
                with self.assertRaises(ValueError):
                    initialize_database(connection,**(arguments|{'password':'weak'}))
            for role in roles:
                self.assertIsNone(self.owner.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(role,)).fetchone())
            with psycopg.connect(self.dsn) as connection:
                user,factor=initialize_database(connection,**arguments)
            with self.pool.connection() as connection:
                row=connection.execute('SELECT user_id,enabled FROM mfa_factors WHERE id=%s',(factor,)).fetchone()
                self.assertEqual(str(row[0]),user);self.assertFalse(row[1])
                self.assertEqual(connection.execute('SELECT count(*) FROM tenants WHERE id=%s',(tenant,)).fetchone()[0],1)
                self.assertTrue(PostgresAuditWriter(self.pool,tenant).verify())
            with psycopg.connect(self.dsn) as connection:
                with self.assertRaises(psycopg.errors.DuplicateObject):initialize_database(connection,**arguments)
        finally:
            for role in roles:
                if self.owner.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(role,)).fetchone():
                    self.owner.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
                    self.owner.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))

    def test_new_login_provisioning_authenticates_and_failure_rolls_back_identity(self):
        for profile in ('aaa','admin'):
            role='tacacs_new_'+uuid4().hex;password=secrets.token_urlsafe(32)
            created=False
            try:
                with psycopg.connect(self.dsn) as connection:
                    provision_new_login(connection,role,self.schema,password,profile=profile)
                created=True
                with psycopg.connect(make_conninfo(self.dsn,user=role,password=password),options=f'-c search_path={self.schema}') as connection:
                    (validate_admin_role if profile=='admin' else validate_runtime_role)(connection)
                with self.assertRaises(psycopg.errors.DuplicateObject):
                    with psycopg.connect(self.dsn) as connection:
                        provision_new_login(connection,role,self.schema,secrets.token_urlsafe(32),profile=profile)
                # Original credential still works; duplicate attempt did not rotate it.
                with psycopg.connect(make_conninfo(self.dsn,user=role,password=password)) as connection:
                    self.assertEqual(connection.execute('SELECT current_user').fetchone()[0],role)
            finally:
                if created:
                    self.owner.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
                    self.owner.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
        role='tacacs_rollback_'+uuid4().hex
        with self.assertRaises(psycopg.errors.InvalidSchemaName):
            with psycopg.connect(self.dsn) as connection:
                provision_new_login(connection,role,'absent_'+uuid4().hex,secrets.token_urlsafe(32))
        self.assertIsNone(self.owner.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(role,)).fetchone())

    def test_aaa_profile_real_login_authentication_accounting_and_forbidden_policy_write(self):
        tenant,user=self.provision()
        with self.restricted_pool('aaa') as pool:
            with pool.connection() as connection:validate_runtime_role(connection)
            provider=PostgresLocalProvider(pool,str(tenant))
            self.assertTrue(provider.authenticate('admin','integration-password'))
            store=PostgresAccountingStore(pool,str(tenant))
            store.append(AccountingRecord(str(tenant),'restricted-session','admin','router','start',()))
            self.assertTrue(PostgresAuditWriter(pool,str(tenant)).verify())
            with pool.connection() as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with connection.transaction():
                        connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,1,'draft',%s,'[]')",(uuid4(),tenant,user))

    def test_concurrent_totp_replay_and_lockout_using_restricted_admin_login(self):
        tenant,user=self.provision();factor=uuid4();secret=secrets.token_bytes(32);now=1800000000
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO mfa_factors(id,tenant_id,user_id,secret_reference,enabled) VALUES (%s,%s,%s,'secret://integration-mfa',true)",(factor,tenant,user))
        with self.restricted_pool('admin') as pool:
            verifier=PostgresTotpVerifier(pool,str(tenant),lambda reference:secret)
            barrier=threading.Barrier(2)
            def attempt():
                barrier.wait(timeout=5)
                return verifier.verify(str(user),str(factor),totp(secret,now),now)
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures=[executor.submit(attempt) for _ in range(2)]
                self.assertEqual(sorted(future.result(timeout=10) for future in futures),[False,True])
            valid={totp(secret,now+offset) for offset in (-30,0,30)}
            bad=next(f'{number:06d}' for number in range(1000000) if f'{number:06d}' not in valid)
            # The rejected concurrent replay already consumed one failure.
            for _ in range(4):self.assertFalse(verifier.verify(str(user),str(factor),bad,now))
            with self.pool.connection() as connection:
                row=connection.execute('SELECT failed_attempts,locked_until>clock_timestamp() FROM mfa_factors WHERE id=%s',(factor,)).fetchone()
                self.assertEqual(row,(5,True))
            self.assertFalse(verifier.verify(str(user),str(factor),totp(secret,now+30),now+30))
            with self.pool.connection() as connection:
                connection.execute("UPDATE mfa_factors SET locked_until=clock_timestamp()-interval '1 second' WHERE id=%s",(factor,))
            self.assertTrue(verifier.verify(str(user),str(factor),totp(secret,now+30),now+30))

    def test_security_checks_reject_column_only_evidence_mutation_grants(self):
        for profile,table,column in (('aaa','audit_events','actor'),
                                     ('aaa','policy_versions','state'),
                                     ('admin','schema_migrations','checksum'),
                                     ('admin','policy_test_reports','cases_digest')):
            with self.subTest(profile=profile,table=table),self.restricted_pool(profile) as pool:
                with pool.connection() as connection:
                    role=connection.execute('SELECT current_user').fetchone()[0]
                self.owner.execute(sql.SQL('GRANT UPDATE({}) ON {}.{} TO {}').format(
                    sql.Identifier(column),sql.Identifier(self.schema),sql.Identifier(table),sql.Identifier(role)))
                with pool.connection() as connection:
                    self.assertFalse(connection.execute('SELECT has_table_privilege(current_user,%s,\'UPDATE\')',(table,)).fetchone()[0])
                    with self.assertRaises(ValueError):
                        (validate_admin_role if profile=='admin' else validate_runtime_role)(connection)

    def test_https_admin_login_session_policy_list_csrf_and_logout_with_real_database(self):
        import http.client,json,ssl,time
        from tls_support import credentials
        from tacacs_appliance.admin_tls import create_admin_tls_context
        from tacacs_appliance.admin_server import AdminHttpsServer
        from tacacs_appliance.admin_composition import build_admin_api
        from tacacs_appliance.admin_console import AdminConsole
        tenant,user=self.provision();factor=uuid4();secret=secrets.token_bytes(32)
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'console.read')",(tenant,user))
            connection.execute("INSERT INTO mfa_factors(id,tenant_id,user_id,secret_reference,enabled) VALUES (%s,%s,%s,'secret://https-test',true)",(factor,tenant,user))
        with self.restricted_pool('admin') as pool,tempfile.TemporaryDirectory() as directory:
            try:cert,key=credentials(directory)
            except ImportError:self.skipTest('cryptography test dependency missing')
            csrf_file=Path(directory)/'csrf';mfa_file=Path(directory)/'mfa'
            csrf_file.write_bytes(secrets.token_bytes(32));csrf_file.chmod(0o600)
            mfa_file.write_bytes(secret);mfa_file.chmod(0o600)
            server=AdminHttpsServer(('127.0.0.1',0),None,create_admin_tls_context(cert,key))
            thread=None;client=None
            try:
                origin=f'https://localhost:{server.server_address[1]}'
                app=build_admin_api(pool,tenant_id=str(tenant),origin=origin,csrf_key_file=csrf_file,
                    mfa_references={'secret://https-test':mfa_file})
                server.set_app(AdminConsole(app))
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                client=http.client.HTTPSConnection('localhost',server.server_address[1],timeout=3,
                    context=ssl.create_default_context(cafile=str(cert)))
                client.request('GET','/');response=client.getresponse()
                self.assertEqual(response.status,200);self.assertIn(b'Administrator sign-in',response.read())
                body=json.dumps(dict(username='admin',password='integration-password',factor_id=str(factor),code=totp(secret,int(time.time()))))
                client.request('POST','/api/login',body=body,headers={'Origin':origin,'Content-Type':'application/json'})
                response=client.getresponse();data=json.loads(response.read())
                self.assertEqual(response.status,200)
                cookie=response.getheader('Set-Cookie');self.assertIn('HttpOnly',cookie)
                cookie=cookie.split(';',1)[0];csrf=data['csrf_token']
                client.request('GET','/api/session',headers={'Cookie':cookie})
                response=client.getresponse();self.assertEqual(response.status,200)
                self.assertEqual(json.loads(response.read())['user_id'],str(user))
                client.request('GET','/api/policies',headers={'Cookie':cookie})
                response=client.getresponse();self.assertEqual(response.status,200)
                self.assertEqual(json.loads(response.read())['items'],[])
                candidate=uuid4()
                with self.pool.connection() as connection:
                    connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,1,'draft',%s,%s)",
                        (candidate,tenant,user,Jsonb([dict(rule_id='show',groups=[],device_ids=[],command_prefix='show',decision='allow')])))
                simulation_path=f'/api/policies/{candidate}/simulate'
                sample_body=json.dumps({'samples':[dict(subject='hypothetical',device_id='router',command='show test-only-sensitive-value',groups=[])]})
                client.request('POST',simulation_path,body=sample_body,headers={'Cookie':cookie,'Origin':origin,'Content-Type':'application/json'})
                response=client.getresponse();response.read();self.assertEqual(response.status,403)
                client.request('POST',simulation_path,body=sample_body,headers={'Cookie':cookie,'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/json'})
                response=client.getresponse();raw=response.read();self.assertEqual(response.status,200)
                impact=json.loads(raw)
                self.assertEqual(impact['newly_allowed'],[0]);self.assertEqual(impact['coverage'],'provided-samples-only')
                self.assertNotIn(b'test-only-sensitive-value',raw)
                record_path=f'/api/policies/{candidate}/simulation-records'
                record_headers={'Cookie':cookie,'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/json'}
                client.request('POST',record_path,body=sample_body,headers=record_headers)
                response=client.getresponse();response.read();self.assertEqual(response.status,403)
                with self.pool.connection() as connection:
                    connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'policy.draft')",(tenant,user))
                client.request('POST',record_path,body=sample_body,headers=record_headers)
                response=client.getresponse();raw=response.read();self.assertEqual(response.status,201)
                recorded=json.loads(raw);self.assertIn('report_id',recorded)
                self.assertNotIn(b'test-only-sensitive-value',raw)
                with pool.connection() as connection:
                    stored=connection.execute('SELECT report FROM policy_simulation_reports WHERE id=%s AND tenant_id=%s',
                        (recorded['report_id'],tenant)).fetchone()
                    self.assertEqual(stored[0],recorded['report'])
                self.assertTrue(PostgresAuditWriter(pool,str(tenant)).verify())
                client.request('GET',record_path+'?limit=1',headers={'Cookie':cookie})
                response=client.getresponse();raw=response.read();self.assertEqual(response.status,200)
                self.assertEqual(response.getheader('Cache-Control'),'no-store');self.assertNotIn(b'test-only-sensitive-value',raw)
                page=json.loads(raw);self.assertEqual(page['items'][0]['report_id'],recorded['report_id'])
                client.request('GET',record_path+'/'+recorded['report_id'],headers={'Cookie':cookie})
                response=client.getresponse();raw=response.read();self.assertEqual(response.status,200)
                detail=json.loads(raw);self.assertEqual(detail['report'],recorded['report'])
                self.assertEqual(detail['integrity_status'],'not-verified');self.assertNotIn(b'test-only-sensitive-value',raw)
                client.request('GET',record_path+'/'+str(uuid4()),headers={'Cookie':cookie})
                response=client.getresponse();response.read();self.assertEqual(response.status,404)
                client.request('POST','/api/logout',body='{}',headers={'Cookie':cookie,'Origin':origin,'Content-Type':'application/json'})
                response=client.getresponse();response.read();self.assertEqual(response.status,403)
                client.request('POST','/api/logout',body='{}',headers={'Cookie':cookie,'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/json'})
                response=client.getresponse();response.read();self.assertEqual(response.status,200)
                client.request('GET','/api/session',headers={'Cookie':cookie})
                response=client.getresponse();response.read();self.assertEqual(response.status,401)
                client.request('GET',record_path,headers={'Cookie':cookie})
                response=client.getresponse();response.read();self.assertEqual(response.status,401)
            finally:
                if client is not None:client.close()
                if thread is not None:server.shutdown()
                server.server_close()
                if thread is not None:thread.join(3)

    def test_tcp49_aaa_with_real_database_and_restricted_role(self):
        tenant,user=self.provision()
        # Owner seeds a test policy; normal policy lifecycle is tested separately.
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) VALUES (%s,%s,1,'active',%s,%s)",
                (uuid4(),tenant,user,Jsonb([dict(rule_id='show',groups=[],device_ids=[],command_prefix='show',decision='allow')])))
            group, operator = uuid4(), uuid4()
            connection.execute(
                "INSERT INTO identity_groups(id,tenant_id,name) VALUES (%s,%s,%s)",
                (group, tenant, "network-operators"),
            )
            connection.execute(
                "INSERT INTO users(id,tenant_id,username,password_hash) VALUES (%s,%s,%s,%s)",
                (operator, tenant, "operator", PasswordHasher().hash("integration-password")),
            )
            connection.execute(
                "INSERT INTO user_groups(tenant_id,user_id,group_id) VALUES (%s,%s,%s)",
                (tenant, operator, group),
            )
        secret=secrets.token_bytes(32)
        with self.restricted_pool('aaa') as pool,tempfile.TemporaryDirectory() as directory:
            secret_file=Path(directory)/'device.secret';secret_file.write_bytes(secret);secret_file.chmod(0o600)
            config=RuntimeConfig(str(tenant),Path('unused'),(('127.0.0.1',secret_file),),
                ListenerConfig(host='127.0.0.1',port=49,allowed_sources=('127.0.0.1/32',)))
            listener=build_listener(config,pool)
            listener.start();thread=threading.Thread(target=listener.serve_forever);thread.start()
            def read_exact(client,count):
                result=b''
                while len(result)<count:
                    part=client.recv(count-len(result))
                    if not part:raise AssertionError('incomplete TACACS reply')
                    result+=part
                return result
            def exchange(client,packet_type,sequence,session,body):
                frame=Frame(Header(0xc0,packet_type,sequence,0,session,len(body)),body)
                client.sendall(struct.pack('!BBBBII',0xc0,packet_type,sequence,0,session,len(body))+xor_body(frame,secret))
                raw=read_exact(client,12);header=Header.parse(raw,Limits())
                self.assertEqual((header.session_id,header.sequence),(session,sequence+1))
                return xor_body(parse_frame(raw+read_exact(client,header.length)),secret)
            try:
                self.assertEqual(listener.address[1],49)
                with socket.create_connection(listener.address,timeout=3) as client:
                    self.assertEqual(exchange(client,1,1,101,bytes((1,15,1,1,8,0,0,0))+b'operator')[0],5)
                    password=b'integration-password'
                    self.assertEqual(exchange(client,1,3,101,struct.pack('!HHB',len(password),0,0)+password)[0],1)
                for command,status in ((b'show',1),(b'reload',16)):
                    arguments=(b'service=shell',b'cmd='+command,b'cmd-arg=version')
                    body=bytes((6,15,1,1,8,0,0,len(arguments)))+bytes(map(len,arguments))+b'operator'+b''.join(arguments)
                    with socket.create_connection(listener.address,timeout=3) as client:
                        self.assertEqual(exchange(client,2,1,102,body)[0],status)
                argument=b'password=not-to-store'
                body=bytes((2,6,15,1,1,8,0,0,1,len(argument)))+b'operator'+argument
                with socket.create_connection(listener.address,timeout=3) as client:
                    self.assertEqual(exchange(client,3,1,103,body)[4],1)
                with self.pool.connection() as connection:
                    row=connection.execute('SELECT arguments FROM accounting_records WHERE tenant_id=%s',(tenant,)).fetchone()
                    self.assertNotIn('not-to-store',str(row))
                    self.assertIsNotNone(row)
                self.assertTrue(PostgresAuditWriter(pool,str(tenant)).verify())
            finally:
                listener.shutdown();thread.join(3)
            self.assertFalse(thread.is_alive())

    def test_admin_profile_real_login_sessions_policy_test_and_evidence_write_guards(self):
        tenant,user=self.provision()
        with self.pool.connection() as connection:
            for permission in ('console.read','policy.draft'):
                connection.execute('INSERT INTO admin_grants VALUES (%s,%s,%s)',(tenant,user,permission))
        with self.restricted_pool('admin') as pool:
            with pool.connection() as connection:validate_admin_role(connection)
            sessions=PostgresAdminSessions(pool,str(tenant))
            factor=self.session_factor(tenant,user)
            token=sessions.create(str(user),mfa_verified=True,factor_id=factor)
            self.assertEqual(sessions.resolve(token),str(user));sessions.revoke(token)
            self.assertIsNone(sessions.resolve(token))
            with self.pool.connection() as connection:
                connection.execute('UPDATE mfa_factors SET enabled=false WHERE id=%s',(factor,))
            with self.assertRaises(ValueError):sessions.create(str(user),mfa_verified=True,factor_id=factor)
            writer=PostgresAuditWriter(pool,str(tenant))
            lifecycle=PostgresPolicyLifecycle(pool,str(tenant),writer.policy_callback)
            version=lifecycle.draft(str(user),[dict(rule_id='show',groups=[],device_ids=[],command_prefix='show',decision='allow')])
            lifecycle.test_version(version,str(user),[
                dict(subject='admin',device_id='router',command='show version',groups=[],expected='allow'),
                dict(subject='admin',device_id='router',command='reload',groups=[],expected='deny')])
            self.assertEqual(lifecycle.inspect(version,str(user))['state'],'test')
            page=lifecycle.list_versions(str(user),limit=1)
            self.assertEqual(page['items'][0]['version_id'],version)
            self.assertIsNone(page['next_before'])
            self.assertEqual(lifecycle.list_versions(str(user),before=1)['items'],[])
            from tacacs_appliance.admin_audit import PostgresAdminAudit
            reader=PostgresAdminAudit(pool,str(tenant))
            with self.assertRaises(PermissionError):reader.list_events(str(user))
            with self.pool.connection() as connection:
                connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'audit.read')",(tenant,user))
            events=reader.list_events(str(user),limit=1)
            self.assertEqual(len(events['items']),1)
            self.assertIsNotNone(events['next_before'])
            older=reader.list_events(str(user),before=events['next_before'])
            self.assertTrue(all(item['sequence']<events['next_before'] for item in older['items']))
            self.assertTrue(writer.verify())
            with pool.connection() as connection:
                for statement in ('DELETE FROM policy_test_reports','UPDATE audit_events SET actor=actor'):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        with connection.transaction():connection.execute(statement)

    def test_password_session_grants_and_revocation(self):
        tenant, user = self.provision()
        provider = PostgresLocalProvider(self.pool, str(tenant))
        self.assertFalse(provider.authenticate("admin", "wrong").authenticated)
        self.assertTrue(provider.authenticate("admin", "integration-password").authenticated)
        grants = PostgresAdminPermissions(self.pool, str(tenant))
        self.assertFalse(grants(str(user), "console.read"))
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,%s)", (tenant, user, "console.read"))
        self.assertTrue(grants(str(user), "console.read"))
        sessions = PostgresAdminSessions(self.pool, str(tenant))
        token = sessions.create(str(user), mfa_verified=True,factor_id=self.session_factor(tenant,user))
        self.assertEqual(sessions.resolve(token), str(user))
        other_tenant, _ = self.provision()
        self.assertIsNone(PostgresAdminSessions(self.pool, str(other_tenant)).resolve(token))
        sessions.revoke(token)
        self.assertIsNone(sessions.resolve(token))

    def test_cross_tenant_policy_author_rejected_by_database(self):
        tenant, _ = self.provision()
        _, foreign_user = self.provision()
        with self.pool.connection() as connection:
            with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                with connection.transaction():
                    connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) "
                                       "VALUES (%s,%s,1,'draft',%s,'[]')", (uuid4(), tenant, foreign_user))

    def test_audit_update_delete_truncate_are_blocked(self):
        tenant, _ = self.provision()
        writer = PostgresAuditWriter(self.pool, str(tenant))
        writer.append(actor="test", source="local", action="integration", target="test", result="ok")
        self.assertTrue(writer.verify())
        statements = (("UPDATE audit_events SET result='changed' WHERE tenant_id=%s", (tenant,)),
                      ("DELETE FROM audit_events WHERE tenant_id=%s", (tenant,)),
                      ("TRUNCATE audit_events", None))
        for statement, parameters in statements:
            with self.pool.connection() as connection:
                with self.assertRaises(psycopg.errors.RaiseException):
                    with connection.transaction():
                        connection.execute(statement, parameters)
        self.assertTrue(writer.verify())

    def test_admin_recovery_revokes_session_and_keeps_mfa(self):
        from tacacs_appliance.admin_reset import reset_admin

        tenant, user = self.provision()
        with self.pool.connection() as connection:
            for permission in ("console.read", "users.manage"):
                connection.execute("INSERT INTO admin_grants VALUES (%s,%s,%s)", (tenant, user, permission))
        factor = self.session_factor(tenant, user)
        sessions = PostgresAdminSessions(self.pool, str(tenant))
        token = sessions.create(str(user), mfa_verified=True, factor_id=factor)
        with self.pool.connection() as connection:
            reset_admin(connection, tenant, user, "Recovery-test-42!")
            self.assertTrue(connection.execute(
                "SELECT enabled FROM mfa_factors WHERE tenant_id=%s AND id=%s", (tenant, factor)
            ).fetchone()[0])
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM audit_events WHERE tenant_id=%s AND action='admin.password.reset'", (tenant,)
            ).fetchone()[0], 1)
        self.assertIsNone(sessions.resolve(token))

    def test_password_change_revokes_session_without_touching_shadow_table(self):
        tenant, user = self.provision()
        with self.pool.connection() as connection:
            connection.execute("INSERT INTO admin_grants VALUES (%s,%s,'console.read')", (tenant,user))
        sessions = PostgresAdminSessions(self.pool,str(tenant))
        token = sessions.create(str(user),mfa_verified=True,factor_id=self.session_factor(tenant,user))
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute("CREATE TEMP TABLE admin_sessions(user_id uuid,tenant_id uuid)")
                connection.execute("INSERT INTO pg_temp.admin_sessions VALUES (%s,%s)",(user,tenant))
                connection.execute("UPDATE users SET password_hash=%s WHERE id=%s",(PasswordHasher().hash("new-password"),user))
                self.assertEqual(connection.execute("SELECT count(*) FROM pg_temp.admin_sessions").fetchone()[0],1)
                connection.execute("DROP TABLE pg_temp.admin_sessions")
        self.assertIsNone(sessions.resolve(token))

    def test_accounting_audit_failure_rolls_back_record(self):
        tenant, _ = self.provision()
        store = PostgresAccountingStore(self.pool, str(tenant))
        store._audit.append_in_transaction = Mock(side_effect=OSError("injected audit failure"))
        with self.assertRaises(OSError):
            store.append(AccountingRecord(str(tenant), "rollback-session", "admin", "router", "start", ()))
        with self.pool.connection() as connection:
            count = connection.execute("SELECT count(*) FROM accounting_records WHERE tenant_id=%s", (tenant,)).fetchone()[0]
        self.assertEqual(count, 0)

    def test_policy_test_approval_activation_and_immutability(self):
        tenant, author = self.provision()
        reviewer = uuid4()
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute("INSERT INTO users(id,tenant_id,username,password_hash) VALUES (%s,%s,'reviewer',%s)",
                                   (reviewer, tenant, PasswordHasher().hash("reviewer-password")))
                for user, permission in ((author, "policy.draft"), (reviewer, "policy.approve"), (reviewer, "policy.activate")):
                    connection.execute("INSERT INTO admin_grants VALUES (%s,%s,%s)", (tenant, user, permission))
        writer = PostgresAuditWriter(self.pool, str(tenant))
        lifecycle = PostgresPolicyLifecycle(self.pool, str(tenant), writer.policy_callback)
        rules = [dict(rule_id="show", groups=[], device_ids=[], command_prefix="show", decision="allow")]
        cases = [dict(subject="admin", device_id="router", command="show version", groups=[], expected="allow"),
                 dict(subject="admin", device_id="router", command="reload", groups=[], expected="deny")]
        version = lifecycle.draft(str(author), rules)
        lifecycle.test_version(version, str(author), cases)
        lifecycle.transition(version, str(author), "submit")
        lifecycle.transition(version, str(reviewer), "approve")
        lifecycle.transition(version, str(reviewer), "activate")
        with self.pool.connection() as connection:
            self.assertEqual(connection.execute("SELECT state FROM policy_versions WHERE id=%s", (version,)).fetchone()[0], "active")
            with self.assertRaises(psycopg.errors.RaiseException):
                with connection.transaction():
                    connection.execute("UPDATE policy_versions SET rules='[]' WHERE id=%s", (version,))
        self.assertTrue(writer.verify())
