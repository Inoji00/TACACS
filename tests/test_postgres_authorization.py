import unittest
from contextlib import nullcontext
from unittest.mock import Mock
from tacacs_appliance.postgres_authorization import PostgresAuthorizationService
from tacacs_appliance.authorization import Decision
from tacacs_appliance.authorization_handler import TacacsAuthorizationHandler
from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.protocol import Frame, Header, parse_frame
from tacacs_appliance.secrets import StaticDeviceSecretProvider
from tacacs_appliance.shell_profiles import decode_shell_grants

TENANT = "00000000-0000-0000-0000-000000000001"
RULE = dict(rule_id="ops", groups=["ops"], device_ids=["router"], command_prefix="show", decision="allow")


class AuthorizationSnapshotTests(unittest.TestCase):
    def test_registered_device_requires_mapping_and_readonly_cannot_bypass_policy(self):
        from unittest.mock import MagicMock
        pool=MagicMock();db=pool.connection.return_value.__enter__.return_value
        mappings=[dict(group='readers',privilege=1,mode='read_only'),dict(group='admins',privilege=15,mode='policy')]
        rules=[dict(rule_id='show',groups=[],device_ids=[],command_prefix='show',decision='allow'),dict(rule_id='config',groups=[],device_ids=[],command_prefix='configure',decision='allow')]
        def query(statement,*args):
            result=MagicMock()
            if 'SELECT enabled,access_mappings' in statement:result.fetchone.return_value=(True,mappings)
            elif 'SELECT id,rules' in statement:result.fetchone.return_value=('version',rules)
            else:result.fetchall.return_value=[('readers',)]
            return result
        db.execute.side_effect=query
        service=PostgresAuthorizationService(pool,TENANT)
        self.assertEqual(service.authorize_shell('u','192.0.2.2'),('service=shell','priv-lvl=1'))
        self.assertEqual(service.authorize('u','192.0.2.2','show version').decision,Decision.ALLOW)
        self.assertEqual(service.authorize('u','192.0.2.2','configure terminal').decision,Decision.DENY)
        rules.clear()
        self.assertEqual(service.authorize('u','192.0.2.2','show version').decision,Decision.DENY)

    def setUp(self):
        self.pool, self.db = Mock(), Mock()
        self.pool.connection.side_effect = lambda: nullcontext(self.db)
        self.db.transaction.side_effect = lambda: nullcontext()
        self.db.execute.return_value.fetchone.return_value = ("version", [RULE])
        self.service = PostgresAuthorizationService(self.pool, TENANT)

    def test_trusted_groups_and_policy_share_one_transaction(self):
        self.db.execute.return_value.fetchall.return_value = [("ops",)]
        result = self.service.authorize("user", "router", "show version")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.pool.connection.assert_called_once()
        self.db.transaction.assert_called_once()
        self.assertEqual(self.db.execute.call_args_list[0].args[0], "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        self.assertEqual(result.policy_version, "version")

    def test_fastiron_exec_uses_configured_profile_and_denies_conflict(self):
        ip, secret = '192.0.2.2', b'q' * 32
        reader = dict(device=ip, group='readers', privilege=5, profile='ruckus-fastiron')
        admin = dict(reader, group='admins', privilege=0)
        grants = decode_shell_grants([reader, admin], {ip})
        service = PostgresAuthorizationService(self.pool, TENANT, grants)
        self.db.execute.return_value.fetchone.return_value = None
        self.db.execute.return_value.fetchall.return_value = [('readers',)]
        handler = TacacsAuthorizationHandler(StaticDeviceSecretProvider({ip: secret}), service=service)
        arguments = (b'service=shell', b'cmd=', b'priv-lvl=15')
        body = bytes((6, 15, 1, 1, 1, 0, 0, len(arguments))) + bytes(map(len, arguments)) + b'u' + b''.join(arguments)
        frame = Frame(Header(0xc0, 2, 1, 0, 9, len(body)), body)
        encrypted = Frame(frame.header, xor_body(frame, secret))
        reply = xor_body(parse_frame(handler(ip, encrypted)), secret)
        self.assertEqual(reply[:2], bytes((2, 2)))
        self.assertTrue(reply.endswith(b'service=shellfoundry-privlvl=5'))
        self.assertEqual(service.authorize('u', ip, 'show version').decision, Decision.DENY)
        self.db.execute.return_value.fetchall.return_value = [('readers',), ('admins',)]
        self.assertEqual(service.authorize_shell('u', ip), ())
        self.db.execute.return_value.fetchall.return_value = [('readers',)]
        self.db.execute.return_value.fetchone.return_value = (True, [{'group':'readers','privilege':15,'mode':'policy'}])
        self.assertEqual(service.authorize_shell('u', ip), ())
        for value in (dict(reader, privilege=15), dict(admin, profile='cisco-ios')):
            with self.assertRaises(ValueError):
                decode_shell_grants([reader, value], {ip})

    def test_unknown_identity_and_empty_group_denied(self):
        for rows in ([], [(None,)]):
            self.db.execute.return_value.fetchall.return_value = rows
            self.assertEqual(self.service.authorize("user", "router", "show version").decision, Decision.DENY)

    def test_database_failure_propagates_without_allow_fallback(self):
        self.db.execute.side_effect = OSError("offline")
        with self.assertRaises(OSError):
            self.service.authorize("user", "router", "show version")
