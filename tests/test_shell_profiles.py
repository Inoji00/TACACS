import unittest
from tacacs_appliance.shell_profiles import decode_shell_grants, shell_reply
from tacacs_appliance.authorization_handler import classify_request,TacacsAuthorizationHandler
from tacacs_appliance.protocol import Header,Frame,parse_frame
from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.secrets import StaticDeviceSecretProvider
from unittest.mock import Mock

class ShellTests(unittest.TestCase):
    def test_fastiron_exec_level_set(self):
        for level in (0, 4, 5):
            with self.subTest(level=level):
                self.assertEqual(shell_reply('ruckus-fastiron', level),
                                 ('service=shell', f'foundry-privlvl={level}'))
        for invalid in (False, 1, 14, 15, '5'):
            self.assertEqual(shell_reply('ruckus-fastiron', invalid), ())
    def test_exec_and_context_not_command(self):
        self.assertIsNone(classify_request(('service=shell','cmd=','priv-lvl=15')))
        self.assertIsNone(classify_request(('service=shell',)))
        self.assertEqual(classify_request(('service=shell','cmd=show','cmd-arg=version','priv-lvl=15')),'show version')
        self.assertEqual(classify_request(('service=shell','cmd=show','extra*value=with-equals')),'show')
        for args in [('service=shell','priv-lvl=19'),('service=shell','priv-lvl=1','priv-lvl=15'),('service=shell','cmd=','cmd-arg=version'),('service=shell','roles=admin')]:
            with self.assertRaises(ValueError):classify_request(args)

    def test_grants_are_explicit_and_bounded(self):
        value=dict(device='192.0.2.2',group='ops',privilege=1,profile='cisco-ios')
        self.assertEqual(decode_shell_grants([value],{'192.0.2.2'})[0].privilege,1)
        for bad in [value|dict(privilege=16),value|dict(privilege=True),value|dict(profile='unknown'),value|dict(device='192.0.2.3')]:
            with self.assertRaises(ValueError):decode_shell_grants([bad],{'192.0.2.2'})
        with self.assertRaises(ValueError):decode_shell_grants([value,value],{'192.0.2.2'})

    def test_shell_reply_replaces_client_privilege_and_default_denies(self):
        secret=b'q'*32;service=Mock();service.authorize_shell.return_value=('service=shell','priv-lvl=1')
        handler=TacacsAuthorizationHandler(StaticDeviceSecretProvider({'127.0.0.1':secret}),service=service)
        args=(b'service=shell',b'cmd=',b'priv-lvl=15')
        body=bytes((6,15,1,1,1,0,0,len(args)))+bytes(map(len,args))+b'u'+b''.join(args)
        frame=Frame(Header(0xc0,2,1,0,9,len(body)),body)
        encrypted=Frame(frame.header,xor_body(frame,secret))
        reply=parse_frame(handler('127.0.0.1',encrypted));plain=xor_body(reply,secret)
        self.assertEqual(plain[0:2],bytes((2,2)));self.assertIn(b'priv-lvl=1',plain)
        self.assertNotIn(b'priv-lvl=15',plain);service.authorize.assert_not_called()
        service.authorize_shell.return_value=()
        self.assertEqual(xor_body(parse_frame(handler('127.0.0.1',encrypted)),secret)[0],0x10)
