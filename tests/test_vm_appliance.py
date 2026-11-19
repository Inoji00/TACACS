import importlib.util
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
from vm_appliance import SubnetSelectionError,main,select_vm_ip,validate_addresses,vm_config
import local_appliance

class VmProfileTests(unittest.TestCase):
    def test_subnet_selects_only_matching_vm_address(self):
        interfaces=[
            {'addr_info':[{'local':'192.0.2.11'}]},
            {'addr_info':[{'local':'198.51.100.134'}]},
        ]
        with patch('vm_appliance.local.run',return_value=SimpleNamespace(stdout=json.dumps(interfaces))) as run:
            self.assertEqual(select_vm_ip('192.0.2.0/24'),'192.0.2.11')
            with self.assertRaisesRegex(SubnetSelectionError,'No active'):
                select_vm_ip('203.0.113.0/24')
        run.assert_called_with(['ip','-j','-4','address','show','scope','global','up'])

    def test_subnet_rejects_ambiguous_addresses(self):
        interfaces=[{'addr_info':[{'local':'192.0.2.11'},{'local':'192.0.2.12'}]}]
        with patch('vm_appliance.local.run',return_value=SimpleNamespace(stdout=json.dumps(interfaces))):
            with self.assertRaisesRegex(SubnetSelectionError,'Multiple'):
                select_vm_ip('192.0.2.0/24')

    def test_init_maps_both_services_to_selected_ip(self):
        args=['vm_appliance.py','init','--subnet','192.0.2.0/24']
        with patch('vm_appliance.sys.argv',args), patch('vm_appliance.sys.platform','linux'), \
             patch('vm_appliance.select_vm_ip',return_value='192.0.2.11'), \
             patch('vm_appliance.local.initialize') as initialize:
            self.assertEqual(main(),0)
        self.assertEqual(initialize.call_args.kwargs['vm_server_ip'],'192.0.2.11')
        self.assertEqual(initialize.call_args.kwargs['vm_admin_ip'],'192.0.2.11')
        self.assertIsNone(initialize.call_args.kwargs['vm_client_ip'])

    def test_web_update_never_recreates_aaa_or_database(self):
        from unittest.mock import patch
        from vm_appliance import update_web
        with patch('vm_appliance.local.command',return_value=['docker','compose']),patch('vm_appliance.local.run') as run:
            update_web(None,{})
        command=run.call_args.args[0]
        self.assertIn('--no-deps',command)
        self.assertEqual(command[-2:],['admin','proxy'])
        self.assertNotIn('app',command)
        self.assertNotIn('postgres',command)

    def test_audit_update_recreates_listener_and_web_without_postgres(self):
        from vm_appliance import update_audit_runtime
        with patch('vm_appliance.local.command',return_value=['docker','compose']),patch('vm_appliance.local.run') as run:
            update_audit_runtime(None,{})
        command=run.call_args.args[0]
        self.assertIn('--no-deps',command)
        self.assertIn('--wait',command)
        self.assertEqual(command[-3:],['app','admin','proxy'])

    def test_addresses_reject_ambiguous_and_non_lan_inputs(self):
        self.assertEqual(validate_addresses('192.0.2.10','192.0.2.2'),('192.0.2.10','192.0.2.2'))
        for server,client in [('127.0.0.1','192.0.2.2'),('0.0.0.0','192.0.2.2'),('224.0.0.1','192.0.2.2'),('192.0.2.2','192.0.2.2'),('::1','192.0.2.2')]:
            with self.assertRaises(ValueError):validate_addresses(server,client)

    def test_vm_ports_keep_admin_private_and_secrets_isolated(self):
        config={'services':{'app':{},'initialize':{},'admin':{},'postgres':{'healthcheck':{}}}}
        config=vm_config(local_appliance.local_config(config,'tacacs-local-'+'a'*32),'192.0.2.10')
        self.assertEqual(config['services']['app']['ports'],['192.0.2.10:49:49/tcp'])
        self.assertEqual(config['services']['postgres']['ports'],['192.0.2.10:8443:8443/tcp'])
        self.assertNotIn('ports',config['services']['admin'])
        self.assertNotIn('volumes',config['services']['proxy'])
        self.assertNotIn('provision:/run/provision:ro',config['services']['app']['volumes'])
        self.assertEqual(config['services']['app']['restart'],'unless-stopped')

    def test_lan_address_controls_binding_origin_and_certificate(self):
        import base64
        import ipaddress
        import tomllib
        from cryptography import x509
        from tacacs_appliance.admin_api import AdminApi

        config={'services':{'app':{},'initialize':{},'admin':{},'postgres':{'healthcheck':{}}}}
        vm_config(local_appliance.local_config(config,'tacacs-local-'+'a'*32),'192.0.2.10','192.0.2.11')
        self.assertEqual(config['services']['postgres']['ports'],['192.0.2.11:8443:8443/tcp'])
        files,certificate=local_appliance.prepare_files('tenant','192.0.2.2',
            password_only=True,admin_ip='192.0.2.11')
        admin=tomllib.loads(base64.b64decode(files['/config/admin.toml'][0]).decode())
        self.assertEqual(admin['origin'],'https://192.0.2.11:8443')
        sans=x509.load_pem_x509_certificate(certificate).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn(ipaddress.IPv4Address('192.0.2.11'),sans.get_values_for_type(x509.IPAddress))
        app=AdminApi(None,None,b'x'*32,admin['origin'],password_only=True,lan_ip=admin['lan_ip'])
        self.assertTrue(app.password_only)
        with self.assertRaises(ValueError):
            AdminApi(None,None,b'x'*32,'https://192.0.2.12:8443',password_only=True,lan_ip=admin['lan_ip'])
