import unittest
from argon2 import PasswordHasher
from unittest.mock import MagicMock
from uuid import UUID
from tacacs_appliance.device_registry import DeviceRegistry
from tacacs_appliance.device_console_scope import parse_scope
from tacacs_appliance.secrets import SecretNotFoundError
from tacacs_appliance.server import ListenerConfig,TacacsListener

TENANT='00000000-0000-0000-0000-000000000001'


class DeviceRegistryTests(unittest.TestCase):
    def test_reveal_requires_permission_and_audit_before_return(self):
        pool=MagicMock()
        db=pool.connection.return_value.__enter__.return_value
        registry=DeviceRegistry(pool,TENANT,b'k'*32)
        address='192.0.2.2'
        nonce=b'n'*12
        value=nonce+registry.cipher.encrypt(nonce,b's'*32,registry._aad(address))
        audit=MagicMock()
        row=db.execute.return_value.fetchone
        password='fixture-password'
        password_hash=PasswordHasher().hash(password)
        row.side_effect=[None]
        with self.assertRaises(PermissionError):
            registry.reveal_secret(TENANT,address,audit,password=password)
        row.side_effect=[(None,),None]
        with self.assertRaises(ValueError):
            registry.reveal_secret(TENANT,address,audit,password=password)
        audit.assert_not_called()
        row.side_effect=[(None,),(value,),(password_hash,)]
        with self.assertRaises(PermissionError):
            registry.reveal_secret(TENANT,address,audit,password='wrong-password')
        audit.assert_not_called()
        row.side_effect=[(None,),(value,),(password_hash,)]
        self.assertEqual(registry.reveal_secret(TENANT,address,audit,password=password),{'secret':'s'*32})
        audit.assert_called_once_with(db,actor=TENANT,source='admin-devices',
                                      action='device.secret.reveal',target=address,result='success')
        row.side_effect=[(None,),(value,),(password_hash,)]
        audit.side_effect=RuntimeError('audit unavailable')
        with self.assertRaises(RuntimeError):
            registry.reveal_secret(TENANT,address,audit,password=password)

    def test_removal_requires_disabled_device_and_preserves_negative_registration(self):
        pool=MagicMock();db=pool.connection.return_value.__enter__.return_value
        registry=DeviceRegistry(pool,TENANT,b'k'*32)
        for state in ((True,False),(False,True),None):
            db.execute.return_value.fetchone.side_effect=[(None,),state]
            with self.assertRaises(ValueError):registry.delete(TENANT,'192.0.2.2',MagicMock())
        db.execute.return_value.fetchone.side_effect=[(None,),(False,False,None,None,'Sw-07')]
        audit=MagicMock();registry.delete(TENANT,'192.0.2.2',audit)
        self.assertIn('deleted=true,enabled=false',db.execute.call_args.args[0])
        self.assertNotIn('DELETE FROM network_devices',db.execute.call_args.args[0])
        self.assertEqual(audit.call_args.kwargs['security_context'],{'target_name':'Sw-07'})

    def test_web_scope_is_applied_before_pagination_and_to_direct_writes(self):
        pool=MagicMock()
        db=pool.connection.return_value.__enter__.return_value
        registry=DeviceRegistry(pool,TENANT,b'k'*32)
        audit=MagicMock()
        location=UUID('00000000-0000-0000-0000-000000000002')
        device_type=UUID('00000000-0000-0000-0000-000000000003')
        scope=dict(location_id=str(location),device_type_id=str(device_type),actions=['edit','delete','reveal_secret'])
        row=db.execute.return_value.fetchone
        row.return_value=(scope,)
        db.execute.return_value.fetchall.return_value=[]
        self.assertEqual(registry.list_devices(actor=TENANT,limit=1)['access'],scope)
        query,params=db.execute.call_args.args
        self.assertIn('location_id=%s AND device_type_id=%s ORDER BY address LIMIT %s',query)
        self.assertEqual(params[1:],(str(location),str(device_type),2))

        address='192.0.2.2'
        row.side_effect=[(scope,),(False,False,None,device_type)]
        with self.assertRaises(PermissionError):registry.delete(TENANT,address,audit)
        row.side_effect=[(scope,),(b'unreadable',location,None)]
        with self.assertRaises(PermissionError):registry.reveal_secret(TENANT,address,audit,password='fixture-password')
        payload=dict(operation='edit',address=address,name='switch',enabled=True,secret='',shell_group='',privilege=1)
        previous=(b'cipher',b'fingerprint','',location,device_type,False,'switch',True,'',1,[])
        for changes in ({'location_id':None},{'enabled':False},{'secret':'x'*16},
                        {'access_mappings':[dict(group='ops',privilege=15,mode='policy')]}):
            row.side_effect=[(scope,),previous]
            with self.assertRaises(PermissionError):registry.save(TENANT,dict(payload,**changes),audit)
        row.side_effect=[(dict(scope,actions=[]),),previous]
        with self.assertRaises(PermissionError):registry.save(TENANT,payload,audit)
        row.side_effect=[(dict(scope,actions=['create']),),None]
        with self.assertRaises(PermissionError):registry.save(TENANT,dict(payload,operation='create',
            location_id=str(location),device_type_id=str(device_type)),audit)
        audit.assert_not_called()

    def test_scoped_creation_requires_an_approved_ip_and_matching_classification(self):
        pool=MagicMock()
        db=pool.connection.return_value.__enter__.return_value
        registry=DeviceRegistry(pool,TENANT,b'k'*32)
        audit=MagicMock()
        location='00000000-0000-0000-0000-000000000002'
        scope=dict(location_id=location,device_type_id=None,actions=['create'])
        for addresses in ([],['192.0.2.2/24'],['127.0.0.1']):
            with self.assertRaises(ValueError):
                parse_scope(dict(scope,creation_addresses=addresses))
        scope['creation_addresses']=['192.0.2.2']
        self.assertEqual(parse_scope(scope)[3],['192.0.2.2'])

        payload=dict(operation='create',address='192.0.2.2',name='switch',enabled=False,
                     secret='x'*16,shell_group='',privilege=1,location_id=location)
        row=db.execute.return_value.fetchone
        for overrides in ({'address':'192.0.2.3'},{'location_id':None},{'enabled':True}):
            row.side_effect=[(scope,),None]
            with self.assertRaises(PermissionError):
                registry.save(TENANT,dict(payload,**overrides),audit)
        outside_scope=(b'cipher',b'fingerprint','',None,None,False,'other',True,'',1,[])
        row.side_effect=[(scope,),outside_scope]
        with self.assertRaises(PermissionError):
            registry.save(TENANT,payload,audit)
        audit.assert_not_called()

        row.side_effect=[(scope,),None,(1,),(0,),None]
        self.assertEqual(registry.save(TENANT,payload,audit),{'status':'saved','address':'192.0.2.2'})
        audit.assert_called_once_with(db,actor=TENANT,source='admin-devices',
                                      action='device.create',target='192.0.2.2',result='success',
                                      security_context={'target_name':'switch'})

    def test_only_runtime_records_source_observations(self):
        pool=MagicMock();connection=pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.return_value=(False,4)
        registry=DeviceRegistry(pool,TENANT,b'k'*32)
        self.assertFalse(registry.source_state('192.0.2.2'))
        self.assertEqual(connection.execute.call_count,1)
        connection.reset_mock()
        runtime=DeviceRegistry(pool,TENANT,b'k'*32,observe_runtime=True)
        self.assertFalse(runtime.source_state('192.0.2.2'))
        statement,values=connection.execute.call_args.args
        self.assertIn('device_runtime_observations.revision<=EXCLUDED.revision',statement)
        self.assertEqual(values[1:],('192.0.2.2',4))

    def test_invalid_list_filters_do_not_open_database(self):
        pool=MagicMock();registry=DeviceRegistry(pool,TENANT,b'k'*32)
        for values in (dict(limit=201),dict(limit=True),dict(search='x\n'),dict(after='::1'),dict(search='x'*65)):
            with self.assertRaises(ValueError):registry.list_devices(**values)
        pool.connection.assert_not_called()
    def test_input_validation_precedes_database(self):
        pool=MagicMock();registry=DeviceRegistry(pool,TENANT,b'k'*32)
        valid=dict(address='192.0.2.2',name='switch',enabled=False,secret='S'*32,shell_group='',privilege=1)
        for changes in ({'address':'0.0.0.0'},{'address':'127.0.0.1'},{'secret':'short'},
                        {'secret':'x'*31+' '},{'privilege':True},{'privilege':16},{'enabled':1},{'shell_group':'*'}):
            with self.assertRaises(ValueError):registry.save(TENANT,dict(valid,**changes),MagicMock())
        pool.connection.assert_not_called()

    def test_ciphertext_is_bound_to_tenant_and_address(self):
        pool=MagicMock();registry=DeviceRegistry(pool,TENANT,b'k'*32)
        nonce=b'n'*12
        value=nonce+registry.cipher.encrypt(nonce,b's'*32,registry._aad('192.0.2.2'))
        pool.connection.return_value.__enter__.return_value.execute.return_value.fetchone.return_value=(True,value)
        self.assertEqual(registry.resolve('192.0.2.2'),b's'*32)
        with self.assertRaises(SecretNotFoundError):registry.resolve('192.0.2.3')

    def test_dynamic_acl_overrides_static_and_database_failure_denies(self):
        callback=MagicMock(return_value=False)
        listener=TacacsListener(ListenerConfig(allowed_sources=('192.0.2.2/32',)),lambda *args:None,source_state=callback)
        try:
            self.assertFalse(listener._source_allowed('192.0.2.2'))
            callback.return_value=True
            self.assertTrue(listener._source_allowed('192.0.2.3'))
            callback.return_value=None
            self.assertTrue(listener._source_allowed('192.0.2.2'))
            callback.side_effect=RuntimeError('database unavailable')
            self.assertFalse(listener._source_allowed('192.0.2.2'))
        finally:listener.shutdown()
