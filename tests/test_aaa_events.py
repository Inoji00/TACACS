import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch
from tacacs_appliance.aaa_events import AaaEvents, ObservedRouter
from tacacs_appliance.protocol import Frame, Header, encode_frame
from tacacs_appliance.obfuscation import xor_body


class AaaEventTests(unittest.TestCase):
    def test_authorization_audit_keeps_only_allowlisted_decision_metadata(self):
        version = 'e85a9074-c285-467a-8bbc-bc38d074b18e'
        with patch('tacacs_appliance.aaa_events.PostgresAuditWriter') as writer:
            writer.return_value.append.return_value = 'digest'
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                AaaEvents(None,'tenant').emit('192.0.2.2',1,'authorization','deny',
                    authorization_details=dict(attempted_username='operator',authorization_kind='command',
                        matched_rule_id='deny-config',reason='matched-rule',policy_version=version,
                        remote_address='2001:0db8::27',command='DO-NOT-LOG'))
            call = writer.return_value.append.call_args.kwargs
            self.assertEqual(call['policy_version'],version)
            self.assertEqual(call['security_context'],dict(attempted_username='operator',
                authorization_kind='command',matched_rule_id='deny-config',reason='matched-rule',
                remote_address='2001:db8::27'))
            self.assertEqual(json.loads(output.getvalue())['remote_address'],'2001:db8::27')
            self.assertNotIn('DO-NOT-LOG',output.getvalue())

    def test_attempted_username_is_validated_and_not_confused_with_actor(self):
        with patch('tacacs_appliance.aaa_events.PostgresAuditWriter') as writer:
            writer.return_value.append.return_value='digest'
            sink=AaaEvents(None,'tenant');output=io.StringIO()
            with contextlib.redirect_stdout(output):
                sink.emit('192.0.2.2',123,'authentication','fail',attempted_username='missing-user')
            row=json.loads(output.getvalue())
            from datetime import datetime,timedelta
            self.assertEqual(datetime.fromisoformat(row['timestamp']).utcoffset(),timedelta(hours=7))
            self.assertEqual(row['attempted_username'],'missing-user')
            self.assertEqual(writer.return_value.append.call_args.kwargs['actor'],'device')
            self.assertEqual(writer.return_value.append.call_args.kwargs['security_context'],{'attempted_username':'missing-user'})
            for invalid in ('bad\nuser','x'*254,'bad\u202ename',None):
                output=io.StringIO()
                with contextlib.redirect_stdout(output):
                    sink.emit('192.0.2.2',1,'authentication','fail',attempted_username=invalid,
                              remote_address='192.0.2.27,192.0.2.28')
                logged=json.loads(output.getvalue())
                self.assertNotIn('attempted_username',logged)
                self.assertNotIn('remote_address',logged)

    def test_username_follows_only_current_connection_pending_start_never_password(self):
        from tacacs_appliance.router import TacacsRouter
        from tacacs_appliance.tacacs_handler import TacacsAuthenticationHandler
        from tacacs_appliance.authentication_service import AuthenticationService
        from tacacs_appliance.local_identity import AuthenticationResult
        from tacacs_appliance.secrets import StaticDeviceSecretProvider
        from tacacs_appliance.protocol import parse_frame
        secret=b's'*32;secrets=StaticDeviceSecretProvider({'192.0.2.2':secret})
        provider=Mock();provider.authenticate.return_value=AuthenticationResult(False)
        events=Mock()
        observer=ObservedRouter(TacacsRouter(TacacsAuthenticationHandler(secrets,AuthenticationService(provider)),lambda *a:None,lambda *a:None),secrets,events)
        first,second=observer.new_connection(),observer.new_connection()
        def request(sequence,body):
            frame=Frame(Header(0xc0,1,sequence,0,123,len(body)),body)
            return Frame(frame.header,xor_body(frame,secret))
        address=b'192.0.2.27'
        first('192.0.2.2',request(1,bytes((1,1,1,1,7,0,len(address),0))+b'unknown'+address))
        events.emit.assert_called_with('192.0.2.2',123,'authentication','challenge',
                                       attempted_username='unknown',remote_address='192.0.2.27')
        password=b'NEVER-LOG-PASSWORD';cont=len(password).to_bytes(2,'big')+b'\0\0\0'+password
        self.assertIsNone(second('192.0.2.2',request(3,cont)))
        events.emit.assert_called_with('192.0.2.2',123,'authentication','no-reply')
        response=parse_frame(first('192.0.2.2',request(3,cont)))
        self.assertEqual(xor_body(response,secret)[0],2)
        events.emit.assert_called_with('192.0.2.2',123,'authentication','fail',
                                       attempted_username='unknown',remote_address='192.0.2.27')
        first('192.0.2.2',request(3,cont))
        events.emit.assert_called_with('192.0.2.2',123,'authentication','no-reply')
        self.assertNotIn('NEVER-LOG-PASSWORD',str(events.emit.call_args_list))

    def test_wire_outcomes_and_response_preservation_without_request_body(self):
        secret = b'private-shared-secret-for-test-only-32'
        for kind, body, expected in ((1,b'\x01','pass'),(1,b'\x02','fail'),
            (1,b'\x05','challenge'),(2,b'\x10','deny'),(2,b'\x02','allow'),
            (3,b'\x00\x03\x00\x00\x01abc','committed'),(3,b'\x00\x00\x00\x00\x02','error')):
            with self.subTest(kind=kind, expected=expected):
                header=Header(0xc0,kind,2,0,123,len(body))
                clear=Frame(header,body)
                response=encode_frame(header,xor_body(clear,secret))
                handler=Mock(return_value=response)
                secrets=Mock();secrets.resolve.return_value=secret
                events=Mock()
                observer=ObservedRouter(handler,secrets,events)
                request=Frame(Header(0xc0,kind,1,0,123,15),b'password-secret')
                self.assertEqual(observer('192.0.2.2',request),response)
                events.emit.assert_called_once_with('192.0.2.2',123,
                    {1:'authentication',2:'authorization',3:'accounting'}[kind],expected)

    def test_errors_and_connection_isolation(self):
        router=Mock(side_effect=RuntimeError('sensitive diagnostic'))
        events=Mock();observer=ObservedRouter(router,Mock(),events)
        self.assertIsNot(observer.new_connection().router,router)
        with self.assertRaises(RuntimeError):observer('192.0.2.2',Frame(Header(0xc0,1,1,0,4,0),b''))
        events.emit.assert_called_once_with('192.0.2.2',4,'authentication','error')

    def test_json_stdout_reports_commit_failure_without_diagnostic(self):
        with patch('tacacs_appliance.aaa_events.PostgresAuditWriter') as writer:
            writer.return_value.append.side_effect=RuntimeError('DSN password secret')
            sink=AaaEvents(None,'tenant')
            output=io.StringIO()
            with contextlib.redirect_stdout(output):sink.emit('192.0.2.2',123,'authentication','fail')
            event=json.loads(output.getvalue())
            self.assertFalse(event['persisted'])
            self.assertNotIn('secret',output.getvalue())
            writer.return_value.append.side_effect=None
            writer.return_value.append.return_value='abc'
            output=io.StringIO()
            with contextlib.redirect_stdout(output):sink.emit('192.0.2.2',123,'authorization','deny')
            self.assertTrue(json.loads(output.getvalue())['persisted'])
