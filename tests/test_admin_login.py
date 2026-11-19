import io
import json
import unittest
from unittest.mock import Mock
from tacacs_appliance.admin_login import AdminLoginService
from tacacs_appliance.admin_api import AdminApi
from tacacs_appliance.local_identity import AuthenticationResult

ID = "00000000-0000-0000-0000-000000000001"


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.passwords, self.totp, self.sessions = Mock(), Mock(), Mock()
        self.subjects, self.permissions = Mock(return_value=ID), Mock(return_value=True)
        self.passwords.authenticate.return_value = AuthenticationResult(True, "canonical")
        self.totp.verify.return_value = True
        self.sessions.create.return_value = "a" * 43
        self.login = AdminLoginService(self.passwords, self.subjects, self.permissions, self.totp, self.sessions)

    def test_both_factors_and_grant_required(self):
        self.assertEqual(self.login.login("name", "password", ID, "123456"), "a" * 43)
        self.subjects.assert_called_once_with("canonical")
        self.totp.verify.assert_called_once_with(ID, ID, "123456")
        self.sessions.create.assert_called_once_with(ID, mfa_verified=True,factor_id=ID)

    def test_explicit_local_password_mode_keeps_password_and_grant_checks(self):
        login=AdminLoginService(self.passwords,self.subjects,self.permissions,self.totp,self.sessions,password_only=True)
        self.sessions.create_password_only.return_value='a'*43
        self.assertEqual(login.login('name','password'),'a'*43)
        self.totp.verify.assert_not_called();self.sessions.create.assert_not_called()
        self.permissions.return_value=False
        self.assertIsNone(login.login('name','password'))

    def test_local_password_api_schema_and_nonlocal_origin_rejection(self):
        login=AdminLoginService(self.passwords,self.subjects,self.permissions,self.totp,self.sessions,password_only=True)
        self.sessions.create_password_only.return_value='a'*43
        app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://localhost:8443',login=login,password_only=True)
        result=self.request(app,json.dumps(dict(username='name',password='password')).encode(),HTTP_ORIGIN='https://localhost:8443')
        self.assertEqual(result['status'],'200 OK')
        self.assertEqual(self.request(app,HTTP_ORIGIN='https://localhost:8443')['status'],'400 Bad Request')
        with self.assertRaises(ValueError):AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',password_only=True)

    def test_denials_never_issue_session(self):
        for stage in ("password", "subject", "grant", "totp"):
            self.setUp()
            if stage == "password": self.passwords.authenticate.return_value = AuthenticationResult(False)
            elif stage == "subject": self.subjects.return_value = None
            elif stage == "grant": self.permissions.return_value = False
            else: self.totp.verify.return_value = False
            self.assertIsNone(self.login.login("name", "password", ID, "123456"))
            self.sessions.create.assert_not_called()

    def test_invalid_input_does_not_reach_password_provider(self):
        for factor, code in (("bad", "123456"), (ID, "１２３４５６"), (None, "123456")):
            self.assertIsNone(self.login.login("name", "password", factor, code))
        self.passwords.authenticate.assert_not_called()

    def request(self, app, raw=None, **extra):
        raw = raw if raw is not None else json.dumps(dict(username="name", password="password", factor_id=ID, code="123456")).encode()
        environ = {"wsgi.url_scheme": "https", "REQUEST_METHOD": "POST", "PATH_INFO": "/api/login",
                   "HTTP_ORIGIN": "https://admin.local", "REMOTE_ADDR": "127.0.0.1", "CONTENT_TYPE": "application/json",
                   "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw)}
        environ.update(extra)
        result = {}
        def start(status, headers): result.update(status=status, headers=dict(headers))
        result["body"] = json.loads(b"".join(app(environ, start)))
        return result

    def app(self):
        return AdminApi(self.sessions, self.permissions, b"k" * 32, "https://admin.local", login=self.login)

    def test_login_sets_cookie_without_echoing_credentials(self):
        result = self.request(self.app())
        self.assertEqual(result["status"], "200 OK")
        self.assertIn("HttpOnly", result["headers"]["Set-Cookie"])
        self.assertNotIn("password", str(result["body"]))

    def test_cross_origin_and_oversized_login_rejected(self):
        app = self.app()
        self.assertEqual(self.request(app, HTTP_ORIGIN="https://evil.local")["status"], "403 Forbidden")
        self.assertEqual(self.request(app, CONTENT_LENGTH="8193")["status"], "400 Bad Request")
        self.passwords.authenticate.assert_not_called()

    def test_duplicate_json_fields_rejected(self):
        self.assertEqual(self.request(self.app(), b'{"username":"a","username":"b"}')["status"], "400 Bad Request")

    def test_source_attempt_limit_applies_before_password_verification(self):
        app = self.app()
        for _ in range(5): self.request(app)
        self.assertEqual(self.request(app)["status"], "429 Too Many Requests")
        self.assertEqual(self.passwords.authenticate.call_count, 5)


    def test_web_audit_logs_socket_ip_and_configured_destination(self):
        audit=Mock()
        self.sessions.resolve.return_value=ID
        app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',
                     login=self.login,lan_ip='192.0.2.15',web_audit=audit)
        metadata={'tnac.via_proxy':True,'tnac.source_ip':'192.0.2.27',
                  'tnac.destination_ip':'172.19.0.2','HTTP_X_FORWARDED_FOR':'192.0.2.99'}
        self.assertEqual(self.request(app,**metadata)['status'],'200 OK')
        audit.assert_called_once_with(actor=ID,source='admin-web',action='web.login',target='192.0.2.15',
                                      result='success',security_context={'source_ip':'192.0.2.27',
                                          'destination_ip':'192.0.2.15','attempted_username':'name'})
        audit.reset_mock()
        self.passwords.authenticate.return_value=AuthenticationResult(False)
        self.assertEqual(self.request(app,**metadata)['status'],'401 Unauthorized')
        self.assertEqual(audit.call_args.kwargs['actor'],'anonymous')
        self.assertEqual(audit.call_args.kwargs['result'],'fail')

        audit.reset_mock()
        self.assertEqual(self.request(app,PATH_INFO='/api/logout',
            HTTP_COOKIE='__Host-tacacs_session='+'a'*43,
            HTTP_X_CSRF_TOKEN=app.csrf_token('a'*43),**metadata)['status'],'200 OK')
        audit.assert_called_once_with(actor=ID,source='admin-web',action='web.logout',target='192.0.2.15',
                                      result='success',security_context={'source_ip':'192.0.2.27',
                                                                        'destination_ip':'192.0.2.15'})

    def test_web_audit_ignores_headers_and_keeps_login_available(self):
        audit=Mock(side_effect=RuntimeError('private data'))
        app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',
                     login=self.login,web_audit=audit)
        with self.assertLogs('tacacs_appliance.admin_api',level='ERROR') as messages:
            self.assertEqual(self.request(app,HTTP_X_FORWARDED_FOR='192.0.2.99',
                HTTP_X_FORWARDED_HOST='192.0.2.98')['status'],'200 OK')
        self.assertEqual(audit.call_args.kwargs['security_context'],{'attempted_username':'name'})
        self.assertNotIn('private data',''.join(messages.output))
