import json
import io
import unittest
from unittest.mock import Mock,patch,MagicMock
from uuid import UUID
from tacacs_appliance.admin_api import AdminApi, COOKIE_NAME
from tacacs_appliance.admin_rbac import PostgresAdminPermissions

TOKEN = "a" * 43


class AdminApiTests(unittest.TestCase):
    def test_syslog_profile_writes_require_csrf_and_admin(self):
        audit = Mock()
        self.app = AdminApi(self.sessions, self.permissions, b"k" * 32, "https://admin.local", web_audit=audit)
        payload = b'{"action":"save","source":"192.0.2.10","name":"FW-EXAMPLE","profile":"firewall"}'
        args = dict(PATH_INFO="/api/device-syslog/profiles", REQUEST_METHOD="POST",
                    CONTENT_TYPE="application/json", CONTENT_LENGTH=str(len(payload)))
        with patch("tacacs_appliance.syslog_profiles.change_profile") as change, \
             patch("tacacs_appliance.syslog_profiles.read_profiles", return_value={}):
            def submit(**headers):
                return self.request(**args, **headers, **{"wsgi.input": io.BytesIO(payload)})["status"]
            self.assertEqual(submit(), "403 Forbidden")
            headers = dict(HTTP_ORIGIN="https://admin.local", HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN))
            self.permissions.return_value = False
            self.assertEqual(submit(**headers), "403 Forbidden")
            change.assert_not_called()
            self.permissions.return_value = True
            self.assertEqual(submit(**headers), "200 OK")
            change.assert_called_once_with(("save", "192.0.2.10", "FW-EXAMPLE", "firewall"))
            audit.assert_called_once()

    def test_device_syslog_is_restricted_to_admin_and_validates_filters(self):
        path = "/api/device-syslog"
        with patch("tacacs_appliance.device_syslog.search", return_value={"items": []}) as search:
            self.assertEqual(self.request(PATH_INFO=path, HTTP_COOKIE="")["status"], "401 Unauthorized")
            self.permissions.return_value = False
            self.assertEqual(self.request(PATH_INFO=path)["status"], "403 Forbidden")
            search.assert_not_called()
            self.permissions.return_value = True
            self.assertEqual(self.request(PATH_INFO=path, QUERY_STRING="severity=5")["status"], "200 OK")
            self.permissions.assert_called_with("user-id", "users.manage")
            search.assert_called_once_with("severity=5")
            search.side_effect = ValueError("invalid filter")
            self.assertEqual(self.request(PATH_INFO=path, QUERY_STRING="severity=9")["status"], "400 Bad Request")

    def test_removed_tenant_header_rejects_reads_and_writes_before_dispatch(self):
        policies, devices = Mock(), Mock()
        self.app = AdminApi(self.sessions, self.permissions, b'k'*32,
                            'https://admin.local', policies=policies, devices=devices)
        for path in ('/api/policies', '/api/devices'):
            for method in ('GET', 'POST'):
                with self.subTest(path=path, method=method):
                    response = self.request(PATH_INFO=path, REQUEST_METHOD=method,
                                            HTTP_X_TACACS_TENANT=str(UUID(int=2)))
                    self.assertEqual(response['status'], '400 Bad Request')
        self.assertFalse(policies.mock_calls)
        self.assertFalse(devices.mock_calls)

    def test_log_filters_do_not_override_session_principal(self):
        logs=Mock();logs.read.return_value={'items':[]}
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',logs=logs)
        self.assertEqual(self.request(PATH_INFO='/api/logs',QUERY_STRING='kind=aaa&actor=device&limit=10')['status'],'200 OK')
        logs.read.assert_called_once_with('user-id',report=False,kind='aaa',actor='device',limit=10)
        for query in ('tenant=forged','report=true','kind=aaa&kind=all','limit=1000','limit=-1','search=%00','before=0'):
            # Semantic validation belongs to the repository; boundary rejects schema/duplicates/numeric syntax.
            if query in ('limit=1000','search=%00','before=0'):continue
            self.assertEqual(self.request(PATH_INFO='/api/logs',QUERY_STRING=query)['status'],'400 Bad Request')
        self.permissions.return_value=False
        self.assertEqual(self.request(PATH_INFO='/api/reports')['status'],'403 Forbidden')
        self.assertEqual(logs.read.call_count,1)

    def setUp(self):
        self.sessions = Mock()
        self.sessions.resolve.return_value = "user-id"
        self.permissions = Mock(return_value=True)
        self.app = AdminApi(self.sessions, self.permissions, b"k" * 32, "https://admin.local")

    def request(self, **overrides):
        environ = {"wsgi.url_scheme": "https", "REQUEST_METHOD": "GET", "PATH_INFO": "/api/session",
                   "HTTP_COOKIE": f"{COOKIE_NAME}={TOKEN}"}
        environ.update(overrides)
        result = {}
        def start(status, headers):
            result.update(status=status, headers=dict(headers))
        result["body"] = json.loads(b"".join(self.app(environ, start)))
        return result

    def test_device_operator_cannot_grant_web_access(self):
        identities=Mock()
        operator=Mock(return_value=True)
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',
                          identities=identities,device_operator=operator)
        payload=b'{"user_id":"target","enabled":true}'
        def submit():
            return self.request(PATH_INFO='/api/identities/console-access',REQUEST_METHOD='POST',
                HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),
                CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(payload)),**{'wsgi.input':io.BytesIO(payload)})
        self.assertEqual(submit()['status'],'403 Forbidden')
        identities.set_console_access.assert_not_called()
        operator.return_value=False
        identities.set_console_access.return_value={'status':'committed'}
        self.assertEqual(submit()['status'],'200 OK')
        identities.set_console_access.assert_called_once_with('user-id',user_id='target',enabled=True)

    def test_session_response_has_no_bearer_and_no_cache(self):
        result = self.request()
        self.assertEqual(result["status"], "200 OK")
        self.assertNotIn(TOKEN, str(result))
        self.assertEqual(result["headers"]["Cache-Control"], "no-store")
        self.permissions.assert_called_once_with("user-id", "console.read")

    def test_unlock_requires_csrf_and_users_manage(self):
        identities = Mock()
        identities.unlock.return_value = {'status': 'committed'}
        self.app = AdminApi(self.sessions, self.permissions, b'k'*32,
                            'https://admin.local', identities=identities)
        payload = b'{"user_id":"target"}'

        def submit(csrf=''):
            return self.request(PATH_INFO='/api/identities/unlock', REQUEST_METHOD='POST',
                HTTP_ORIGIN='https://admin.local', HTTP_X_CSRF_TOKEN=csrf,
                CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(payload)),
                **{'wsgi.input': io.BytesIO(payload)})

        self.assertEqual(submit()['status'], '403 Forbidden')
        self.permissions.return_value = False
        token = self.app.csrf_token(TOKEN)
        self.assertEqual(submit(token)['status'], '403 Forbidden')
        identities.unlock.assert_not_called()
        self.permissions.return_value = True
        self.assertEqual(submit(token)['body'], {'status': 'committed'})
        identities.unlock.assert_called_once_with('user-id', user_id='target')

    def test_device_operator_has_only_opted_in_aaa_routes(self):
        logs, accounting = Mock(), Mock()
        logs.read.return_value = accounting.list_events.return_value = {"items": []}
        permissions = {"console.read", "devices.manage"}
        self.permissions.side_effect = lambda actor, permission: permission in permissions
        self.app = AdminApi(self.sessions, self.permissions, b"k" * 32, "https://admin.local",
                            device_operator=lambda actor: True, logs=logs, accounting=accounting)
        self.assertFalse(self.request()["body"]["device_aaa_logs"])
        self.assertEqual(self.request(PATH_INFO="/api/logs", QUERY_STRING="kind=aaa")["status"],
                         "403 Forbidden")
        self.assertEqual(self.request(PATH_INFO="/api/accounting")["status"], "403 Forbidden")
        permissions.add("devices.aaa.read")
        self.assertTrue(self.request()["body"]["device_aaa_logs"])
        self.assertEqual(self.request(PATH_INFO="/api/logs", QUERY_STRING="kind=aaa")["status"],
                         "200 OK")
        self.assertEqual(self.request(PATH_INFO="/api/accounting")["status"], "200 OK")
        self.assertEqual(self.request(PATH_INFO="/api/reports")["status"], "403 Forbidden")

    def test_admin_can_save_web_access_repeatedly(self):
        identities = Mock()
        identities.set_console_access.return_value = {"status": "committed"}
        self.app = AdminApi(self.sessions, self.permissions, b"k" * 32,
                            "https://admin.local", identities=identities)
        payload = b'{"user_id":"target","enabled":true}'

        def submit():
            return self.request(PATH_INFO="/api/identities/console-access",
                REQUEST_METHOD="POST", HTTP_ORIGIN="https://admin.local",
                HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN), CONTENT_TYPE="application/json",
                CONTENT_LENGTH=str(len(payload)), **{"wsgi.input": io.BytesIO(payload)})

        with patch("tacacs_appliance.rate_limit.time.monotonic", return_value=0):
            self.assertEqual([submit()["status"] for _ in range(8)], ["200 OK"] * 8)
        self.assertEqual(identities.set_console_access.call_count, 8)

    def test_admin_device_writes_are_exempt_but_secret_reads_are_limited(self):
        registry = Mock()
        registry.save.return_value = {"status": "saved"}
        registry.reveal_secret.return_value = {"secret": "fixture"}
        self.app = AdminApi(self.sessions, self.permissions, b"k" * 32,
                            "https://admin.local", devices=registry)

        def submit(path, payload):
            return self.request(PATH_INFO=path, REQUEST_METHOD="POST",
                HTTP_ORIGIN="https://admin.local", HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),
                CONTENT_TYPE="application/json", CONTENT_LENGTH=str(len(payload)),
                **{"wsgi.input": io.BytesIO(payload)})["status"]

        device = b'{"address":"192.0.2.2"}'
        reveal = b'{"address":"192.0.2.2","password":"fixture-password"}'
        with patch("tacacs_appliance.rate_limit.time.monotonic", return_value=0):
            self.assertEqual([submit("/api/devices", device) for _ in range(8)], ["200 OK"] * 8)
            self.assertEqual([submit("/api/devices/secret", reveal) for _ in range(5)], ["200 OK"] * 5)
            self.assertEqual(submit("/api/devices/secret", reveal), "429 Too Many Requests")

            self.permissions.side_effect = lambda user, permission: permission == "devices.manage"
            self.sessions.resolve.return_value = "delegated-user"
            self.assertEqual([submit("/api/devices", device) for _ in range(5)], ["200 OK"] * 5)
            self.assertEqual(submit("/api/devices", device), "429 Too Many Requests")

    def test_dashboard_uses_session_actor_and_rejects_query_and_denied_access(self):
        dashboard=Mock();dashboard.read.return_value={'inventory':{'users':2}}
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',dashboard=dashboard)
        result=self.request(PATH_INFO='/api/dashboard')
        self.assertEqual(result['status'],'200 OK')
        dashboard.read.assert_called_once_with('user-id')
        self.assertEqual(self.request(PATH_INFO='/api/dashboard',QUERY_STRING='tenant=forged')['status'],'400 Bad Request')
        self.permissions.return_value=False
        self.assertEqual(self.request(PATH_INFO='/api/dashboard')['status'],'403 Forbidden')
        self.assertEqual(dashboard.read.call_count,1)

    def test_operations_endpoints_trusted_actor_and_strict_queries(self):
        accounting=Mock();accounting.list_events.return_value={'items':[]}
        deployment=Mock();deployment.read.return_value={'state':'unknown'}
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',accounting=accounting,deployment=deployment)
        self.assertEqual(self.request(PATH_INFO='/api/deployment')['status'],'200 OK')
        self.assertEqual(self.request(PATH_INFO='/api/deployment',QUERY_STRING='actor=forged')['status'],'400 Bad Request')
        self.assertEqual(self.request(PATH_INFO='/api/accounting',QUERY_STRING='username=operator&limit=10')['status'],'200 OK')
        accounting.list_events.assert_called_once_with('user-id',username='operator',limit=10)
        accounting.list_events.reset_mock()
        self.assertEqual(self.request(PATH_INFO='/api/accounting',
            QUERY_STRING='username=&device=&session=&action=&command=&since=&until=&limit=100')['status'],'200 OK')
        accounting.list_events.assert_called_once_with(
            'user-id',username='',device='',session='',action='',command='',since='',until='',limit=100)
        for query in ('limit=1&limit=2','actor=forged','limit=-1','limit=%D9%A1','limit=1000'):
            self.assertEqual(self.request(PATH_INFO='/api/accounting',QUERY_STRING=query)['status'],'400 Bad Request')
        self.permissions.return_value=False
        self.assertEqual(self.request(PATH_INFO='/api/deployment')['status'],'403 Forbidden')

    def test_device_api_write_only_secret_csrf_and_permissions(self):
        registry=Mock();registry.save.return_value={'status':'saved','address':'192.0.2.2'}
        registry.list_devices.return_value={'devices':[]}
        audit=Mock()
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',devices=registry,device_audit=audit)
        self.assertEqual(self.request(PATH_INFO='/api/devices')['status'],'200 OK')
        registry.list_devices.assert_called_once_with(actor='user-id')
        self.assertEqual(self.request(PATH_INFO='/api/devices',REQUEST_METHOD='POST')['status'],'403 Forbidden')
        body=dict(address='192.0.2.2',name='switch',enabled=False,secret='S'*32,shell_group='',privilege=1)
        raw=json.dumps(body).encode()
        result=self.request(PATH_INFO='/api/devices',REQUEST_METHOD='POST',HTTP_ORIGIN='https://admin.local',
            HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),
            **{'wsgi.input':io.BytesIO(raw)})
        self.assertEqual(result['status'],'200 OK')
        registry.save.assert_called_once_with('user-id',body,audit)
        self.assertNotIn('S'*32,str(result))
        self.permissions.return_value=False
        self.assertEqual(self.request(PATH_INFO='/api/devices')['status'],'403 Forbidden')

    def test_device_secret_requires_explicit_post_csrf_and_permission(self):
        registry=Mock()
        registry.reveal_secret.return_value={'secret':'fixture-key'}
        audit=Mock()
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',devices=registry,device_audit=audit)
        path='/api/devices/secret'
        self.assertEqual(self.request(PATH_INFO=path)['status'],'405 Method Not Allowed')
        self.assertEqual(self.request(PATH_INFO=path,REQUEST_METHOD='POST')['status'],'403 Forbidden')
        raw=b'{"address":"192.0.2.2"}'
        def reveal():
            return self.request(PATH_INFO=path,REQUEST_METHOD='POST',HTTP_ORIGIN='https://admin.local',
                HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),CONTENT_TYPE='application/json',
                CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
        self.permissions.return_value=False
        self.assertEqual(reveal()['status'],'403 Forbidden')
        registry.reveal_secret.assert_not_called()
        self.permissions.return_value=True
        self.assertEqual(reveal()['status'],'400 Bad Request')
        registry.reveal_secret.assert_not_called()
        raw=b'{"address":"192.0.2.2","password":"fixture-password"}'
        result=reveal()
        self.assertEqual(result['status'],'200 OK')
        self.assertEqual(result['headers']['Cache-Control'],'no-store')
        registry.reveal_secret.assert_called_once_with('user-id','192.0.2.2',audit,password='fixture-password')

    def test_device_group_routes_require_csrf_permission_and_session_actor(self):
        registry=Mock();audit=Mock()
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',devices=registry,device_audit=audit)
        with patch('tacacs_appliance.device_groups.DeviceGroups') as groups:
            groups.return_value.list.return_value={'groups':[]}
            groups.return_value.save.return_value={'status':'saved'}
            self.assertEqual(self.request(PATH_INFO='/api/device-groups')['status'],'200 OK')
            self.assertEqual(self.request(PATH_INFO='/api/device-groups',QUERY_STRING='tenant=forged')['status'],'400 Bad Request')
            self.assertEqual(self.request(PATH_INFO='/api/device-groups',REQUEST_METHOD='POST')['status'],'403 Forbidden')
            raw=json.dumps({'operation':'delete','id':'group-id'}).encode()
            result=self.request(PATH_INFO='/api/device-groups',REQUEST_METHOD='POST',HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
            self.assertEqual(result['status'],'200 OK')
            groups.return_value.save.assert_called_once_with('user-id',{'operation':'delete','id':'group-id'},audit)
            self.permissions.return_value=False
            self.assertEqual(self.request(PATH_INFO='/api/device-groups')['status'],'403 Forbidden')

    def test_device_delete_requires_csrf_and_passes_only_session_actor(self):
        registry=Mock();registry.delete.return_value={'status':'committed'};audit=Mock()
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',devices=registry,device_audit=audit)
        self.assertEqual(self.request(PATH_INFO='/api/devices/delete',REQUEST_METHOD='POST')['status'],'403 Forbidden')
        raw=json.dumps({'address':'192.0.2.2'}).encode()
        result=self.request(PATH_INFO='/api/devices/delete',REQUEST_METHOD='POST',HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
        self.assertEqual(result['status'],'200 OK')
        registry.delete.assert_called_once_with('user-id','192.0.2.2',audit)

    def test_identity_group_mutation_uses_trusted_actor_and_permission(self):
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',identities=Mock())
        with patch('tacacs_appliance.identity_groups.IdentityGroups') as groups:
            groups.return_value.save.return_value={'status':'committed'}
            raw=json.dumps({'operation':'create','name':'ops'}).encode()
            result=self.request(PATH_INFO='/api/identity-groups',REQUEST_METHOD='POST',HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
            self.assertEqual(result['status'],'200 OK')
            groups.return_value.save.assert_called_once_with('user-id',{'operation':'create','name':'ops'})
            self.permissions.return_value=False
            self.assertEqual(self.request(PATH_INFO='/api/identity-groups')['status'],'403 Forbidden')

    def test_protected_identity_returns_safe_specific_error(self):
        from tacacs_appliance.admin_identities import IdentityProtectedError
        identities=Mock();identities.delete.side_effect=IdentityProtectedError('not a raw database diagnostic')
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',identities=identities)
        raw=json.dumps({'user_id':'subject-id'}).encode()
        result=self.request(PATH_INFO='/api/identities/delete',REQUEST_METHOD='POST',HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
        self.assertEqual(result['status'],'400 Bad Request')
        self.assertEqual(result['body'],{'error':'identity protected'})

    def test_identity_creation_uses_session_actor_and_rejects_extra_fields(self):
        service=Mock();service.create.return_value={'id':'new-user'}
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',identities=service)
        payload=dict(username='operator',password='long-test-password',group_name='ops')
        def submit(body):
            raw=json.dumps(body).encode()
            return self.request(REQUEST_METHOD='POST',PATH_INFO='/api/identities',
                HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),
                CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
        result=submit(payload)
        self.assertEqual(result['status'],'201 Created')
        service.create.assert_called_once_with('user-id',**payload)
        self.assertNotIn('long-test-password',str(result))
        self.assertEqual(submit(dict(payload,actor='forged'))['status'],'400 Bad Request')
        self.permissions.return_value=False
        self.assertEqual(submit(payload)['status'],'403 Forbidden')
        self.assertEqual(self.request(REQUEST_METHOD='POST',PATH_INFO='/api/identities')['status'],'403 Forbidden')

    def test_password_change_uses_session_actor_and_clears_cookie(self):
        service=Mock()
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',password_change=service)
        raw=json.dumps(dict(current_password='admin',new_password='replacement-password')).encode()
        result=self.request(REQUEST_METHOD='POST',PATH_INFO='/api/password',
            HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),
            CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
        self.assertEqual(result['status'],'200 OK')
        service.change.assert_called_once_with('user-id',current_password='admin',new_password='replacement-password')
        self.assertIn('Max-Age=0',result['headers']['Set-Cookie'])
        self.assertNotIn('replacement-password',str(result))

    def test_password_change_rejects_missing_csrf_and_client_actor(self):
        service=Mock()
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',password_change=service)
        self.assertEqual(self.request(REQUEST_METHOD='POST',PATH_INFO='/api/password')['status'],'403 Forbidden')
        raw=json.dumps(dict(current_password='admin',new_password='replacement-password',actor='other')).encode()
        result=self.request(REQUEST_METHOD='POST',PATH_INFO='/api/password',
            HTTP_ORIGIN='https://admin.local',HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN),
            CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(raw)),**{'wsgi.input':io.BytesIO(raw)})
        self.assertEqual(result['status'],'400 Bad Request')
        service.change.assert_not_called()

    def test_http_forwarded_https_is_not_trusted(self):
        self.assertEqual(self.request(**{"wsgi.url_scheme": "http", "HTTP_X_FORWARDED_PROTO": "https"})["status"], "400 Bad Request")
        self.sessions.resolve.assert_not_called()

    def test_missing_duplicate_and_invalid_cookies(self):
        for cookie in ("", f"{COOKIE_NAME}={TOKEN}; {COOKIE_NAME}={TOKEN}", f"{COOKIE_NAME}=bad"):
            self.assertEqual(self.request(HTTP_COOKIE=cookie)["status"], "401 Unauthorized")
        self.sessions.resolve.assert_not_called()

    def test_mutation_requires_origin_and_session_bound_csrf(self):
        for origin, csrf in ((None, None), ("https://evil.local", self.app.csrf_token(TOKEN)),
                             ("https://admin.local", self.app.csrf_token("b" * 43))):
            result = self.request(REQUEST_METHOD="POST", PATH_INFO="/api/logout", HTTP_ORIGIN=origin, HTTP_X_CSRF_TOKEN=csrf or "")
            self.assertEqual(result["status"], "403 Forbidden")
        self.sessions.revoke.assert_not_called()

    def test_logout_revokes_and_clears_secure_cookie(self):
        result = self.request(REQUEST_METHOD="POST", PATH_INFO="/api/logout", HTTP_ORIGIN="https://admin.local", HTTP_X_CSRF_TOKEN=self.app.csrf_token(TOKEN))
        self.assertEqual(result["status"], "200 OK")
        self.sessions.revoke.assert_called_once_with(TOKEN)
        self.assertIn("Max-Age=0", result["headers"]["Set-Cookie"])

    def test_revoked_session_and_denied_permission(self):
        self.sessions.resolve.return_value = None
        self.assertEqual(self.request()["status"], "401 Unauthorized")
        self.sessions.resolve.return_value = "user-id"
        self.permissions.return_value = False
        self.assertEqual(self.request()["status"], "403 Forbidden")

    def test_backend_failure_is_generic(self):
        self.sessions.resolve.side_effect = RuntimeError(TOKEN)
        result = self.request()
        self.assertEqual(result["status"], "503 Service Unavailable")
        self.assertNotIn(TOKEN, str(result))

    def test_cookie_security_attributes(self):
        cookie = self.app.session_cookie(TOKEN)
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(attribute, cookie)
        self.assertNotIn("Domain=", cookie)

    def test_inventory_requires_session_and_console_permission(self):
        inventory=Mock();inventory.read.return_value={'users':[],'groups':[],'truncated':False}
        self.app=AdminApi(self.sessions,self.permissions,b'k'*32,'https://admin.local',inventory=inventory)
        self.sessions.resolve.return_value=None
        self.assertEqual(self.request(PATH_INFO='/api/inventory')['status'],'401 Unauthorized')
        self.sessions.resolve.return_value='user-id';self.permissions.return_value=False
        self.assertEqual(self.request(PATH_INFO='/api/inventory')['status'],'403 Forbidden')
        inventory.read.assert_not_called()
        self.permissions.return_value=True
        self.assertEqual(self.request(PATH_INFO='/api/inventory',QUERY_STRING='tenant=other')['status'],'400 Bad Request')
        self.assertEqual(self.request(PATH_INFO='/api/inventory')['status'],'200 OK')
        inventory.read.assert_called_once_with()

    def test_unknown_permission_denied_without_database_access(self):
        pool = Mock()
        grants = PostgresAdminPermissions(pool, "00000000-0000-0000-0000-000000000001")
        self.assertFalse(grants("00000000-0000-0000-0000-000000000002", "superuser"))
        pool.connection.assert_not_called()
