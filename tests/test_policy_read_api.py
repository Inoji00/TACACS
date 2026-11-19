import json,unittest
from unittest.mock import Mock
from tacacs_appliance.admin_api import AdminApi,COOKIE_NAME


class PolicyReadTests(unittest.TestCase):
    def test_list_uses_session_actor_and_validated_cursor(self):
        sessions=Mock();sessions.resolve.return_value='trusted'
        policies=Mock();policies.list_versions.return_value={'items':[],'next_before':None}
        app=AdminApi(sessions,Mock(),b'k'*32,'https://admin.local',policies=policies)
        start=Mock()
        body=b''.join(app({'wsgi.url_scheme':'https','REQUEST_METHOD':'GET','PATH_INFO':'/api/policies',
            'QUERY_STRING':'before=42&limit=10','HTTP_COOKIE':f'{COOKIE_NAME}={"a"*43}'},start))
        self.assertEqual(start.call_args.args[0],'200 OK')
        self.assertEqual(json.loads(body)['items'],[])
        policies.list_versions.assert_called_once_with('trusted',before=42,limit=10)

    def test_list_rejects_duplicate_unknown_and_non_numeric_parameters(self):
        for query in ('before=1&before=2','tenant=foreign','limit=-1','before=','limit=1&before=2&extra=3'):
            sessions=Mock();sessions.resolve.return_value='trusted';policies=Mock();start=Mock()
            app=AdminApi(sessions,Mock(),b'k'*32,'https://admin.local',policies=policies)
            list(app({'wsgi.url_scheme':'https','REQUEST_METHOD':'GET','PATH_INFO':'/api/policies',
                'QUERY_STRING':query,'HTTP_COOKIE':f'{COOKIE_NAME}={"a"*43}'},start))
            self.assertEqual(start.call_args.args[0],'400 Bad Request');policies.list_versions.assert_not_called()

    def test_read_uses_trusted_actor_and_no_store(self):
        sessions=Mock();sessions.resolve.return_value="trusted"
        policies=Mock();policies.inspect.return_value={"version_id":"v","rules":[],"test_report":None}
        app=AdminApi(sessions,Mock(),b"k"*32,"https://admin.local",policies=policies)
        result={}
        def start(status,headers):result.update(status=status,headers=dict(headers))
        body=b"".join(app({"wsgi.url_scheme":"https","REQUEST_METHOD":"GET","PATH_INFO":"/api/policies/v",
                          "HTTP_COOKIE":f"{COOKIE_NAME}={'a'*43}"},start))
        self.assertEqual(result["status"],"200 OK")
        self.assertEqual(result["headers"]["Cache-Control"],"no-store")
        self.assertEqual(json.loads(body)["version_id"],"v")
        policies.inspect.assert_called_once_with("v","trusted")
