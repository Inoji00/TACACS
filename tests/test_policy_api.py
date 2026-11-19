import io,json,unittest
from unittest.mock import Mock
from tacacs_appliance.admin_api import AdminApi,COOKIE_NAME


class PolicyApiTests(unittest.TestCase):
    def setUp(self):
        self.sessions=Mock();self.sessions.resolve.return_value="trusted-actor"
        self.policies=Mock();self.policies.draft.return_value="new-version"
        self.simulation=Mock();self.simulation.compare.return_value={'coverage':'provided-samples-only'}
        self.app=AdminApi(self.sessions,Mock(),b"k"*32,"https://admin.local",policies=self.policies,simulation=self.simulation)

    def test_simulation_uses_session_actor_and_does_not_call_mutation_repository(self):
        samples=[dict(subject='sample',device_id='router',command='show',groups=[])]
        result=self.request('/api/policies/version/simulate',{'samples':samples})
        self.assertEqual(result['status'],'200 OK')
        self.simulation.compare.assert_called_once_with('version','trusted-actor',samples)
        self.policies.draft.assert_not_called();self.policies.transition.assert_not_called()

    def test_simulation_rejects_client_actor_and_missing_csrf(self):
        self.assertEqual(self.request('/api/policies/version/simulate',{'samples':[],'actor':'fake'})['status'],'400 Bad Request')
        self.assertEqual(self.request('/api/policies/version/simulate',{'samples':[]},False)['status'],'403 Forbidden')
        self.simulation.compare.assert_not_called()

    def test_simulation_permission_and_database_failure_are_generic(self):
        self.simulation.compare.side_effect=PermissionError('private diagnostic')
        result=self.request('/api/policies/version/simulate',{'samples':[]})
        self.assertEqual(result['status'],'403 Forbidden');self.assertNotIn('diagnostic',str(result))
        self.simulation.compare.side_effect=RuntimeError('private database secret')
        result=self.request('/api/policies/version/simulate',{'samples':[]})
        self.assertEqual(result['status'],'503 Service Unavailable');self.assertNotIn('secret',str(result))

    def test_recorded_simulation_is_explicit_write_with_session_actor(self):
        self.simulation.record.return_value={'report_id':'new-report','report':{'coverage':'provided-samples-only'}}
        samples=[dict(subject='sample',device_id='router',command='show',groups=[])]
        result=self.request('/api/policies/version/simulation-records',{'samples':samples})
        self.assertEqual(result['status'],'201 Created')
        self.simulation.record.assert_called_once_with('version','trusted-actor',samples)
        self.simulation.compare.assert_not_called();self.policies.transition.assert_not_called()

    def test_recorded_simulation_requires_csrf_and_rejects_client_report_or_actor(self):
        path='/api/policies/version/simulation-records'
        self.assertEqual(self.request(path,{'samples':[]},False)['status'],'403 Forbidden')
        self.assertEqual(self.request(path,{'samples':[],'actor':'fake'})['status'],'400 Bad Request')
        self.assertEqual(self.request(path,{'samples':[],'report':{}})['status'],'400 Bad Request')
        self.simulation.record.assert_not_called()

    def test_recorded_simulation_failed_commit_is_not_created(self):
        self.simulation.record.side_effect=RuntimeError('private audit diagnostic')
        result=self.request('/api/policies/version/simulation-records',{'samples':[]})
        self.assertEqual(result['status'],'503 Service Unavailable');self.assertNotIn('diagnostic',str(result))

    def test_replay_requires_csrf_exact_samples_and_session_actor(self):
        path='/api/policies/version/simulation-records/record/verify'
        self.simulation.verify_record.return_value={'samples_match':True,'integrity_status':'not-verified'}
        self.assertEqual(self.request(path,{'samples':[]},False)['status'],'403 Forbidden')
        self.assertEqual(self.request(path,{'samples':[],'actor':'fake'})['status'],'400 Bad Request')
        result=self.request(path,{'samples':[]})
        self.assertEqual(result['status'],'200 OK')
        self.simulation.verify_record.assert_called_once_with('version','trusted-actor','record',[])
        self.simulation.record.assert_not_called();self.policies.transition.assert_not_called()

    def test_replay_missing_record_and_failures_are_generic(self):
        path='/api/policies/version/simulation-records/record/verify'
        self.simulation.verify_record.return_value=None
        self.assertEqual(self.request(path,{'samples':[]})['status'],'404 Not Found')
        for error,status in ((PermissionError('private'), '403 Forbidden'),(RuntimeError('private'),'503 Service Unavailable')):
            self.simulation.verify_record.side_effect=error
            result=self.request(path,{'samples':[]})
            self.assertEqual(result['status'],status);self.assertNotIn('private',str(result))

    def get(self,path,query='',authenticated=True):
        result={}
        environ={'wsgi.url_scheme':'https','REQUEST_METHOD':'GET','PATH_INFO':path,
                 'QUERY_STRING':query,'HTTP_COOKIE':f'{COOKIE_NAME}={"a"*43}' if authenticated else ''}
        def start(status,headers):result['status']=status;result['headers']=dict(headers)
        result['body']=json.loads(b''.join(self.app(environ,start)))
        return result

    def test_evidence_list_and_detail_use_session_actor_without_writes(self):
        self.simulation.list_records.return_value={'items':[],'next_before':None}
        result=self.get('/api/policies/version/simulation-records','before=cursor&limit=10')
        self.assertEqual(result['status'],'200 OK');self.assertEqual(result['headers']['Cache-Control'],'no-store')
        self.simulation.list_records.assert_called_once_with('version','trusted-actor',before='cursor',limit=10)
        self.simulation.inspect_record.return_value={'report_id':'record'}
        self.assertEqual(self.get('/api/policies/version/simulation-records/record')['status'],'200 OK')
        self.simulation.inspect_record.assert_called_once_with('version','trusted-actor','record')
        self.simulation.record.assert_not_called();self.policies.transition.assert_not_called()

    def test_evidence_reads_require_session_and_handle_unknown_record_generically(self):
        self.assertEqual(self.get('/api/policies/version/simulation-records',authenticated=False)['status'],'401 Unauthorized')
        self.simulation.list_records.assert_not_called()
        self.simulation.list_records.return_value=None
        self.assertEqual(self.get('/api/policies/version/simulation-records')['status'],'404 Not Found')
        self.simulation.inspect_record.return_value=None
        self.assertEqual(self.get('/api/policies/version/simulation-records/record')['status'],'404 Not Found')

    def test_evidence_query_rejects_unknown_duplicate_empty_and_oversized_fields(self):
        for query in ('actor=fake','before=','limit=10&limit=20','limit=abc','limit=100','before='+'a'*129):
            self.assertEqual(self.get('/api/policies/version/simulation-records',query)['status'],'400 Bad Request')
        self.assertEqual(self.get('/api/policies/version/simulation-records/record','actor=fake')['status'],'400 Bad Request')
        self.simulation.list_records.assert_not_called();self.simulation.inspect_record.assert_not_called()

    def test_evidence_permission_and_corrupt_report_errors_are_generic(self):
        self.simulation.inspect_record.side_effect=PermissionError('private grant detail')
        result=self.get('/api/policies/version/simulation-records/record')
        self.assertEqual(result['status'],'403 Forbidden');self.assertNotIn('private',str(result))
        self.simulation.inspect_record.side_effect=RuntimeError('private raw command')
        result=self.get('/api/policies/version/simulation-records/record')
        self.assertEqual(result['status'],'503 Service Unavailable');self.assertNotIn('command',str(result))

    def request(self,path,payload,csrf=True):
        raw=json.dumps(payload).encode();result={}
        environ={"wsgi.url_scheme":"https","REQUEST_METHOD":"POST","PATH_INFO":path,
                 "HTTP_COOKIE":f"{COOKIE_NAME}={'a'*43}","HTTP_ORIGIN":"https://admin.local",
                 "HTTP_X_CSRF_TOKEN":self.app.csrf_token('a'*43) if csrf else "",
                 "CONTENT_TYPE":"application/json","CONTENT_LENGTH":str(len(raw)),"wsgi.input":io.BytesIO(raw)}
        def start(status,headers):result["status"]=status
        result["body"]=json.loads(b"".join(self.app(environ,start)))
        return result

    def test_draft_uses_session_actor(self):
        self.assertEqual(self.request("/api/policies",{"rules":[]})["status"],"201 Created")
        self.policies.draft.assert_called_once_with("trusted-actor",[])

    def test_client_actor_and_missing_csrf_rejected(self):
        self.assertEqual(self.request("/api/policies",{"rules":[],"actor":"fake"})["status"],"400 Bad Request")
        self.assertEqual(self.request("/api/policies",{"rules":[]},False)["status"],"403 Forbidden")
        self.policies.draft.assert_not_called()

    def test_permission_failure_is_generic(self):
        self.policies.transition.side_effect=PermissionError("secret diagnostic")
        result=self.request("/api/policies/version/approve",{})
        self.assertEqual(result["status"],"403 Forbidden")
        self.assertNotIn("diagnostic",str(result))
