"""Keep the standalone UI fixture isolated from production writes/credentials."""
import http.client
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import ThreadingHTTPServer

spec=importlib.util.spec_from_file_location('ui_fixture',Path(__file__).resolve().parents[1]/'scripts/preview_console_fixture.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class PreviewFixtureTests(unittest.TestCase):
    def request(self,path,payload,enabled,method='POST'):
        handler=type('TestFixture',(fixture.FixtureHandler,),{'simulation_fixture':enabled})
        server=ThreadingHTTPServer(('127.0.0.1',0),handler)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        client=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
        try:
            client.request(method,path,json.dumps(payload) if payload is not None else None,{'Content-Type':'application/json'})
            response=client.getresponse();return response.status,response.read()
        finally:client.close();server.shutdown();server.server_close();thread.join(3)

    def test_default_fixture_rejects_all_posts(self):
        status,_=self.request('/api/policies/'+fixture.VERSION+'/simulate',{'samples':[{}]},False)
        self.assertEqual(status,405)

    def test_replay_fixture_never_claims_real_verification_or_echoes_samples(self):
        path='/api/policies/'+fixture.VERSION+'/simulation-records/'+fixture.REPORT_IDS[0]+'/verify'
        status,body=self.request(path,{'samples':[{'command':'private-fixture-value'}]},True)
        self.assertEqual(status,200);self.assertNotIn(b'private-fixture-value',body)
        result=json.loads(body)
        self.assertFalse(result['samples_match']);self.assertFalse(result['rules_match'])
        self.assertIsNone(result['decisions_match']);self.assertEqual(result['coverage'],'UI-fixture-only')
        self.assertEqual(self.request(path,{'samples':[{}]},False)[0],405)

    def test_optional_simulation_is_fixed_and_does_not_echo_input(self):
        status,body=self.request('/api/policies/'+fixture.VERSION+'/simulate',{'samples':[{'command':'test-only-private-value'},{}]},True)
        self.assertEqual(status,200);self.assertNotIn(b'test-only-private-value',body)
        report=json.loads(body);self.assertEqual(report['coverage'],'UI-fixture-only');self.assertEqual(report['newly_allowed'],[0])

    def test_simulation_option_never_enables_login_or_policy_mutations(self):
        for path in ('/api/login','/api/policies','/api/policies/'+fixture.VERSION+'/activate',
                     '/api/policies/'+fixture.VERSION+'/simulation-records'):
            status,_=self.request(path,{},True)
            self.assertEqual(status,405)

    def test_saved_evidence_fixture_is_opt_in_fixed_and_paginated(self):
        path='/api/policies/'+fixture.VERSION+'/simulation-records'
        self.assertEqual(self.request(path,None,False,'GET')[0],404)
        status,body=self.request(path,None,True,'GET')
        self.assertEqual(status,200);page=json.loads(body)
        self.assertEqual(page['next_before'],fixture.REPORT_IDS[0])
        status,body=self.request(path+'?before='+page['next_before'],None,True,'GET')
        self.assertEqual(status,200);self.assertIsNone(json.loads(body)['next_before'])
        status,body=self.request(path+'/'+fixture.REPORT_IDS[0],None,True,'GET')
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['report']['coverage'],'UI-fixture-only')

    def test_evidence_fixture_does_not_accept_arbitrary_ids_or_queries(self):
        path='/api/policies/'+fixture.VERSION+'/simulation-records'
        self.assertEqual(self.request(path+'?before=arbitrary',None,True,'GET')[0],400)
        self.assertEqual(self.request(path+'/arbitrary',None,True,'GET')[0],404)
