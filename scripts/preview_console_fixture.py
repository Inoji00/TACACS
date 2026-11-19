"""UI-only disposable fixture. Never connects to PostgreSQL or runs AAA."""
import json
import argparse
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT=Path(__file__).resolve().parents[1]/'src/tacacs_appliance/console'
VERSION='00000000-0000-0000-0000-000000000042'
POLICY=dict(version_id=VERSION,revision=1,state='approval',author_id='fixture-author',approver_id=None)
REPORT_IDS=('00000000-0000-0000-0000-000000000043','00000000-0000-0000-0000-000000000044')


def fixed_impact(count):
    comparisons=[]
    for index in range(count):
        baseline=dict(decision='deny',matched_policy=None,policy_version='fixture-default-deny',explanation='UI fixture',risk='unassessed',required_mfa=None,obligations=None)
        candidate=baseline|dict(decision='allow' if index==0 else 'deny',matched_policy='fixture-show' if index==0 else None,policy_version=VERSION)
        comparisons.append(dict(index=index,baseline=baseline,candidate=candidate,effect='newly-allowed' if index==0 else 'unchanged'))
    return dict(baseline_version='fixture-default-deny',candidate_version=VERSION,total=count,
                newly_allowed=[0],newly_denied=[],unchanged=count-1,comparisons=comparisons,coverage='UI-fixture-only')


def fixed_summary(index):
    return dict(report_id=REPORT_IDS[index],simulated_by='UI FIXTURE — NO REAL ACTOR',
        created_at=f'2026-10-02T0{8-index}:00:00+00:00',candidate_version=VERSION,
        baseline_version='fixture-default-deny',sample_count=2,integrity_status='not-verified')


class FixtureHandler(SimpleHTTPRequestHandler):
    simulation_fixture=False
    def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(ROOT),**kwargs)
    def do_GET(self):
        routes={'/api/login-options':dict(mfa_required=True),'/api/session':dict(user_id='UI FIXTURE — NO REAL SESSION',csrf_token='f'*64),
            '/api/policies':dict(items=[POLICY],next_before=None),
            '/api/policies/'+VERSION:POLICY,'/api/audit':dict(items=[],next_before=None),
            '/api/deployment':dict(state='unknown',endpoints=[],runtime_acknowledgement='not-measured',switch_test='not-measured'),
            '/api/accounting':dict(items=[],next_before=None,scope='accounting-only'),
            '/api/devices':dict(devices=[dict(address='192.0.2.2',name='UI FIXTURE SWITCH',enabled=False,shell_group='',privilege=1,saved_at='2026-10-29T00:00:00+00:00')],
                next_after=None,search='',truncated=False,application='UI-fixture-only',transport='UI-fixture-only'),
            '/api/inventory':dict(users=[dict(id=VERSION,username='fixture-admin',enabled=True,locked=False)],groups=[],truncated=False)}
        path=self.path.split('?',1)[0]
        evidence='/api/policies/'+VERSION+'/simulation-records'
        if self.simulation_fixture and path==evidence:
            try:
                query=self.path.partition('?')[2]
                fields=parse_qs(query,keep_blank_values=True,strict_parsing=True,max_num_fields=1)
                if fields and fields!={'before':[REPORT_IDS[0]]}:raise ValueError()
            except ValueError:self.send_error(400,'Invalid fixture query');return
            index=1 if fields else 0
            routes[path]=dict(items=[fixed_summary(index)],next_before=REPORT_IDS[0] if index==0 else None)
        elif self.simulation_fixture and path.startswith(evidence+'/'):
            report_id=path[len(evidence)+1:]
            if report_id not in REPORT_IDS or '?' in self.path:self.send_error(404,'Unknown fixture report');return
            routes[path]=fixed_summary(REPORT_IDS.index(report_id))|dict(baseline_rules_digest='a'*64,
                candidate_rules_digest='b'*64,samples_digest='c'*64,report=fixed_impact(2))
        if path not in routes:return super().do_GET()
        body=json.dumps(routes[path]).encode()
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
        self.end_headers();self.wfile.write(body)
    def do_POST(self):
        # Drain a bounded body before denying mutations; closing a socket with
        # unread bytes can reset the response on Windows. Fixture only, not the
        # production HTTPS request boundary.
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=65536:raise ValueError()
            self.connection.settimeout(3)
            raw=self.rfile.read(length)
            if len(raw)!=length:raise ValueError()
        except (ValueError,OSError):self.send_error(400,'Invalid fixture body');return
        replay_prefix='/api/policies/'+VERSION+'/simulation-records/'
        replay_id=self.path[len(replay_prefix):-len('/verify')] if self.path.startswith(replay_prefix) and self.path.endswith('/verify') else None
        if self.simulation_fixture and (self.path=='/api/policies/'+VERSION+'/simulate' or replay_id in REPORT_IDS):
            # Fixed UI fixtures only; no evaluator/database/authentication and
            # no submitted values echoed. Every mutation route stays rejected.
            try:
                if self.headers.get('Content-Type')!='application/json' or not 1<=length<=65536:raise ValueError()
                payload=json.loads(raw)
                if not isinstance(payload,dict) or set(payload)!={'samples'}:raise ValueError()
                samples=payload['samples']
                if not isinstance(samples,list) or not 1<=len(samples)<=1024:raise ValueError()
                result=fixed_impact(len(samples)) if replay_id is None else dict(report_id=replay_id,
                    candidate_version=VERSION,baseline_version='fixture-default-deny',samples_match=False,
                    rules_match=False,decisions_match=None,integrity_status='not-verified',coverage='UI-fixture-only')
                body=json.dumps(result).encode()
                self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
                self.end_headers();self.wfile.write(body)
                return
            except (ValueError,TypeError):self.send_error(400,'Invalid fixture request');return
        # No writes, credential handling or actual policy transitions in preview.
        self.send_error(405,'UI fixture is read-only')
    def log_message(self,*args):pass


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Disposable read-only UI fixture')
    parser.add_argument('--simulation-fixture',action='store_true',help='enable fixed, non-mutating simulation responses only')
    FixtureHandler.simulation_fixture=parser.parse_args().simulation_fixture
    print('Read-only UI fixture on http://127.0.0.1:8765; no database or AAA service.',flush=True)
    with ThreadingHTTPServer(('127.0.0.1',8765),FixtureHandler) as server:
        try:server.serve_forever()
        except KeyboardInterrupt:pass
