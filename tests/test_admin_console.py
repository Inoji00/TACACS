import unittest
from unittest.mock import Mock
from tacacs_appliance.admin_console import AdminConsole


class AdminConsoleTests(unittest.TestCase):
    def request(self,path='/',method='GET',scheme='https'):
        api=Mock(return_value=[b'api'])
        start=Mock()
        body=b''.join(AdminConsole(api)({'PATH_INFO':path,'REQUEST_METHOD':method,'wsgi.url_scheme':scheme},start))
        return body,start,api

    def test_english_offline_console_has_security_headers(self):
        body,start,api=self.request()
        self.assertIn(b'<html lang="en">',body)
        self.assertIn(b'Administrator sign-in',body)
        headers=dict(start.call_args.args[1])
        self.assertIn("script-src 'self'",headers['Content-Security-Policy'])
        self.assertNotIn('unsafe-inline',headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(int(headers['Content-Length']),len(body))
        api.assert_not_called()

    def test_bundled_assets_are_served_with_correct_types(self):
        for path,kind in (('/console.js','text/javascript'),('/connection-guide.js','text/javascript'),('/device-syslog.js','text/javascript'),('/console.css','text/css'),('/login-tnac.svg','image/svg+xml')):
            body,start,api=self.request(path)
            self.assertTrue(body)
            self.assertTrue(dict(start.call_args.args[1])['Content-Type'].startswith(kind))
            api.assert_not_called()

    def test_asset_urls_and_build_header_match_actual_javascript(self):
        import hashlib
        script,_,_=self.request('/console.js')
        html,start,_=self.request('/')
        digest=hashlib.sha256(script).hexdigest()[:16]
        self.assertIn(('/console.js?v='+digest).encode(),html)
        guide,_,_=self.request('/connection-guide.js')
        guide_url=('/connection-guide.js?v='+hashlib.sha256(guide).hexdigest()[:16]).encode()
        self.assertLess(html.index(guide_url),html.index(('/console.js?v='+digest).encode()))
        self.assertNotIn(b'v=workspace1',html)
        self.assertEqual(dict(start.call_args.args[1])['X-Console-Build'],digest)

    def test_head_omits_body_and_keeps_length(self):
        body,start,_=self.request(method='HEAD')
        self.assertEqual(body,b'')
        self.assertGreater(int(dict(start.call_args.args[1])['Content-Length']),0)

    def test_plaintext_and_asset_mutation_are_rejected(self):
        for method,scheme,status in (('GET','http','400'),('POST','https','405')):
            body,start,api=self.request(method=method,scheme=scheme)
            self.assertTrue(start.call_args.args[0].startswith(status));api.assert_not_called()

    def test_non_assets_and_traversal_delegate_without_file_access(self):
        for path in ('/api/session','/../runtime.py','/console/../../runtime.py'):
            body,_,api=self.request(path)
            self.assertEqual(body,b'api');api.assert_called_once()
