"""Offline administration console assets, served only from an explicit allow-list."""
from importlib.resources import files
import hashlib


class AdminConsole:
    def __init__(self,api):
        self.api=api
        root=files('tacacs_appliance').joinpath('console')
        self.versions={name:hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest() for name in ('console.js','console.css')}

    def __call__(self,environment,start_response):
        path=environment.get('PATH_INFO','')
        assets={'/':('index.html','text/html; charset=utf-8'),
                '/console.css':('console.css','text/css; charset=utf-8'),
                '/console.js':('console.js','text/javascript; charset=utf-8'),
                '/login-tnac.svg':('login-tnac.svg','image/svg+xml')}
        if path not in assets:return self.api(environment,start_response)
        if environment.get('wsgi.url_scheme')!='https':
            start_response('400 Bad Request',[('Content-Length','0'),('Cache-Control','no-store')]);return [b'']
        if environment.get('REQUEST_METHOD') not in ('GET','HEAD'):
            start_response('405 Method Not Allowed',[('Content-Length','0'),('Allow','GET, HEAD')]);return [b'']
        name,content_type=assets[path]
        content=files('tacacs_appliance').joinpath('console',name).read_bytes()
        if name=='index.html':
            for asset,digest in self.versions.items():
                content=content.replace(('/'+asset+'?v=workspace1').encode(),('/'+asset+'?v='+digest[:16]).encode())
        start_response('200 OK',[
            ('Content-Type',content_type),('Content-Length',str(len(content))),('Cache-Control','no-store'),
            ('X-Content-Type-Options','nosniff'),('Referrer-Policy','no-referrer'),
            ('X-Console-Build',self.versions['console.js'][:16]),
            ('Strict-Transport-Security','max-age=31536000'),
            ('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")])
        return [content if environment['REQUEST_METHOD']=='GET' else b'']
