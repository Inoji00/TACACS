"""Read-only comparison of the served JavaScript and the expected release."""
import argparse
import hashlib
from html.parser import HTMLParser
import json
import ssl
import sys
from urllib.parse import urljoin,urlsplit
from urllib.request import urlopen
from vm_appliance import DIRECTORY
import local_appliance as local


class Scripts(HTMLParser):
    def __init__(self):super().__init__();self.sources=[]
    def handle_starttag(self,tag,attrs):
        if tag=='script' and dict(attrs).get('src'):self.sources.append(dict(attrs)['src'])


def verify(origin,expected,context):
    url=urlsplit(origin)
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.path not in ('','/') or url.query or url.fragment:raise ValueError('HTTPS origin required')
    origin=origin.rstrip('/')
    with urlopen(origin+'/',context=context,timeout=10) as response:
        if urlsplit(response.geturl()).netloc!=url.netloc:raise ValueError('unexpected origin')
        html=response.read(1024*1024)
        build=response.headers.get('X-Console-Build','not reported')
    parser=Scripts();parser.feed(html.decode('utf-8'))
    sources=[source for source in parser.sources if urlsplit(source).path=='/console.js' and not urlsplit(source).netloc and not urlsplit(source).scheme]
    if len(sources)!=1:raise ValueError('console asset not found')
    with urlopen(urljoin(origin+'/',sources[0]),context=context,timeout=10) as response:
        if urlsplit(response.geturl()).netloc!=url.netloc:raise ValueError('unexpected asset origin')
        script=response.read(2*1024*1024)
    digest=hashlib.sha256(script).hexdigest()
    return dict(matches_release=digest==expected['console_js_sha256'],served_sha256=digest,expected_sha256=expected['console_js_sha256'],
        asset_url=sources[0],build=build,delete_policy_code_present=b'Delete policy' in script,edit_policy_code_present=b'Edit as new draft' in script)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--origin');args=parser.parse_args()
    try:
        profile=json.loads((DIRECTORY/'vm-profile.json').read_text())
        origin=args.origin or 'https://'+(profile.get('admin_domain') or profile.get('admin_ip') or profile['server_ip'])+':8443'
        expected=json.loads((local.ROOT/'artifacts/ui-release.json').read_text())
        context=ssl.create_default_context(cafile=str(DIRECTORY/'localhost-ca.pem'))
        result=verify(origin,expected,context);print(json.dumps(result,indent=2))
        return 0 if result['matches_release'] else 1
    except Exception as error:
        print('UI verification failed ('+type(error).__name__+'). No configuration was changed.',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
