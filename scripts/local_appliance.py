"""Persistent loopback-only development launcher. Never resets existing data."""
import argparse
import base64
import hashlib
from datetime import datetime,timedelta,timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
from urllib.request import urlopen
from uuid import UUID,uuid4

ROOT=Path(__file__).resolve().parents[1]
HOME_DIR=ROOT/'data'/'local-appliance'
IMAGE='tnac:current'
POSTGRES_IMAGE='tnac-postgres:16.16-r2'
LEGACY_IMAGE='local-tacacs-appliance:offline-verify'
REFERENCE='secret://local-appliance/admin'


def run(args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=90,**kwargs)


def state(directory):
    if directory.is_symlink():raise ValueError('state links forbidden')
    item=json.loads((directory/'state.json').read_text(encoding='utf-8'))
    if set(item)!={'project','tenant','user','factor'} or not re.fullmatch(r'(?:tnac|tacacs-local)-[0-9a-f]{32}',item['project']):
        raise ValueError('invalid local state')
    UUID(item['tenant'])
    for field in ('user','factor'):
        if item[field] is not None:UUID(item[field])
    return item


def command(directory,item):
    return ['docker','compose','--project-name',item['project'],'-f',str(directory/'compose.json')]


def image_for(project):
    return LEGACY_IMAGE if project.startswith('tacacs-local-') else IMAGE


def local_config(config,project):
    """Keep public ports on host loopback and all service secrets separated."""
    config.pop('name',None);config.pop('secrets',None)
    keys=('config','runtime','provision','dbsecret','admin','alerts')
    config['volumes']={key:{'name':project+'-'+key,'external':True} for key in keys}|{'postgres-data':{}}
    config['networks']={'private':{'external':True,'name':project+'-private'},
                        'local':{'external':True,'name':project+'-local'}}
    services=config['services']
    for key in ('app','initialize','admin'):
        services[key].pop('build',None);services[key]['image']=image_for(project)
        services[key].pop('restart',None)
    services['app']['ports']=['127.0.0.1:49:49/tcp']
    services['app']['networks']=['private','local']
    services['app']['volumes']=['config:/etc/tacacs:ro','runtime:/run/tacacs-secrets:ro']
    services['initialize']['volumes']=['provision:/run/provision:ro']
    services['postgres'].pop('secrets',None)
    services['postgres']['ports']=['127.0.0.1:8443:8443/tcp']
    services['postgres']['networks']={'private':{},'local':{'aliases':['local-console']}}
    services['postgres']['volumes']=['postgres-data:/var/lib/postgresql/data','dbsecret:/run/secrets:ro']
    services['postgres']['healthcheck']['test']=['CMD','pg_isready','-h','127.0.0.1','-U','tacacs_app','-d','tacacs']
    services['admin']['network_mode']='service:postgres'
    services['admin'].pop('networks',None)
    services['admin']['volumes']=['config:/etc/tacacs:ro','admin:/run/admin-secrets:ro','alerts:/run/tnac-alerts']
    services['proxy']=dict(image=image_for(project),user='10001:10001',network_mode='service:postgres',
        command=['python','-m','tacacs_appliance.loopback_proxy','--bind-name','local-console'],
        depends_on={'admin':{'condition':'service_healthy'}},read_only=True,cap_drop=['ALL'],
        security_opt=['no-new-privileges:true'],healthcheck=dict(
            test=['CMD','python','-c',"import socket; socket.create_connection(('local-console',8443),3).close()"],
            interval='5s',timeout='4s',retries=5))
    from logging_defaults import configure
    return configure(config)


def admin_certificate(admin_ip=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'TACACS+ Appliance')])
    now=datetime.now(timezone.utc)
    names=[x509.DNSName('localhost'),x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))]
    if admin_ip is not None:
        names.append(x509.IPAddress(ipaddress.IPv4Address(admin_ip)))
    certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(names),critical=False)
        .sign(key,hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
    private_key=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    return certificate,private_key


def prepare_files(tenant,gateway,*,password_only=False,admin_ip=None):
    # Generated credentials stay inside owner-protected Linux Docker volumes.
    service_config=f'tenant_id = "{tenant}"\ndatabase_dsn_file = "/run/tacacs-secrets/database_dsn"\n'
    if gateway is None:
        service_config+='devices = []\n'
    service_config+='[listener]\nhost = "0.0.0.0"\nport = 49\n'
    password,aaa,admin=(secrets.token_urlsafe(48) for _ in range(3))
    # This host script also runs before the application package is installed.
    operator='Aa1!'+secrets.token_urlsafe(48)
    totp_secret=secrets.token_bytes(32)
    certificate,private_key=admin_certificate(admin_ip)
    from urllib.parse import urlencode
    uri='otpauth://totp/Local%20TACACS:admin?'+urlencode(dict(secret=base64.b32encode(totp_secret).decode().rstrip('='),issuer='Local TACACS',algorithm='SHA256',digits=6,period=30))
    files={
        '/config/device_registry.key':(secrets.token_bytes(32),10001,0o600),
        '/runtime/database_dsn':(f'host=postgres dbname=tacacs user=tacacs_aaa password={aaa}',10001,0o600),
        '/provision/owner_dsn':(f'host=postgres dbname=tacacs user=tacacs_app password={password}',0,0o600),
        '/provision/aaa_password':(aaa,0,0o600),'/provision/admin_password':(admin,0,0o600),
        '/provision/operator_password':(operator,0,0o600),
        '/provision/admin_totp':(totp_secret,0,0o600),
        '/provision/operator-access.json':(json.dumps(dict(username='admin',password=operator,totp_uri=uri)),0,0o600),
        '/dbsecret/postgres_password':(password,70,0o600),
        '/config/admin.toml':(f'tenant_id = "{tenant}"\ndatabase_dsn_file = "/run/admin-secrets/admin_dsn"\norigin = "https://localhost:8443"\nport = 8443\ncsrf_key_file = "/run/admin-secrets/admin_csrf"\ncert_file = "/run/admin-secrets/admin_cert.pem"\nkey_file = "/run/admin-secrets/admin_key.pem"\n[mfa_references]\n"{REFERENCE}" = "/run/admin-secrets/admin_totp"\n',10001,0o644),
        '/admin/admin_dsn':(f'host=127.0.0.1 dbname=tacacs user=tacacs_admin password={admin}',10001,0o600),
        '/admin/admin_csrf':(secrets.token_urlsafe(48),10001,0o600),
        '/admin/admin_totp':(totp_secret,10001,0o600),
        '/admin/admin_cert.pem':(certificate,10001,0o644),
        '/admin/health_ca.pem':(certificate,10001,0o644),
        '/admin/admin_key.pem':(private_key,10001,0o600)}
    if gateway is not None:
        address=ipaddress.IPv4Address(gateway)
        service_config+=f'[[devices]]\naddress = "{address}"\nsecret_file = "/run/tacacs-secrets/device_local"\n'
        files['/runtime/device_local']=(secrets.token_urlsafe(48),10001,0o600)
    files['/config/service.toml']=(service_config,10001,0o644)
    if admin_ip is not None:
        value,owner,mode=files['/config/admin.toml']
        value=value.replace('origin = "https://localhost:8443"',f'origin = "https://{admin_ip}:8443"')
        files['/config/admin.toml']=(f'lan_ip = "{admin_ip}"\n'+value,owner,mode)
    if password_only:
        value,owner,mode=files['/config/admin.toml']
        files['/config/admin.toml']=('local_password_only = true\n'+value,owner,mode)
    for config_name in ('/config/service.toml','/config/admin.toml'):
        value,owner,mode=files[config_name]
        files[config_name]=('device_registry_key_file = "/etc/tacacs/device_registry.key"\n'+value,owner,mode)
    encoded={name:(base64.b64encode(value.encode() if isinstance(value,str) else value).decode(),uid,mode)
             for name,(value,uid,mode) in files.items()}
    return encoded,certificate


SEED="""import base64,json,os,pathlib,sys
data=json.load(sys.stdin)
for root in ('config','runtime','provision','dbsecret','admin','alerts'):
 p=pathlib.Path('/'+root)
 if any(p.iterdir()):raise ValueError('existing volume contents forbidden')
 p.chmod(0o700)
for name,(value,uid,mode) in data.items():
 p=pathlib.Path(name)
 if p.parent.name not in ('config','runtime','provision','dbsecret','admin'):raise ValueError('invalid target')
 with p.open('xb') as stream:stream.write(base64.b64decode(value,validate=True))
 p.chmod(mode);os.chown(p,uid,uid)
for root in ('config','runtime','admin','alerts'):os.chown('/'+root,10001,10001)
os.chown('/dbsecret',70,70)
"""


def initialize(directory,*,vm_server_ip=None,vm_client_ip=None,vm_admin_ip=None,vm_primary=True,password_only=False):
    if vm_server_ip is not None:
        if sys.platform!='linux':raise ValueError('VM profile requires native Linux Docker Engine')
        from vm_appliance import validate_addresses, validate_admin_ip
        vm_server_ip,vm_client_ip=validate_addresses(vm_server_ip,vm_client_ip)
        vm_admin_ip=validate_admin_ip(vm_admin_ip or vm_server_ip)
    if directory.exists():raise ValueError('local installation already exists; never reinitialize')
    bindings=[(vm_server_ip or '127.0.0.1',49)]
    if vm_server_ip is None:
        bindings.append(('127.0.0.1',8443))
    if vm_admin_ip is not None:
        bindings.append((vm_admin_ip,8443))
    for address,port in bindings:
        with socket.socket() as probe:probe.bind((address,port))
    run(['docker','info','--format','{{.ServerVersion}}'])
    run(['docker','image','inspect',IMAGE]);run(['docker','image','inspect',POSTGRES_IMAGE])
    project='tnac-'+uuid4().hex;tenant=str(uuid4())
    environment=os.environ|{'TACACS_TENANT_ID':tenant,'TACACS_MFA_REFERENCE':REFERENCE}
    config=json.loads(run(['docker','compose','-f',str(ROOT/'docker-compose.yml'),'-f',str(ROOT/'docker-compose.initialize.yml'),
        '-f',str(ROOT/'docker-compose.admin.yml'),'config','--format','json'],env=environment,cwd=ROOT).stdout)
    config=local_config(config,project)
    if vm_server_ip:
        from vm_appliance import vm_config
        config=vm_config(config,vm_server_ip,vm_admin_ip)
        from container_names import configure as configure_names
        configure_names(config,project,primary=vm_primary)
    directory.mkdir(parents=True)
    item=dict(project=project,tenant=tenant,user=None,factor=None)
    with (directory/'state.json').open('x',encoding='utf-8') as stream:json.dump(item,stream)
    with (directory/'compose.json').open('x',encoding='utf-8') as stream:json.dump(config,stream)
    run(['docker','network','create','--internal',project+'-private'])
    run(['docker','network','create','--opt','com.docker.network.bridge.host_binding_ipv4=127.0.0.1',project+'-local'])
    bootstrap_device=vm_client_ip
    if vm_server_ip is None:
        network=json.loads(run(['docker','network','inspect',project+'-local']).stdout)[0]
        bootstrap_device=network['IPAM']['Config'][0]['Gateway']
    files,certificate=prepare_files(
        tenant,bootstrap_device,
        password_only=password_only,admin_ip=vm_admin_ip)
    with (directory/'localhost-ca.pem').open('xb') as stream:stream.write(certificate)
    keys=('config','runtime','provision','dbsecret','admin','alerts')
    for name in keys:run(['docker','volume','create',project+'-'+name])
    run(['docker','run','--rm','-i','--network','none','--user','0:0','--cap-drop','ALL',
        '--cap-add','CHOWN','--security-opt','no-new-privileges',
        *[arg for name in keys for arg in ('--mount',f'type=volume,source={project}-{name},target=/{name}')],
        IMAGE,'python','-c',SEED],input=json.dumps(files))
    cmd=command(directory,item)
    run(cmd+['up','-d','--no-build','--wait','--wait-timeout','60','postgres'])
    output=run(cmd+['run','--rm','--no-deps','initialize']).stdout
    match=re.search(r'Administrator: ([0-9a-f-]{36}); pending MFA factor: ([0-9a-f-]{36})',output)
    if not match:raise ValueError('initialization receipt unavailable')
    item.update(user=str(UUID(match[1])),factor=str(UUID(match[2])))
    (directory/'state.json').write_text(json.dumps(item),encoding='utf-8')
    if vm_server_ip:
        with (directory/'vm-profile.json').open('x',encoding='utf-8') as stream:
            json.dump(dict(server_ip=vm_server_ip,client_ip=vm_client_ip,admin_ip=vm_admin_ip),stream)
        from vm_appliance import start_vm
        start_vm(directory,item,vm_server_ip)
    else:start(directory,item)


def start(directory,item):
    if not item['factor']:raise ValueError('installation incomplete; retained data requires diagnosis')
    run(command(directory,item)+['up','-d','--no-build','--wait','--wait-timeout','60','postgres','app','admin','proxy'])
    mfa_required=status(directory,item)
    from deployment_snapshot import capture
    try:capture(directory,item,'local','127.0.0.1')
    except Exception:print('Service readiness passed; host snapshot could not be updated. Treat deployment facts as unknown or stale.')
    print('Local evaluation appliance running: https://localhost:8443; TACACS+ on 127.0.0.1:49.')
    print(('MFA enrollment and ' if mfa_required else '')+'explicit certificate trust are required before browser sign-in.')


def status(directory,item):
    context=ssl.create_default_context(cafile=str(directory/'localhost-ca.pem'))
    with urlopen('https://localhost:8443/',context=context,timeout=5) as response:
        if response.status!=200 or b'lang="en"' not in response.read():raise ValueError('console unavailable')
    with urlopen('https://localhost:8443/api/login-options',context=context,timeout=5) as response:
        options=json.load(response)
    if set(options)!={'mfa_required'} or type(options['mfa_required']) is not bool:
        raise ValueError('invalid authentication options')
    with socket.create_connection(('127.0.0.1',49),timeout=3):pass
    factor_check="""import sys
from pathlib import Path
import psycopg
from tacacs_appliance.runtime import read_secret
with psycopg.connect(read_secret(Path('/run/admin-secrets/admin_dsn')).decode(),connect_timeout=3) as db:
 db.execute('SET TRANSACTION READ ONLY')
 row=db.execute('SELECT enabled FROM mfa_factors WHERE tenant_id=%s AND user_id=%s AND id=%s',tuple(sys.argv[1:])).fetchone()
 if row is None:raise ValueError('factor unavailable')
 print('enrolled' if row[0] else 'pending')
"""
    enrollment=run(command(directory,item)+['exec','-T','admin','python','-c',factor_check,
        item['tenant'],item['user'],item['factor']]).stdout.strip()
    if enrollment not in ('pending','enrolled'):raise ValueError('invalid factor status')
    print('HTTPS console and TCP/49 reachable. This is not an authenticated AAA interoperability test.')
    print('MFA factor ID: '+str(item['factor']))
    print('MFA enrollment: '+enrollment)
    print('Console authentication: '+('password plus MFA' if options['mfa_required'] else 'local password-only evaluation'))
    certificate=(directory/'localhost-ca.pem').read_text(encoding='ascii')
    print('TLS certificate SHA-256: '+hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest())
    return options['mfa_required']


def probe_tacacs(directory,item):
    # Retrieve only into process memory, never arguments/logs or host files.
    result=run(command(directory,item)+['exec','-T','app','python','-c',
        "import base64; from pathlib import Path; print(base64.b64encode(Path('/run/tacacs-secrets/device_local').read_bytes()).decode())"])
    secret=base64.b64decode(result.stdout.strip(),validate=True)
    sys.path.insert(0,str(ROOT/'src'))
    from tacacs_appliance.protocol import Frame,Header,Limits,parse_frame
    from tacacs_appliance.obfuscation import xor_body
    arguments=(b'service=shell',b'cmd=show',b'cmd-arg=version')
    body=bytes((6,15,1,1,5,0,0,len(arguments)))+bytes(map(len,arguments))+b'admin'+b''.join(arguments)
    session=secrets.randbits(32)
    request=Frame(Header(0xc0,2,1,0,session,len(body)),body)
    def exact(client,count):
        data=b''
        while len(data)<count:
            part=client.recv(count-len(data))
            if not part:raise ValueError('incomplete TACACS reply')
            data+=part
        return data
    with socket.create_connection(('127.0.0.1',49),timeout=3) as client:
        client.sendall(struct.pack('!BBBBII',0xc0,2,1,0,session,len(body))+xor_body(request,secret))
        raw=exact(client,12);header=Header.parse(raw,Limits())
        if header.packet_type!=2 or header.sequence!=2 or header.session_id!=session or header.flags!=0:
            raise ValueError('invalid TACACS reply')
        response=xor_body(parse_frame(raw+exact(client,header.length)),secret)
        if not response or response[0] not in (1,2,16):raise ValueError('unexpected authorization result')
    print('Encrypted TACACS+ authorization exchange on TCP/49 passed; decision: '+('deny' if response[0]==16 else 'allow')+'.')


def repair_publishing(directory,item):
    """Upgrade our generated local deployment, retaining database and credentials."""
    if not item['factor']:raise ValueError('incomplete initialization')
    project=item['project'];network=project+'-local'
    inspected=subprocess.run(['docker','network','inspect',network],capture_output=True,text=True,timeout=10)
    if inspected.returncode:
        run(['docker','network','create','--opt','com.docker.network.bridge.host_binding_ipv4=127.0.0.1',network])
        inspected=run(['docker','network','inspect',network])
    network_info=json.loads(inspected.stdout)[0]
    if network_info['Name']!=network or network_info['Internal']:
        raise ValueError('unexpected local network')
    gateway=str(ipaddress.IPv4Address(network_info['IPAM']['Config'][0]['Gateway']))
    config=json.loads((directory/'compose.json').read_text(encoding='utf-8'))
    if config['services']['app']['ports']!=['127.0.0.1:49:49/tcp'] or config['services']['postgres']['ports']!=['127.0.0.1:8443:8443/tcp']:
        raise ValueError('operator-modified port configuration')
    cmd=command(directory,item)
    run(cmd+['stop','admin','app','postgres'])
    update="""from pathlib import Path
import sys,tomllib
p=Path('/config/service.toml');text=p.read_text();data=tomllib.loads(text)
if data['tenant_id']!=sys.argv[1] or len(data['devices'])!=1:raise ValueError('operator-modified configuration')
old='address = "'+data['devices'][0]['address']+'"'
if text.count(old)!=1:raise ValueError('ambiguous address')
p.write_text(text.replace(old,'address = "'+sys.argv[2]+'"'))
"""
    run(['docker','run','--rm','--network','none','--user','10001:10001','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--mount',f'type=volume,source={project}-config,target=/config',
        image_for(item['project']),'python','-c',update,item['tenant'],gateway])
    (directory/'compose.json').write_text(json.dumps(local_config(config,project)),encoding='utf-8')
    start(directory,item)


def login_mode(directory,item,enabled):
    config=json.loads((directory/'compose.json').read_text(encoding='utf-8'))
    if config['services']['postgres']['ports']!=['127.0.0.1:8443:8443/tcp']:
        raise ValueError('password-only mode requires loopback publishing')
    write_login_mode(item,enabled,'https://localhost:8443')
    run(command(directory,item)+['stop','proxy','admin'])
    start(directory,item)
    print('Local login mode: '+('username/password only' if enabled else 'password plus enrolled MFA')+'. Reload the browser.')


def write_login_mode(item,enabled,origin):
    update="""from pathlib import Path
import sys,tomllib
p=Path('/config/admin.toml');text=p.read_text();data=tomllib.loads(text)
if data['tenant_id']!=sys.argv[1] or data['origin']!=sys.argv[3] or data.get('port',8443)!=8443:raise ValueError('administration configuration mismatch')
lines=[line for line in text.splitlines() if not line.strip().startswith('local_password_only')]
p.write_text('local_password_only = '+sys.argv[2]+'\\n'+'\\n'.join(lines)+'\\n')
"""
    run(['docker','run','--rm','--network','none','--user','10001:10001','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--mount',f'type=volume,source={item["project"]}-config,target=/config',
        image_for(item['project']),'python','-c',update,item['tenant'],'true' if enabled else 'false',origin])


def demo_admin(directory,item):
    context=ssl.create_default_context(cafile=str(directory/'localhost-ca.pem'))
    with urlopen('https://localhost:8443/api/login-options',context=context,timeout=5) as response:
        if json.load(response)!={'mfa_required':False}:raise ValueError('local password-only mode required')
    config=json.loads((directory/'compose.json').read_text())
    if config['services']['postgres']['ports']!=['127.0.0.1:8443:8443/tcp']:raise ValueError('loopback publishing required')
    setup="""from pathlib import Path
import sys,json
from uuid import UUID
from argon2 import PasswordHasher
import psycopg
from tacacs_appliance.runtime import read_secret
from tacacs_appliance.password_policy import generate_password
from tacacs_appliance.postgres_audit import PostgresAuditWriter
tenant,user=UUID(sys.argv[1]),UUID(sys.argv[2])
password=generate_password()
with psycopg.connect(read_secret(Path('/run/provision/owner_dsn')).decode()) as db:
 with db.transaction():
  row=db.execute('SELECT username FROM users WHERE tenant_id=%s AND id=%s AND enabled AND NOT locked FOR UPDATE',(tenant,user)).fetchone()
  if row!=('admin',):raise ValueError('unexpected administrator')
  db.execute('UPDATE users SET password_hash=%s,failed_logins=0 WHERE tenant_id=%s AND id=%s',(PasswordHasher().hash(password),tenant,user))
  PostgresAuditWriter(None,str(tenant)).append_in_transaction(db,actor='local-operator',source='local-cli',action='admin.password.evaluation-default',target=str(user),result='success')
p=Path('/run/provision/operator_password');p.write_text(password);p.chmod(0o600)
p=Path('/run/provision/operator-access.json');data=json.loads(p.read_text());data['password']=password;p.write_text(json.dumps(data));p.chmod(0o600)
print('Evaluation administrator password set. No MFA flags or grants changed.')
"""
    run(['docker','run','--rm','--network',item['project']+'-private','--user','0:0',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--mount',
        f'type=volume,source={item["project"]}-provision,target=/run/provision',
        image_for(item['project']),'python','-c',setup,item['tenant'],item['user']])
    print('Run python3 scripts/local_appliance.py login-info in a private terminal.')


def main():
    parser=argparse.ArgumentParser(description='Persistent loopback-only local evaluation appliance')
    parser.add_argument('action',choices=('init','start','stop','status','probe','credentials','login-info','enroll','repair-publishing','password-only','require-mfa','demo-admin'))
    args=parser.parse_args();directory=HOME_DIR
    try:
        if args.action=='init':initialize(directory);return 0
        item=state(directory);cmd=command(directory,item)
        if args.action=='start':start(directory,item)
        elif args.action=='repair-publishing':repair_publishing(directory,item)
        elif args.action in ('password-only','require-mfa'):login_mode(directory,item,args.action=='password-only')
        elif args.action=='demo-admin':demo_admin(directory,item)
        elif args.action=='stop':run(cmd+['stop']);print('Services stopped. Persistent data retained.')
        elif args.action=='status':status(directory,item)
        elif args.action=='probe':probe_tacacs(directory,item)
        elif args.action=='login-info':
            result=run(cmd+['run','--rm','--no-deps','--user','0:0','initialize','python','-c',
                'from pathlib import Path; import json; print(json.dumps(dict(username="admin",password=Path("/run/provision/operator_password").read_text())))'])
            print('PRIVATE: local sign-in credentials. Do not share this output.')
            print(result.stdout.strip())
        elif args.action=='credentials':
            # Explicit human command only. Never called by automatic init/status.
            result=run(cmd+['run','--rm','--no-deps','--user','0:0','initialize','python','-c',
                'from pathlib import Path; print(Path("/run/provision/operator-access.json").read_text())'])
            print('PRIVATE: import the TOTP URI into your SHA-256 authenticator. Do not share this output.')
            print(result.stdout.strip());print('MFA factor ID: '+str(item['factor']))
        elif args.action=='enroll':
            if not sys.stdin.isatty():raise ValueError('interactive operator terminal required')
            return subprocess.run(cmd+['run','--rm','--no-deps','--user','0:0','initialize','python','-m','tacacs_appliance.enroll_cli',
                '--dsn-file','/run/provision/owner_dsn','--secret-file','/run/provision/admin_totp',
                '--secret-reference',REFERENCE,'--tenant-id',item['tenant'],'--user-id',item['user'],'--factor-id',item['factor']]).returncode
        return 0
    except Exception as error:
        print('Local appliance operation failed ('+type(error).__name__+'). Existing data was not reset; diagnostics and credentials suppressed.',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
