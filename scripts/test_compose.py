"""Disposable Compose database/initializer/AAA smoke test; no operator inputs."""
import json
import argparse
from datetime import datetime,timedelta,timezone
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import re
from uuid import uuid4
from local_appliance import IMAGE, POSTGRES_IMAGE


def cleanup_fixture(command,project,volumes,*,configured):
    if not re.fullmatch(r'tacacs-smoke-[0-9a-f]{32}',project):
        raise ValueError('exact generated project required')
    if any(not name.startswith(project+'-') for name in volumes.values()):
        raise ValueError('fixture volume outside generated project')
    clean=True
    def run(arguments,timeout=10):
        nonlocal clean
        try:return subprocess.run(arguments,capture_output=True,text=True,timeout=timeout)
        except Exception:
            clean=False
            return None
    if configured:
        result=run(command+['down','--volumes','--remove-orphans','--timeout','5'],30)
        if result is None or result.returncode:clean=False
    # Named seed container is not a Compose service and can survive a timeout.
    run(['docker','rm','--force',project+'-seed'])
    for name in volumes.values():run(['docker','volume','rm',name])
    for resource in ('container','network','volume'):
        arguments=(['docker','ps','-a'] if resource=='container' else ['docker',resource,'ls'])
        result=run(arguments+['--format','{{.Names}}' if resource=='container' else '{{.Name}}'])
        if result is None or result.returncode:
            clean=False
        elif any(name==project or name.startswith(project+'-') or name.startswith(project+'_')
                 for name in result.stdout.splitlines()):clean=False
    return clean


def exec_probe(command, service, probe):
    container=subprocess.check_output(command+['ps','-q',service],text=True,timeout=10).strip()
    if not re.fullmatch('[0-9a-f]{12,64}',container):
        raise ValueError('expected one running probe container')
    subprocess.run(['docker','exec',container,'python','-c',probe],
        stdin=subprocess.DEVNULL,check=True,capture_output=True,timeout=20)


def verify_backup_restore(command):
    container = subprocess.check_output(command + ['ps', '-q', 'postgres'],
                                        text=True, timeout=15).strip()
    if not re.fullmatch('[0-9a-f]{12,64}', container):
        raise ValueError('expected one running PostgreSQL test container')

    def execute(*args, input=None):
        print(f'PostgreSQL backup/restore: {args[0]}', flush=True)
        # Only restore reads the archive from stdin. Keep other commands non-interactive.
        invocation = ['docker', 'exec']
        if input is not None:
            invocation.append('-i')
        invocation.extend([container, *args])
        return subprocess.run(invocation, input=input,
                              stdin=subprocess.DEVNULL if input is None else None,
                              capture_output=True, check=True, timeout=120).stdout

    backup = execute('pg_dump', '-U', 'tacacs_app', '-Fc', 'tacacs')
    execute('createdb', '-U', 'tacacs_app', 'tnac_restore_check')
    execute('pg_restore', '-U', 'tacacs_app', '--exit-on-error',
            '-d', 'tnac_restore_check', input=backup)
    query = "SELECT name, checksum FROM schema_migrations ORDER BY name"
    def migrations(database):
        return execute('psql', '-XAt', '-v', 'ON_ERROR_STOP=1',
                       '-U', 'tacacs_app', '-d', database, '-c', query)

    original = migrations('tacacs')
    if not original.strip() or original != migrations('tnac_restore_check'):
        raise RuntimeError('restored migration history differs')


def main():
    parser=argparse.ArgumentParser(description='Disposable real Compose smoke test')
    parser.add_argument('--admin',action='store_true',help='also verify isolated HTTPS admin container (requires cryptography)')
    parser.add_argument('--image',default=IMAGE,help='local TNAC+ image to test')
    parser.add_argument('--postgres-image',default=POSTGRES_IMAGE,help='local PostgreSQL image to test')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    project='tacacs-smoke-'+uuid4().hex
    tenant=str(uuid4())
    environment=os.environ|{'TACACS_TENANT_ID':tenant,'TACACS_MFA_REFERENCE':'secret://smoke/mfa'}
    image=args.image
    phase='configuration'
    volumes={};status=1
    with tempfile.TemporaryDirectory(prefix=project) as directory:
        path=Path(directory)/'compose.json'
        command=['docker','compose','--project-name',project,'-f',str(path)]
        try:
            result=subprocess.run(['docker','compose','-f',str(root/'docker-compose.yml'),
                '-f',str(root/'docker-compose.initialize.yml'),
                *(['-f',str(root/'docker-compose.admin.yml')] if args.admin else []),'config','--format','json'],
                cwd=root,env=environment,check=True,capture_output=True,text=True,timeout=15)
            config=json.loads(result.stdout)
            config.pop('name',None);config.pop('secrets',None)
            volumes={key:project+'-'+key for key in ('config','runtime','provision','dbsecret',*(['admin'] if args.admin else []))}
            config['volumes']={key:{'name':name,'external':True} for key,name in volumes.items()}|{'postgres-data':{}}
            config['networks']={'private':{'internal':True}}
            services=config['services']
            services['postgres']['image']=args.postgres_image
            services['postgres']['healthcheck']['test']=[
                'CMD','pg_isready','-h','127.0.0.1','-U','tacacs_app','-d','tacacs']
            for key in ('app','initialize'):
                services[key].pop('build',None);services[key]['image']=image
            services['app'].pop('ports',None)
            services['app']['volumes']=['config:/etc/tacacs:ro','runtime:/run/tacacs-secrets:ro']
            services['initialize']['volumes']=['provision:/run/provision:ro']
            services['postgres'].pop('secrets',None)
            services['postgres'].pop('ports',None)
            services['postgres']['volumes']=['postgres-data:/var/lib/postgresql/data','dbsecret:/run/secrets:ro']
            path.write_text(json.dumps(config),encoding='utf-8')
            password=secrets.token_urlsafe(48);aaa=secrets.token_urlsafe(48);admin=secrets.token_urlsafe(48)
            files={
                '/config/service.toml':(f'tenant_id = "{tenant}"\ndatabase_dsn_file = "/run/tacacs-secrets/database_dsn"\n'
                    '[listener]\nhost = "0.0.0.0"\nport = 49\n[[devices]]\naddress = "127.0.0.1"\n'
                    'secret_file = "/run/tacacs-secrets/device_localhost"\n',10001,0o644),
                '/runtime/database_dsn':(f'host=postgres dbname=tacacs user=tacacs_aaa password={aaa}',10001,0o600),
                '/runtime/device_localhost':(secrets.token_urlsafe(48),10001,0o600),
                '/provision/owner_dsn':(f'host=postgres dbname=tacacs user=tacacs_app password={password}',0,0o600),
                '/provision/aaa_password':(aaa,0,0o600),'/provision/admin_password':(admin,0,0o600),
                '/provision/operator_password':('Aa1!'+secrets.token_urlsafe(32),0,0o600),
                '/dbsecret/postgres_password':(password,70,0o600)}
            if args.admin:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes,serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.x509.oid import NameOID
                phase='ephemeral TLS identity'
                key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
                name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
                now=datetime.now(timezone.utc)
                certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
                    .sign(key,hashes.SHA256())).public_bytes(serialization.Encoding.PEM).decode('ascii')
                # Test-only shared namespace avoids changing local-only runtime
                # binding or enabling Docker Desktop host networking.
                service=services['admin'];service.pop('build',None);service['image']=image
                service['network_mode']='service:postgres'
                service['volumes']=['config:/etc/tacacs:ro','admin:/run/admin-secrets:ro']
                files.update({
                    '/config/admin.toml':(f'tenant_id = "{tenant}"\ndatabase_dsn_file = "/run/admin-secrets/admin_dsn"\n'
                        'origin = "https://localhost:8443"\nport = 8443\ncsrf_key_file = "/run/admin-secrets/admin_csrf"\n'
                        'cert_file = "/run/admin-secrets/admin_cert.pem"\nkey_file = "/run/admin-secrets/admin_key.pem"\n'
                        '[mfa_references]\n"secret://smoke/mfa" = "/run/admin-secrets/admin_totp"\n',10001,0o644),
                    '/admin/admin_dsn':(f'host=127.0.0.1 dbname=tacacs user=tacacs_admin password={admin}',10001,0o600),
                    '/admin/admin_csrf':(secrets.token_urlsafe(48),10001,0o600),
                    '/admin/admin_totp':(secrets.token_urlsafe(32),10001,0o600),
                    '/admin/admin_cert.pem':(certificate,10001,0o644),
                    '/admin/health_ca.pem':(certificate,10001,0o644),
                    '/admin/admin_key.pem':(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode('ascii'),10001,0o600)})
                path.write_text(json.dumps(config),encoding='utf-8')
            phase='fixture volumes'
            for name in volumes.values():
                subprocess.run(['docker','volume','create',name],check=True,capture_output=True,timeout=10)
            seed="import json,sys,os,pathlib; data=json.load(sys.stdin);\nfor name,(value,uid,mode) in data.items():\n p=pathlib.Path(name); p.write_text(value); os.chown(p,uid,uid); p.chmod(mode)"
            subprocess.run(['docker','run','--rm','--name',project+'-seed','-i','--network','none','--user','0:0',
                *[item for key,name in volumes.items() for item in ('--mount',f'type=volume,source={name},target=/{key}')],
                image,'python','-c',seed],input=json.dumps(files),text=True,check=True,capture_output=True,timeout=20)
            phase='database startup'
            subprocess.run(command+['up','-d','--no-build','--wait','--wait-timeout','60','postgres'],
                check=True,capture_output=True,timeout=80)
            phase='one-shot initialization'
            initializer=project+'-initializer'
            try:
                subprocess.run(command+['run','-d','--no-deps','--pull','never','--name',initializer,'initialize'],
                    check=True,capture_output=True,timeout=30)
                result=subprocess.run(['docker','wait',initializer],
                    check=True,capture_output=True,text=True,timeout=120)
                if result.stdout.strip()!='0':
                    raise RuntimeError('initializer exited unsuccessfully')
            finally:
                subprocess.run(['docker','rm','-f',initializer],capture_output=True,timeout=15)
            phase='AAA readiness'
            subprocess.run(command+['up','-d','--no-build','--wait','--wait-timeout','60','app'],
                check=True,capture_output=True,timeout=80)
            phase='TCP49 and credential isolation'
            probe="import socket,pathlib; s=socket.create_connection(('127.0.0.1',49),3); s.close(); assert not pathlib.Path('/run/provision/owner_dsn').exists(); assert not pathlib.Path('/run/tacacs-secrets/owner_dsn').exists()"
            exec_probe(command,'app',probe)
            if args.admin:
                phase='HTTPS administration readiness'
                subprocess.run(command+['up','-d','--no-build','--wait','--wait-timeout','60','admin'],
                    check=True,capture_output=True,timeout=80)
                probe=('import ssl,http.client,pathlib; '
                    'context=ssl.create_default_context(cafile="/run/admin-secrets/health_ca.pem"); '
                    'client=http.client.HTTPSConnection("localhost",8443,context=context,timeout=5); '
                    'client.request("GET","/"); version=client.sock.version(); response=client.getresponse(); '
                    'assert response.status==200; assert b"lang=\\"en\\"" in response.read(); '
                    'assert version=="TLSv1.3"; '
                    'client.request("GET","/api/session"); response=client.getresponse(); '
                    'assert response.status==401; response.read(); client.close(); '
                    'assert not pathlib.Path("/run/provision/owner_dsn").exists(); '
                    'assert not pathlib.Path("/run/tacacs-secrets/device_localhost").exists()')
                exec_probe(command,'admin',probe)
                print('Restricted admin HTTPS/TLS1.3 console, anonymous session denial and mount isolation passed.')
            print('Compose database initialization, restricted AAA readiness, TCP49 and owner-file isolation passed.')
            phase='disposable PostgreSQL backup and restore'
            verify_backup_restore(command)
            print('Disposable PostgreSQL dump/restore and migration checksum comparison passed.')
            status=0
        except Exception as error:
            # Never publish command output: database diagnostics may contain secrets.
            print(f'Compose smoke test failed during {phase}: {type(error).__name__}.')
            status=1
        finally:
            if not cleanup_fixture(command,project,volumes,configured=path.exists()):
                print('Fixture cleanup failed or resources remain; smoke test is not successful.')
                status=1
    return status


if __name__=='__main__':raise SystemExit(main())
