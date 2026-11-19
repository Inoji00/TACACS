"""Linux VM appliance manager. Never configures OS networking or firewall."""
import argparse
import base64
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path
import local_appliance as local
try:
    from admin_endpoint import admin_domain, probe_admin, verify_certificate, verify_dns_binding
except ModuleNotFoundError:
    from tacacs_appliance.admin_endpoint import admin_domain, probe_admin, verify_certificate, verify_dns_binding

DIRECTORY=local.ROOT/'data'/'vm-appliance'


def validate_addresses(server,client):
    if client is None:
        return validate_admin_ip(server),None
    addresses=tuple(ipaddress.IPv4Address(value) for value in (server,client))
    if addresses[0]==addresses[1] or any(ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or ip.is_link_local for ip in addresses):
        raise ValueError('distinct unicast LAN addresses required')
    return tuple(map(str,addresses))


def validate_admin_ip(value):
    ip=ipaddress.IPv4Address(value)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or ip.is_link_local:
        raise ValueError('explicit LAN administration IPv4 required')
    return str(ip)


class SubnetSelectionError(ValueError):
    """An operator-facing error containing no command output."""


def select_vm_ip(subnet):
    if not subnet:
        if not sys.stdin.isatty():
            raise SubnetSelectionError('Supply --subnet with an IPv4 CIDR in a non-interactive terminal.')
        try:
            subnet=input('Ubuntu VM IPv4 subnet (e.g. 192.168.100.0/24): ').strip()
        except EOFError:
            raise SubnetSelectionError('No subnet entered.') from None
    try:
        if '/' not in subnet:
            raise ValueError
        network=ipaddress.IPv4Network(subnet)
    except ValueError:
        raise SubnetSelectionError('Enter an IPv4 subnet in CIDR form, e.g. 192.168.100.0/24.') from None

    try:
        interfaces=json.loads(local.run(['ip','-j','-4','address','show','scope','global','up']).stdout)
    except (OSError,local.subprocess.SubprocessError,ValueError):
        raise SubnetSelectionError('Could not read IPv4 addresses from Ubuntu. Check ip -br -4 addr.') from None
    candidates=set()
    for interface in interfaces:
        for entry in interface.get('addr_info',[]):
            address=ipaddress.IPv4Address(entry['local'])
            if address in network:
                try:
                    candidates.add(validate_admin_ip(address))
                except ValueError:
                    continue
    if not candidates:
        raise SubnetSelectionError('No active VM IPv4 address matches this subnet. Check ip -br -4 addr.')
    if len(candidates)>1:
        raise SubnetSelectionError('Multiple VM IPv4 addresses match this subnet. Use --server-ip and --admin-ip explicitly.')
    return candidates.pop()


def vm_config(config,server,admin=None):
    ip=ipaddress.IPv4Address(server)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:raise ValueError('explicit LAN address required')
    config['services']['app']['ports']=[f'{ip}:49:49/tcp']
    admin = validate_admin_ip(admin or server)
    config['services']['postgres']['ports'] = [f'{admin}:8443:8443/tcp']
    for key in ('app','postgres','admin','proxy'):config['services'][key]['restart']='unless-stopped'
    return config


def update_web(directory,item):
    """Recreate only the web services; keep AAA and PostgreSQL running."""
    local.run(local.command(directory,item)+['up','-d','--no-deps','--no-build',
        '--force-recreate','--wait','--wait-timeout','60','admin','proxy'])
    print('Web services updated. AAA and PostgreSQL were not recreated. Schema upgrades require a full service update.')


def update_audit_runtime(directory,item):
    """Apply audit changes to the TACACS+ listener and Web UI together."""
    local.run(local.command(directory,item)+['up','-d','--no-deps','--no-build',
        '--force-recreate','--wait','--wait-timeout','60','app','admin','proxy'])
    print('TACACS+ and Web services updated. PostgreSQL kept running.')


def start_vm(directory,item,server):
    from logging_defaults import persist
    persist(directory)
    profile=json.loads((directory/'vm-profile.json').read_text())
    admin=profile.get('admin_ip')
    services = ['postgres', 'app', 'admin', 'proxy']
    config = json.loads((directory/'compose.json').read_text(encoding='utf-8'))
    if 'device-syslog' in config['services']:
        services.append('device-syslog')
    local.run(local.command(directory,item)+['up','-d','--no-build','--wait','--wait-timeout','60',*services])
    with socket.create_connection((server,49),timeout=3):pass
    # Validate TLS on the address used by the browser.
    import ssl
    from urllib.request import urlopen
    domain=profile.get('admin_domain')
    origin=f'https://{domain or admin or "localhost"}:8443'
    if domain:
        verify_dns_binding(domain,admin)
        probe_admin(domain,admin,directory/'localhost-ca.pem')
    else:
        with urlopen(origin+'/',context=ssl.create_default_context(cafile=str(directory/'localhost-ca.pem')),timeout=5) as response:
            if response.status!=200:raise ValueError('admin readiness failed')
    from deployment_snapshot import capture
    try:capture(directory,item,'vm',server)
    except Exception:print('Service readiness passed; host snapshot could not be updated. Treat deployment facts as unknown or stale.')
    print(f'TACACS+ listener ready: {server}:49/TCP. Verify the network path and AAA from each device.')
    print(f'Administration: {origin}/' + ('' if admin else ' via VM or SSH forwarding.'))


ADMIN_FILES = {
    '/config/admin.toml': 0o644,
    '/admin/admin_cert.pem': 0o644,
    '/admin/health_ca.pem': 0o644,
    '/admin/admin_key.pem': 0o600,
}

UPDATE_ADMIN = """import base64,json,os,sys,tempfile
from pathlib import Path
for name,(value,mode) in json.load(sys.stdin).items():
    path=Path(name)
    fd,temp=tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd,'wb') as stream:
        stream.write(base64.b64decode(value,validate=True))
        os.fchmod(stream.fileno(),mode)
    os.replace(temp,path)
"""


def rebind_vm(directory,item,profile,server,admin,*,domain=None,tls_files=None):
    """Change host bindings and TLS without reseeding volumes or identities."""
    import re
    import tomllib

    if not item['factor']:
        raise ValueError('installation incomplete')
    local.run(['docker','run','--rm','--network','none',local.image_for(item['project']),'python','-c',
        'from tacacs_appliance.admin_api import lan_admin_origin'])
    server,client=validate_addresses(server,profile['client_ip'])
    admin=validate_admin_ip(admin)
    if domain:
        domain=admin_domain(domain)
        verify_dns_binding(domain,admin)
        cert_file,key_file,ca_file=map(Path,tls_files)
        for path,limit in ((cert_file,131072),(key_file,32768),(ca_file,262144)):
            if not path.is_file() or path.is_symlink() or not 1<=path.stat().st_size<=limit:
                raise ValueError('invalid TLS input file')
        if key_file.stat().st_mode & 0o077:
            raise ValueError('private key must not be accessible to group or others')
        verify_certificate(domain,cert_file,key_file,ca_file)
        certificate,key,trust=(path.read_bytes() for path in (cert_file,key_file,ca_file))
    else:
        certificate,key=local.admin_certificate(admin)
        trust=certificate
    for address in {server,admin}:
        with socket.socket() as probe:
            probe.bind((address,0))

    config_path=directory/'compose.json'
    profile_path=directory/'vm-profile.json'
    ca_path=directory/'localhost-ca.pem'
    previous={path:path.read_bytes() for path in (config_path,profile_path,ca_path)}
    config=vm_config(json.loads(previous[config_path]),server,admin)
    config['services']['admin']['healthcheck']['test']=[
        'CMD','python','-m','tacacs_appliance.admin_endpoint',domain or 'localhost',
        '127.0.0.1','/run/admin-secrets/health_ca.pem',
    ]
    volume_command=['docker','run','--rm','-i','--network','none','--user','10001:10001',
        '--cap-drop','ALL','--security-opt','no-new-privileges',
        '--mount',f'type=volume,source={item["project"]}-config,target=/config',
        '--mount',f'type=volume,source={item["project"]}-admin,target=/admin',local.image_for(item['project']),'python','-c']
    read_files=("import base64,json,sys;from pathlib import Path;"
        "print(json.dumps({p:[base64.b64encode(Path(p).read_bytes()).decode(),m] "
        "for p,m in json.load(sys.stdin).items()}))")
    old_files=json.loads(local.run(volume_command+[read_files],input=json.dumps(ADMIN_FILES)).stdout)
    admin_text=base64.b64decode(old_files['/config/admin.toml'][0]).decode()
    if tomllib.loads(admin_text)['tenant_id']!=item['tenant']:
        raise ValueError('administration tenant mismatch')
    admin_text=re.sub(r'(?m)^\s*(?:origin|lan_ip|lan_domain)\s*=.*\n','',admin_text)
    admin_text=f'lan_ip = "{admin}"\norigin = "https://{domain or admin}:8443"\n'+admin_text
    if domain:
        admin_text=f'lan_domain = "{domain}"\n'+admin_text
    contents=dict(zip(ADMIN_FILES,(admin_text.encode(),certificate,trust,key),strict=True))
    new_files={path:(base64.b64encode(value).decode(),ADMIN_FILES[path])
               for path,value in contents.items()}
    cmd=local.command(directory,item)
    local.run(cmd+['stop','proxy','admin','postgres','app'])
    try:
        local.run(volume_command+[UPDATE_ADMIN],input=json.dumps(new_files))
        config_path.write_text(json.dumps(config),encoding='utf-8')
        new_profile=dict(server_ip=server,client_ip=client,admin_ip=admin)
        if domain:new_profile['admin_domain']=domain
        profile_path.write_text(json.dumps(new_profile),encoding='utf-8')
        ca_path.write_bytes(trust)
        start_vm(directory,item,server)
    except Exception:
        local.run(cmd+['stop','proxy','admin','postgres','app'])
        local.run(volume_command+[UPDATE_ADMIN],input=json.dumps(old_files))
        for path,value in previous.items():
            path.write_bytes(value)
        start_vm(directory,item,profile['server_ip'])
        raise


def main():
    parser=argparse.ArgumentParser(description='Linux VM TACACS+ appliance manager; preconfigure VM IP and firewall first')
    parser.add_argument('action',choices=('init','start','status','update-web','update-audit','snapshot','monitor-resources','stop','credentials','switch-key','enroll','rebind','password-only','short-names'),
                        help='status lists Compose service names, states and ports')
    server=parser.add_mutually_exclusive_group()
    server.add_argument('--server-ip')
    server.add_argument('--subnet',nargs='?',const='',metavar='CIDR',
                        help='init: select the VM IPv4 address from this subnet, or prompt for CIDR')
    parser.add_argument('--client-ip',help='Optional bootstrap TACACS+ device IPv4');parser.add_argument('--admin-ip')
    parser.add_argument('--admin-domain',help='rebind: canonical DNS name for HTTPS')
    parser.add_argument('--cert-file',help='rebind: PEM leaf certificate followed by intermediates')
    parser.add_argument('--key-file',help='rebind: PEM private key with mode 600')
    parser.add_argument('--ca-file',help='rebind: trusted CA PEM bundle')
    parser.add_argument('--ip-only',action='store_true',help='rebind: explicitly return to IP-based HTTPS')
    parser.add_argument('--tenant-profile',help='Separate member-company installation name')
    args=parser.parse_args()
    if args.subnet is not None and args.action!='init':
        parser.error('--subnet is only supported with init')
    tls_files=(args.cert_file,args.key_file,args.ca_file)
    if args.ip_only and (args.action!='rebind' or args.admin_domain or any(tls_files)):
        parser.error('--ip-only is only supported with rebind and without DNS TLS options')
    if args.admin_domain or any(tls_files):
        if args.action!='rebind' or not args.admin_domain or not all(tls_files):
            parser.error('rebind requires --admin-domain, --cert-file, --key-file and --ca-file together')
    try:
        if sys.platform!='linux':raise ValueError('native Linux required')
        directory=DIRECTORY
        if args.tenant_profile is not None:
            if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}',args.tenant_profile):
                raise ValueError('invalid tenant profile name')
            directory=DIRECTORY.parent/'vm-tenants'/args.tenant_profile
        if args.action=='init':
            if args.server_ip is None and args.subnet is None:
                parser.error('init requires either --server-ip or --subnet')
            server_ip=args.server_ip
            admin_ip=args.admin_ip
            if args.subnet is not None:
                server_ip=select_vm_ip(args.subnet)
                validate_addresses(server_ip,args.client_ip)
                admin_ip=validate_admin_ip(admin_ip or server_ip)
                print(f'Selected VM endpoints: TACACS+ {server_ip}:49, Web UI https://{admin_ip}:8443/')
            local.initialize(directory,vm_server_ip=server_ip,vm_client_ip=args.client_ip,vm_admin_ip=admin_ip,vm_primary=args.tenant_profile is None,password_only=True)
            print('Retrieve the initial administrator credentials privately using the credentials command.')
            print('Sign in with the initial administrator username and password.')
            if args.client_ip is None:
                print('Register TACACS+ devices in the Web UI when ready.')
            else:
                print('Retrieve the bootstrap device secret privately using the switch-key command.')
            return 0
        if args.client_ip or (args.action!='rebind' and (args.server_ip or args.admin_ip)):
            raise ValueError('invalid address options for action')
        item=local.state(directory)
        if args.action=='status':
            result=local.run([
                'docker','ps','--all',
                '--filter',f"label=com.docker.compose.project={item['project']}",
                '--format','table {{.Label "com.docker.compose.service"}}\t{{.Status}}\t{{.Ports}}',
            ])
            print(result.stdout,end='')
            return 0
        profile=json.loads((directory/'vm-profile.json').read_text())
        if set(profile) not in ({'server_ip','client_ip'},{'server_ip','client_ip','admin_ip'},{'server_ip','client_ip','admin_ip','admin_domain'}):
            raise ValueError('invalid VM profile')
        server,client=validate_addresses(profile['server_ip'],profile['client_ip'])
        if args.action=='rebind':
            if not (args.server_ip or args.admin_ip or args.admin_domain or args.ip_only):raise ValueError('specify an IP or administration domain')
            if profile.get('admin_domain') and not (args.admin_domain or args.ip_only):
                parser.error('supply DNS TLS options or explicitly select --ip-only')
            server_ip=args.server_ip or server
            admin_ip=args.admin_ip or args.server_ip or profile.get('admin_ip') or server
            if args.admin_domain:
                rebind_vm(directory,item,profile,server_ip,admin_ip,domain=args.admin_domain,tls_files=tls_files)
            else:
                rebind_vm(directory,item,profile,server_ip,admin_ip)
        elif args.action=='start':start_vm(directory,item,server)
        elif args.action=='short-names':
            from container_names import apply
            from logging_defaults import persist
            apply(directory,item,primary=directory==DIRECTORY,run=local.run,
                  compose=local.command(directory,item),persist=persist)
            print('TNAC+ container names saved.')
        elif args.action=='update-web':update_web(directory,item)
        elif args.action=='update-audit':update_audit_runtime(directory,item)
        elif args.action=='snapshot':
            from deployment_snapshot import capture
            capture(directory,item,'vm',server)
        elif args.action=='monitor-resources':
            from deployment_snapshot import stream_resources
            stream_resources(directory)
        elif args.action=='stop':local.run(local.command(directory,item)+['stop'])
        elif args.action=='password-only':
            admin=profile.get('admin_ip')
            domain=profile.get('admin_domain')
            origin=f'https://{domain or (validate_admin_ip(admin) if admin else "localhost")}:8443'
            local.write_login_mode(item,True,origin)
            update_web(directory,item)
            print('Sign-in mode: username and password. Reload the browser.')
        elif args.action=='enroll':
            if not sys.stdin.isatty():raise ValueError('interactive operator terminal required')
            return local.subprocess.run(local.command(directory,item)+['run','--rm','--no-deps','--user','0:0','initialize',
                'python','-m','tacacs_appliance.enroll_cli','--dsn-file','/run/provision/owner_dsn',
                '--secret-file','/run/provision/admin_totp','--secret-reference',local.REFERENCE,
                '--tenant-id',item['tenant'],'--user-id',item['user'],'--factor-id',item['factor']]).returncode
        else:
            if args.action=='switch-key' and client is None:
                parser.error('No bootstrap device is configured. Manage devices and their secrets in the Web UI.')
            if not sys.stdin.isatty() or not sys.stdout.isatty():raise ValueError('private interactive terminal required')
            if args.action=='credentials':
                result=local.run(local.command(directory,item)+['run','--rm','--no-deps','--user','0:0','initialize','python','-c',
                    'from pathlib import Path;print(Path("/run/provision/operator-access.json").read_text())'])
                print('PRIVATE: initial credentials and TOTP URI. Do not share or capture this output.')
                print(result.stdout);print('MFA factor ID: '+item['factor'])
            else:
                result=local.run(local.command(directory,item)+['exec','-T','app','python','-c',
                    "from pathlib import Path;print(Path('/run/tacacs-secrets/device_local').read_text(),end='')"])
                print(f'Switch source: {client}; server: {server}; port: 49')
                print(result.stdout)
        return 0
    except SubnetSelectionError as error:
        parser.error(str(error))
    except Exception as error:
        print(f'VM appliance action failed ({type(error).__name__}); existing data retained and sensitive output suppressed.',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
