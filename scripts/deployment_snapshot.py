"""Record actual Docker port bindings and bounded readiness probes; never changes ports."""
from datetime import datetime,timezone
import json
from ipaddress import IPv4Address
import re
import shutil
import socket
import ssl
import sys
from pathlib import Path
from time import perf_counter, sleep
from urllib.request import urlopen
import local_appliance as local


def host_metrics(docker_root=None):
    """Measure the Linux VM and the filesystem containing Docker's data root."""
    def cpu_ticks():
        fields = Path('/proc/stat').read_text().splitlines()[0].split()
        ticks = [int(field) for field in fields[1:9]]
        return sum(ticks), ticks[3] + ticks[4]

    total_before, idle_before = cpu_ticks()
    sleep(0.25)
    total, idle = cpu_ticks()
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    memory_total = int(memory['MemTotal'].split()[0])
    memory_available = int(memory['MemAvailable'].split()[0])
    if docker_root is None:
        docker_root = local.run(['docker', 'info', '--format', '{{.DockerRootDir}}']).stdout.strip()
    if not Path(docker_root).is_absolute():
        raise ValueError('Docker data root unavailable')
    disk = shutil.disk_usage(docker_root)
    return dict(
        uptime_seconds=int(float(Path('/proc/uptime').read_text().split()[0])),
        cpu_percent=round(max(0, min(100, 100 * (1 - (idle - idle_before) / (total - total_before)))), 1),
        memory_percent=round(100 * (memory_total - memory_available) / memory_total, 1),
        disk_percent=round(100 * disk.used / (disk.used + disk.free), 1),
    )


def stream_resources(directory):
    """Keep a single restricted Docker writer for the duration of the collector."""
    item = local.state(directory)
    docker_root = local.run(['docker', 'info', '--format', '{{.DockerRootDir}}']).stdout.strip()
    code = '''
import json, os, sys, tempfile
from pathlib import Path
from tacacs_appliance.deployment_status import validate_resources

root = Path('/etc/tacacs')
for line in sys.stdin:
    data = json.loads(line)
    validate_resources(data)
    with tempfile.NamedTemporaryFile(mode='w', dir=root, prefix='resources-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(data, stream)
            stream.close()
            os.replace(temporary, root / 'resource-status.json')
        finally:
            temporary.unlink(missing_ok=True)
'''
    command = ['docker', 'run', '--rm', '-i', '--network', 'none', '--read-only',
               '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--mount', 'type=volume,source='+item['project']+'-config,target=/etc/tacacs',
               local.image_for(item['project']), 'python', '-c', code]
    config = json.loads((directory / 'compose.json').read_text(encoding='utf-8'))
    app_name = config['services']['app'].get('container_name')
    if app_name and re.fullmatch(r'tnac(?:-[a-f0-9]{8})?-app', app_name):
        command[2:2] = ['--name', app_name.removesuffix('-app') + '-monitor']
    with local.subprocess.Popen(command, stdin=local.subprocess.PIPE, text=True) as writer:
        try:
            while writer.poll() is None:
                metrics = host_metrics(docker_root)
                data = dict(observed_at=datetime.now(timezone.utc).isoformat(), system=metrics)
                writer.stdin.write(json.dumps(data)+'\n')
                writer.stdin.flush()
                sleep(4.75)
        finally:
            writer.stdin.close()
        raise RuntimeError('resource writer stopped')


def capture(directory,item,mode,server):
    endpoints=[]
    services={}
    service_started_at={}
    probe_latency_ms={}
    containers={}
    for service in ('app','admin','proxy','postgres'):
        container=local.run(['docker','ps','-aq',
            '--filter','label=com.docker.compose.project='+item['project'],
            '--filter','label=com.docker.compose.service='+service,
            '--filter','label=com.docker.compose.oneoff=False']).stdout.strip()
        if not container:
            services[service]='missing'
            continue
        if not re.fullmatch('[0-9a-f]{12,64}',container):
            raise ValueError('ambiguous container')
        containers[service]=container
        state=json.loads(local.run(['docker','inspect','--format','{{json .State}}',container]).stdout)
        status=state.get('Status')
        health=(state.get('Health') or {}).get('Status')
        if status == 'running' and isinstance(state.get('StartedAt'), str):
            try:
                started = datetime.fromisoformat(state['StartedAt'].replace('Z', '+00:00'))
                if started.tzinfo is not None and 1970 <= started.year and started <= datetime.now(timezone.utc):
                    service_started_at[service] = started.isoformat()
            except ValueError:
                pass
        services[service]=health if status=='running' and health in ('healthy','unhealthy','starting') else (
            status if status in ('running','exited','created','paused','restarting','dead','removing') else 'unknown')

    for service,container_port,label in (('app','49/tcp','tacacs'),('postgres','8443/tcp','admin')):
        container=containers.get(service)
        if container is None:continue
        ports=json.loads(local.run(['docker','inspect','--format','{{json .NetworkSettings.Ports}}',container]).stdout) or {}
        for binding in ports.get(container_port) or []:
            endpoints.append(dict(service=label,address=binding['HostIp'],port=int(binding['HostPort'])))
    tcp_probe=https_probe=False
    try:
        begin=perf_counter()
        with socket.create_connection((server,49),timeout=3):
            tcp_probe=True
            probe_latency_ms['app']=round((perf_counter()-begin)*1000,1)
    except OSError:
        pass
    try:
        profile_path=directory/'vm-profile.json'
        profile=json.loads(profile_path.read_text(encoding='utf-8')) if mode=='vm' and profile_path.is_file() else {}
        begin=perf_counter()
        if profile.get('admin_domain'):
            try:
                from admin_endpoint import probe_admin
            except ModuleNotFoundError:
                from tacacs_appliance.admin_endpoint import probe_admin
            probe_admin(profile['admin_domain'],profile['admin_ip'],directory/'localhost-ca.pem')
            https_probe=True
        else:
            address=str(IPv4Address(profile['admin_ip'])) if profile.get('admin_ip') else 'localhost'
            with urlopen(f'https://{address}:8443/',context=ssl.create_default_context(cafile=str(directory/'localhost-ca.pem')),timeout=5) as response:
                https_probe=response.status==200
        if https_probe:
            probe_latency_ms['proxy']=round((perf_counter()-begin)*1000,1)
    except (OSError, ValueError):
        pass
    data=dict(observed_at=datetime.now(timezone.utc).isoformat(),mode=mode,endpoints=endpoints,
              tcp_probe=tcp_probe,https_probe=https_probe,services=services,
              service_started_at=service_started_at,probe_latency_ms=probe_latency_ms)
    if mode == 'vm' and sys.platform == 'linux':
        try:
            data['system'] = host_metrics()
        except (OSError, ValueError, KeyError, IndexError, ArithmeticError, local.subprocess.SubprocessError):
            # Docker health remains available even if a host metric cannot be read.
            pass
    code='''
import json,os,sys,uuid
from pathlib import Path
from tacacs_appliance.deployment_status import validate_snapshot
data=json.load(sys.stdin);validate_snapshot(data)
root=Path('/etc/tacacs');target=root/'deployment-status.json'
if target.is_symlink():raise ValueError('links forbidden')
temporary=root/('status-'+uuid.uuid4().hex+'.tmp')
fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as stream:json.dump(data,stream)
os.replace(temporary,target)
'''
    local.run(['docker','run','--rm','-i','--network','none','--read-only','--user','10001:10001',
        '--cap-drop','ALL','--security-opt','no-new-privileges',
        '--mount','type=volume,source='+item['project']+'-config,target=/etc/tacacs',
        local.image_for(item['project']),'python','-c',code],input=json.dumps(data))
