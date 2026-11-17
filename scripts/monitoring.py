"""Install the primary Ubuntu deployment's periodic dashboard snapshot."""
import json
from ipaddress import IPv4Address
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import local_appliance as local
from deployment_snapshot import capture


MONITOR = Path('/usr/local/lib/tnac-monitoring')
UNITS = Path('/etc/systemd/system')
SERVICE = """[Unit]
Description=TNAC+ dashboard snapshot
After=docker.service
ConditionPathExists=/run/docker.sock

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -Es /usr/local/lib/tnac-monitoring/monitoring.py snapshot
TimeoutStartSec=45
"""
TIMER = """[Unit]
Description=Refresh the TNAC+ dashboard snapshot

[Timer]
OnActiveSec=5s
OnUnitInactiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
"""

def write_owned(path, content):
    """Replace the file atomically with a fresh root-owned inode."""
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(content)
            stream.close()
            temporary.chmod(0o644)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def install():
    root = local.ROOT
    directory = root / 'data' / 'vm-appliance'
    item = local.state(directory)
    MONITOR.mkdir(mode=0o755, exist_ok=True)
    if MONITOR.is_symlink() or MONITOR.stat().st_uid != 0 or MONITOR.stat().st_mode & 0o022:
        raise ValueError('monitoring directory must be controlled by root')
    for source in (
        root / 'scripts' / 'monitoring.py',
        root / 'scripts' / 'deployment_snapshot.py',
        root / 'scripts' / 'local_appliance.py',
        root / 'src' / 'tacacs_appliance' / 'admin_endpoint.py',
    ):
        write_owned(MONITOR / source.name, source.read_bytes())
    write_owned(MONITOR / 'deployment.json',
        json.dumps({'directory': str(directory), 'project': item['project']}).encode())
    write_owned(UNITS / 'tnac-snapshot.service', SERVICE.encode())
    write_owned(UNITS / 'tnac-snapshot.timer', TIMER.encode())
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'tnac-snapshot.timer'], check=True)
    subprocess.run(['systemctl', 'start', '--no-block', 'tnac-snapshot.service'], check=True)
    print('TNAC+ dashboard monitoring enabled. A snapshot is collected about once a minute.')


def snapshot():
    saved = json.loads((MONITOR / 'deployment.json').read_text(encoding='utf-8'))
    directory = Path(saved['directory'])
    item = local.state(directory)
    if item['project'] != saved['project']:
        raise ValueError('deployment changed; enable monitoring again')
    profile = json.loads((directory / 'vm-profile.json').read_text(encoding='utf-8'))
    capture(directory, item, 'vm', str(IPv4Address(profile['server_ip'])))


if __name__ == '__main__':
    try:
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise PermissionError('run as root')
        {'install': install, 'snapshot': snapshot}[sys.argv[1]]()
    except Exception as exc:
        # Docker diagnostics can contain deployment details.
        print(f'TNAC+ dashboard monitoring failed ({type(exc).__name__}).', file=sys.stderr)
        raise SystemExit(1) from None
