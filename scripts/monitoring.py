"""Install the primary Ubuntu deployment's periodic dashboard snapshot."""
import json
from ipaddress import IPv4Address
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

import local_appliance as local
from deployment_snapshot import capture


MONITOR = Path('/usr/local/lib/tnac-monitoring')
UNITS = Path('/etc/systemd/system')
SERVICE = """[Unit]
Description=TNAC+ dashboard snapshot
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -Es /usr/local/lib/tnac-monitoring/monitoring.py snapshot
TimeoutStartSec=90
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
ALERT_SERVICE = """[Unit]
Description=TNAC+ fast Slack activity delivery
After=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -Es /usr/local/lib/tnac-monitoring/monitoring.py alerts
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
KillMode=control-group

[Install]
WantedBy=multi-user.target
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
        root / 'scripts' / 'slack_monitor.py',
        root / 'src' / 'tacacs_appliance' / 'alert_storage.py',
        root / 'src' / 'tacacs_appliance' / 'admin_endpoint.py',
    ):
        write_owned(MONITOR / source.name, source.read_bytes())
    volume = json.loads(local.run(['docker', 'volume', 'inspect', item['project'] + '-alerts']).stdout)[0]
    if volume.get('Driver') != 'local' or volume.get('Scope') != 'local' or not Path(volume['Mountpoint']).is_absolute():
        raise ValueError('local alert volume required')
    write_owned(MONITOR / 'deployment.json',
        json.dumps({'directory': str(directory), 'project': item['project'], 'alerts_path': volume['Mountpoint']}).encode())
    write_owned(UNITS / 'tnac-snapshot.service', SERVICE.encode())
    write_owned(UNITS / 'tnac-snapshot.timer', TIMER.encode())
    write_owned(UNITS / 'tnac-alerts.service', ALERT_SERVICE.encode())
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'tnac-snapshot.timer'], check=True)
    subprocess.run(['systemctl', 'start', '--no-block', 'tnac-snapshot.service'], check=True)
    subprocess.run(['systemctl', 'enable', 'tnac-alerts.service'], check=True)
    subprocess.run(['systemctl', 'restart', 'tnac-alerts.service'], check=True)
    print('TNAC+ dashboard monitoring enabled. A snapshot is collected about once a minute.')
    print('TNAC+ Slack activity delivery enabled. Activity is polled about every three seconds.')


def alerts():
    from slack_monitor import check_alerts
    stopped = threading.Event()
    def stop(*_):
        stopped.set()
    previous = {number: signal.signal(number, stop) for number in (signal.SIGTERM, signal.SIGINT)}
    last_error = float('-inf')
    try:
        while not stopped.is_set():
            started = time.monotonic()
            try:
                saved = json.loads((MONITOR / 'deployment.json').read_text(encoding='utf-8'))
                check_alerts(saved['project'], {}, saved['alerts_path'], activity_only=True)
            except Exception:
                if started - last_error >= 60:
                    print('TNAC+ fast Slack delivery failed. Check protected storage and monitor status.', file=sys.stderr, flush=True)
                    last_error = started
            stopped.wait(max(0.25, 3 - (time.monotonic() - started)))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def snapshot():
    saved = json.loads((MONITOR / 'deployment.json').read_text(encoding='utf-8'))
    directory = Path(saved['directory'])
    item = local.state(directory)
    if item['project'] != saved['project']:
        raise ValueError('deployment changed; enable monitoring again')
    profile = json.loads((directory / 'vm-profile.json').read_text(encoding='utf-8'))
    failed = False
    def deadline(*_):
        raise TimeoutError('snapshot deadline exceeded')
    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(45)
    try:
        data = capture(directory, item, 'vm', str(IPv4Address(profile['server_ip'])))
    except Exception:
        data = {'snapshot_error': True}
        failed = True
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    if saved.get('alerts_path'):
        from slack_monitor import check_alerts
        try:
            check_alerts(item['project'], data, saved['alerts_path'])
        except Exception:
            print('TNAC+ Slack monitoring failed. Check protected storage and network access.', file=sys.stderr)
    if failed:
        raise RuntimeError('snapshot failed')


if __name__ == '__main__':
    try:
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise PermissionError('run as root')
        {'install': install, 'snapshot': snapshot, 'alerts': alerts}[sys.argv[1]]()
    except Exception as exc:
        # Docker diagnostics can contain deployment details.
        print(f'TNAC+ dashboard monitoring failed ({type(exc).__name__}).', file=sys.stderr)
        raise SystemExit(1) from None
