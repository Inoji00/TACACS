"""Public deployment facts recorded by the host launcher, not guessed in container."""
from datetime import datetime,timezone
import ipaddress
import json
from pathlib import Path

DEFAULT_PATH=Path('/etc/tacacs/deployment-status.json')


def validate_resources(data):
    if not isinstance(data,dict) or set(data)!={'observed_at','system'}:
        raise ValueError('invalid resource snapshot')
    stamp=datetime.fromisoformat(data['observed_at'])
    if stamp.tzinfo is None:
        raise ValueError('resource timestamp requires a time zone')
    system=data['system']
    percentages={'cpu_percent','memory_percent','disk_percent'}
    if not isinstance(system,dict) or set(system)!=percentages|{'uptime_seconds'}:
        raise ValueError('invalid system metrics')
    if type(system['uptime_seconds']) is not int or system['uptime_seconds']<0:
        raise ValueError('invalid uptime')
    if any(type(system[key]) not in (int,float) or not 0<=system[key]<=100 for key in percentages):
        raise ValueError('invalid resource percentage')
    return stamp


def validate_snapshot(data):
    if not isinstance(data,dict) or set(data)-{'services','system','service_started_at','probe_latency_ms'}!={'observed_at','mode','endpoints','tcp_probe','https_probe'}:raise ValueError('invalid snapshot')
    stamp=datetime.fromisoformat(data['observed_at'])
    if stamp.tzinfo is None or data['mode'] not in ('local','vm'):raise ValueError('invalid snapshot metadata')
    if type(data['tcp_probe']) is not bool or type(data['https_probe']) is not bool:raise ValueError('invalid probe')
    if not isinstance(data['endpoints'],list) or not 0<=len(data['endpoints'])<=16:raise ValueError('invalid endpoints')
    for item in data['endpoints']:
        if not isinstance(item,dict) or set(item)!={'service','address','port'}:raise ValueError('invalid endpoint')
        if item['service'] not in ('tacacs','admin') or type(item['port']) is not int or not 1<=item['port']<=65535:raise ValueError('invalid port')
        ipaddress.ip_address(item['address'])
    if 'services' in data:
        services=data['services']
        if not isinstance(services,dict) or set(services)!={'app','admin','proxy','postgres'}:
            raise ValueError('invalid services')
        if any(status not in ('healthy','unhealthy','starting','running','exited','created','paused',
                              'restarting','dead','removing','missing','unknown') for status in services.values()):
            raise ValueError('invalid service status')
    if 'service_started_at' in data:
        starts=data['service_started_at']
        if not isinstance(starts,dict) or set(starts)-{'app','admin','proxy','postgres'}:
            raise ValueError('invalid service timestamps')
        for value in starts.values():
            if not isinstance(value,str) or len(value)>40:
                raise ValueError('invalid service start')
            started=datetime.fromisoformat(value)
            if started.tzinfo is None or started.year<1970 or started>stamp:
                raise ValueError('invalid service start')
    if 'probe_latency_ms' in data:
        latencies=data['probe_latency_ms']
        if not isinstance(latencies,dict) or set(latencies)-{'app','proxy'}:
            raise ValueError('invalid probe latency')
        for service,value in latencies.items():
            if type(value) not in (int,float) or not 0<=value<=60000:
                raise ValueError('invalid probe latency')
            if not data['tcp_probe' if service=='app' else 'https_probe']:
                raise ValueError('latency requires a successful probe')
    if 'system' in data:
        validate_resources(dict(observed_at=data['observed_at'],system=data['system']))
    return stamp


class DeploymentStatus:
    def __init__(self,path=DEFAULT_PATH):self.path=path

    def read(self):
        data=self._read_deployment()
        path=self.path.with_name('resource-status.json')
        try:
            if path.is_symlink():return data
            with path.open('rb') as stream:
                raw=stream.read(1025)
            if len(raw)>1024:return data
            resources=json.loads(raw)
            stamp=validate_resources(resources)
            age=(datetime.now(timezone.utc)-stamp).total_seconds()
            if 0<=age<=20:
                data['live_resources']=resources
        except (OSError,ValueError,TypeError,KeyError):
            pass
        return data

    def _read_deployment(self):
        unknown={'state':'unknown','endpoints':[],'runtime_acknowledgement':'not-measured','switch_test':'not-measured'}
        try:
            if self.path.is_symlink():return unknown
            with self.path.open('rb') as stream:raw=stream.read(8193)
            if len(raw)>8192:return unknown
            data=json.loads(raw);stamp=validate_snapshot(data)
            age=(datetime.now(timezone.utc)-stamp).total_seconds()
            if age < -300:return unknown
            return dict(data,state='snapshot' if age<=300 else 'stale',
                        runtime_acknowledgement='not-measured',switch_test='not-measured')
        except (OSError,ValueError,TypeError,KeyError):return unknown
