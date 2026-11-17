"""Bound Docker log growth while preserving operator overrides."""
import json
import os
from pathlib import Path
import tempfile


def configure(config):
    for service in ('app','admin','proxy','postgres'):
        if service in config['services']:
            config['services'][service].setdefault('logging',{'driver':'json-file','options':{'max-size':'20m','max-file':'5'}})
            entry=config['services'][service]
            environment=entry.setdefault('environment',{})
            if isinstance(environment,list):
                environment=dict(item.split('=',1) if '=' in item else (item,None) for item in environment)
                entry['environment']=environment
            environment.setdefault('TZ','Asia/Ho_Chi_Minh')
            environment.setdefault('PGTZ','UTC')
            if service=='postgres':
                entry.setdefault('command',['postgres','-c','timezone=UTC','-c','log_timezone=Asia/Ho_Chi_Minh'])
    return config


def persist(directory, *, transform=None):
    path=Path(directory)/'compose.json'
    if path.is_symlink():raise ValueError('configuration links forbidden')
    before=json.loads(path.read_text(encoding='utf-8'))
    updated=(transform or configure)(json.loads(json.dumps(before)))
    if before==updated:return
    descriptor,temporary=tempfile.mkstemp(dir=path.parent,prefix='.compose-')
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8') as stream:
            json.dump(updated,stream);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,path.stat().st_mode & 0o777)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
