"""Ephemeral loopback PostgreSQL integration runner; never uses operator data."""
import json
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
import psycopg
from local_appliance import IMAGE, POSTGRES_IMAGE


def main():
    parser=argparse.ArgumentParser(description='Disposable PostgreSQL integration runner')
    parser.add_argument('--linux',action='store_true',help='run installed application inside Linux runtime image')
    parser.add_argument('--image',default=IMAGE,help='local Linux test/runtime image')
    parser.add_argument('--postgres-image',default=POSTGRES_IMAGE,help='local PostgreSQL test image')
    parser.add_argument('--full',action='store_true',help='run complete regression suite with real PostgreSQL')
    parser.add_argument('--report',type=Path,help='write JSON test evidence (outside the runtime image)')
    args=parser.parse_args()
    if args.report:
        args.report=args.report.resolve()
        args.report.parent.mkdir(parents=True,exist_ok=True)
    root=Path(__file__).resolve().parents[1]
    name='tacacs-integration-'+uuid.uuid4().hex
    environment=dict(os.environ,POSTGRES_PASSWORD=secrets.token_urlsafe(32))
    started=False
    network=None
    phase='network creation'
    try:
        if args.linux:
            network=name+'-network'
            subprocess.run(['docker','network','create','--internal',network],check=True,capture_output=True,timeout=10)
        phase='database start'
        subprocess.run(['docker','run','--detach','--rm','--name',name,
            *(['--network',network] if network else []),
            *([] if args.linux else ['-p','127.0.0.1::5432']),'-e','POSTGRES_PASSWORD',
            args.postgres_image],env=environment,check=True,capture_output=True,timeout=180)
        started=True
        phase='database inspection'
        if not args.linux:
            details=json.loads(subprocess.run(['docker','inspect',name],check=True,
                capture_output=True,text=True,timeout=10).stdout)[0]
            port=details['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
            dsn=f"host=127.0.0.1 port={port} dbname=postgres user=postgres password={environment['POSTGRES_PASSWORD']}"
        phase='database readiness'
        deadline=time.monotonic()+40
        while True:
            try:
                if args.linux:
                    # The image's temporary initialization server exposes only
                    # a Unix socket. Tests connect over TCP after initialization.
                    ready=subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1',
                        '-p','5432','-U','postgres','-d','postgres'],capture_output=True,timeout=5)
                    if ready.returncode:raise psycopg.OperationalError('database not ready')
                else:
                    with psycopg.connect(dsn,connect_timeout=2) as connection:connection.execute('SELECT 1')
                break
            except psycopg.OperationalError:
                if time.monotonic()>deadline:raise RuntimeError('database readiness failed')
                time.sleep(0.5)
        if args.linux:
            phase='Linux test container'
            container_environment=dict(os.environ,TACACS_EPHEMERAL_TEST_DSN=
                f"host={name} port=5432 dbname=postgres user=postgres password={environment['POSTGRES_PASSWORD']}")
            return subprocess.run(['docker','run','--rm','--network',network,'--read-only',
                '--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=64m',
                '--mount',f'type=bind,source={root},target=/workspace,readonly','--workdir','/workspace',
                *(['--mount',f'type=bind,source={args.report.parent},target=/evidence'] if args.report else []),
                '-e','TACACS_EPHEMERAL_TEST_DSN',args.image,
                'python','scripts/container_integration.py',*(['--full'] if args.full else []),
                *(['--report',f'/evidence/{args.report.name}'] if args.report else [])],env=container_environment,timeout=600).returncode
        with tempfile.TemporaryDirectory(prefix='tacacs-integration-') as directory:
            dsn_file=Path(directory)/'test_dsn'
            dsn_file.write_text(dsn,encoding='utf-8');dsn_file.chmod(0o600)
            tests_environment=dict(os.environ,TACACS_TEST_DSN_FILE=str(dsn_file),PYTHONPATH=str(root/'src'))
            return subprocess.run([sys.executable,'scripts/run_tests.py','--pattern',
                'test*.py' if args.full else 'test_postgres_integration.py',
                *(['--report',str(args.report)] if args.report else [])],cwd=root,env=tests_environment,timeout=600).returncode
    except Exception as error:
        print(f'Ephemeral PostgreSQL integration runner failed at {phase} ({type(error).__name__}); diagnostic secrets suppressed.',file=sys.stderr)
        return 1
    finally:
        if started:
            subprocess.run(['docker','stop','--time','5',name],capture_output=True,timeout=20)
        if network:
            subprocess.run(['docker','network','rm',network],capture_output=True,timeout=10)


if __name__=='__main__':raise SystemExit(main())
