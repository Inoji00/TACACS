"""First-install database phase; never overwrites existing identities."""
import argparse
from pathlib import Path
import psycopg
from psycopg import sql
from .bootstrap import bootstrap_tenant
from .migrations import migrate
from .provision_role import provision_new_login
from .runtime import read_secret


def initialize_database(connection, *, migration_directory: Path, aaa_role: str,
                        admin_role: str, aaa_password: str, admin_password: str,
                        tenant_id: str, name: str, username: str,
                        password: str, mfa_reference: str, schema: str='public') -> tuple[str,str]:
    if aaa_role==admin_role:
        raise ValueError('separate service identities required')
    if not schema or len(schema.encode('utf-8'))>63:
        raise ValueError('explicit bounded schema required')
    # Dedicated provisioning connection only; schema must already exist.
    if connection.execute('SELECT 1 FROM pg_namespace WHERE nspname=%s',(schema,)).fetchone() is None:
        raise ValueError('provisioning schema does not exist')
    connection.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
    connection.commit()
    # Migration runner owns its commits. Bootstrap failures retain checked
    # migrations, but roll back BOTH logins, tenant, grants and audit record.
    migrate(connection,migration_directory)
    with connection.transaction():
        provision_new_login(connection,aaa_role,schema,aaa_password,profile='aaa')
        provision_new_login(connection,admin_role,schema,admin_password,profile='admin')
        return bootstrap_tenant(connection,tenant_id=tenant_id,name=name,
            username=username,password=password,mfa_reference=mfa_reference)


def main() -> int:
    parser=argparse.ArgumentParser(description='Initialize a new local appliance database')
    for option in ('dsn','aaa-password','admin-password','operator-password'):
        parser.add_argument('--'+option+'-file',required=True,type=Path)
    parser.add_argument('--migration-directory',required=True,type=Path)
    parser.add_argument('--schema',default='public')
    for option in ('aaa-role','admin-role','tenant-id','name','username','mfa-reference'):
        parser.add_argument('--'+option,required=True)
    args=parser.parse_args()
    try:
        inputs={key:read_secret(getattr(args,key+'_file')).decode('utf-8')
                for key in ('aaa_password','admin_password','operator_password')}
        with psycopg.connect(read_secret(args.dsn_file).decode().strip(),connect_timeout=5) as connection:
            user,factor=initialize_database(connection,migration_directory=args.migration_directory,
                aaa_role=args.aaa_role,admin_role=args.admin_role,
                aaa_password=inputs['aaa_password'],admin_password=inputs['admin_password'],
                tenant_id=args.tenant_id,name=args.name,username=args.username,
                password=inputs['operator_password'],mfa_reference=args.mfa_reference,schema=args.schema)
        print(f'Database initialized. Administrator: {user}; pending MFA factor: {factor}')
        return 0
    except Exception:
        print('Database initialization failed. Existing identities were not replaced; committed migrations may remain.')
        return 1


if __name__=='__main__':
    raise SystemExit(main())
