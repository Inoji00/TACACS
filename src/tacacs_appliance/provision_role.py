"""Provision dedicated database logins and bounded service grants."""
import argparse
from pathlib import Path
import psycopg
from psycopg import sql
from .database_security import validate_runtime_role,validate_admin_role
from .runtime import read_secret

READ_TABLES = ("tenants", "users", "policy_versions", "identity_groups", "user_groups", "audit_events", "schema_migrations")


def provision_new_login(connection,role: str,schema: str,password: str,*,profile: str='aaa') -> None:
    if profile not in ('aaa','admin') or not isinstance(password,str) or not 32<=len(password)<=1024:
        raise ValueError('explicit profile and strong generated password required')
    if any(ord(character)<32 or ord(character)==127 for character in password):
        raise ValueError('password contains unsupported controls')
    if not isinstance(role,str) or not isinstance(schema,str) or not role or not schema or len(role.encode())>63 or len(schema.encode())>63:
        raise ValueError('explicit bounded role and schema required')
    with connection.transaction():
        # Explicit client-side SCRAM avoids placing the plaintext password in
        # SQL statements (including server statement logs). Never negotiate MD5.
        verifier=connection.pgconn.encrypt_password(password.encode('utf-8'),role.encode('utf-8'),b'scram-sha-256').decode('ascii')
        if not verifier.startswith('SCRAM-SHA-256$'):
            raise ValueError('SCRAM password verifier required')
        # No IF NOT EXISTS: duplicate login never silently replaces credentials.
        connection.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}').format(
            sql.Identifier(role),sql.Literal(verifier)))
        (provision_admin_role if profile=='admin' else provision_aaa_role)(connection,role,schema)


def provision_aaa_role(connection, role: str, schema: str) -> None:
    _provision_role(connection,role,schema,administration=False)


def provision_admin_role(connection, role: str, schema: str) -> None:
    _provision_role(connection,role,schema,administration=True)


def _provision_role(connection, role: str, schema: str, *, administration: bool) -> None:
    if not role or not schema or len(role.encode()) > 63 or len(schema.encode()) > 63:
        raise ValueError("explicit role and schema required")
    with connection.transaction():
        row = connection.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
        if row is None or not row[0]:
            raise ValueError("existing dedicated login required")
        target, namespace = sql.Identifier(role), sql.Identifier(schema)
        # No automatic PUBLIC revocations: operator must secure their schema.
        connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(namespace, target))
        for table in READ_TABLES:
            connection.execute(sql.SQL("GRANT SELECT ON {}.{} TO {}").format(namespace, sql.Identifier(table), target))
        connection.execute(sql.SQL('GRANT SELECT ON {}.network_devices TO {}').format(namespace,target))
        connection.execute(sql.SQL('GRANT SELECT ON {}.policy_retirements TO {}').format(namespace,target))
        connection.execute(sql.SQL('GRANT SELECT ON {}.device_runtime_observations TO {}').format(namespace,target))
        if not administration:
            connection.execute(sql.SQL('GRANT INSERT, UPDATE ON {}.device_runtime_observations TO {}').format(namespace,target))
        connection.execute(sql.SQL("GRANT UPDATE(id) ON {}.tenants TO {}").format(namespace, target))
        connection.execute(sql.SQL("GRANT UPDATE(password_hash,failed_logins,locked) ON {}.users TO {}").format(namespace, target))
        for table in ("accounting_records", "audit_events"):
            if administration and table=='accounting_records':continue
            connection.execute(sql.SQL("GRANT INSERT ON {}.{} TO {}").format(namespace, sql.Identifier(table), target))
        if administration:
            connection.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {}.set_device_console_access(uuid,uuid,uuid,boolean) TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT UPDATE(name) ON {}.identity_groups TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT DELETE ON {}.identity_groups TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT INSERT ON {}.policy_retirements TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON {}.network_device_groups TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON {}.device_console_scopes TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT SELECT(id,tenant_id,occurred_at,session_id,username,device_id,action,arguments) ON {}.accounting_records TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT INSERT, UPDATE ON {}.network_devices TO {}').format(namespace,target))
            for table in ('users','identity_groups','user_groups'):
                connection.execute(sql.SQL('GRANT INSERT ON {}.{} TO {}').format(namespace,sql.Identifier(table),target))
            connection.execute(sql.SQL('GRANT UPDATE(enabled,username,deleted) ON {}.users TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT DELETE ON {}.users, {}.user_groups TO {}').format(namespace,namespace,target))
            for table in ('admin_grants','admin_sessions','mfa_factors','policy_test_reports','policy_simulation_reports'):
                connection.execute(sql.SQL('GRANT SELECT ON {}.{} TO {}').format(namespace,sql.Identifier(table),target))
            for table in ('admin_sessions','policy_versions','policy_test_reports','policy_simulation_reports'):
                connection.execute(sql.SQL('GRANT INSERT ON {}.{} TO {}').format(namespace,sql.Identifier(table),target))
            connection.execute(sql.SQL('GRANT DELETE ON {}.admin_sessions TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT UPDATE(state,approver_id) ON {}.policy_versions TO {}').format(namespace,target))
            connection.execute(sql.SQL('GRANT UPDATE(last_accepted_step,failed_attempts,locked_until) ON {}.mfa_factors TO {}').format(namespace,target))
        sequence = connection.execute("SELECT pg_get_serial_sequence(%s,'chain_sequence')", (sql.Identifier(schema,'audit_events').as_string(),)).fetchone()
        if sequence is None or sequence[0] is None:
            raise ValueError("audit sequence missing")
        # regclass resolution is parameterized; sequence identifier is not built
        # from caller text or split on dots (quoted names may contain dots).
        sequence_row = connection.execute("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=%s::regclass",
                                          (sequence[0],)).fetchone()
        if sequence_row is None:
            raise ValueError("audit sequence unavailable")
        connection.execute(sql.SQL("GRANT USAGE ON SEQUENCE {}.{} TO {}").format(
            sql.Identifier(sequence_row[0]), sql.Identifier(sequence_row[1]), target))
        connection.execute(sql.SQL("SET LOCAL ROLE {}").format(target))
        connection.execute(sql.SQL("SET LOCAL search_path TO {}").format(namespace))
        (validate_admin_role if administration else validate_runtime_role)(connection)
        connection.execute("RESET ROLE")


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision a dedicated AAA or administration database role")
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument('--profile',choices=('aaa','admin'),default='aaa')
    parser.add_argument('--new-login-password-file',type=Path,help='create a NEW login using a protected generated password file; duplicates fail')
    args = parser.parse_args()
    try:
        with psycopg.connect(read_secret(args.dsn_file).decode().strip(), connect_timeout=5) as connection:
            if args.new_login_password_file is not None:
                password=read_secret(args.new_login_password_file).decode('utf-8')
                provision_new_login(connection,args.role,args.schema,password,profile=args.profile)
            else:
                provision=provision_admin_role if args.profile=='admin' else provision_aaa_role
                provision(connection, args.role, args.schema)
        print("Role grants applied and security checks passed.")
        return 0
    except Exception:
        print("Role provisioning failed; transaction rolled back. Check ownership, memberships and PUBLIC privileges.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
