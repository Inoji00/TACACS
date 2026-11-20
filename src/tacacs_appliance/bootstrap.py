"""One-time operator bootstrap; no default password or enabled MFA bypass."""
import argparse
from pathlib import Path
from uuid import UUID, uuid4
from .password_policy import valid_new_password
from argon2 import PasswordHasher
import psycopg
from .admin_rbac import PERMISSIONS
from .postgres_audit import PostgresAuditWriter
from .runtime import read_secret
from .schema_manifest import validate_schema


def bootstrap_tenant(connection, *, tenant_id: str, name: str, username: str, password: str,
                     mfa_reference: str) -> tuple[str,str]:
    tenant = UUID(tenant_id)
    if (not isinstance(name,str) or not 1<=len(name)<=253 or not isinstance(username,str)
            or not 1<=len(username)<=253 or any(ord(c)<32 or ord(c)==127 for c in name+username)):
        raise ValueError("invalid tenant or username")
    if not valid_new_password(password):
        raise ValueError("bootstrap password must contain 12..1024 characters with uppercase, lowercase, a digit and ASCII punctuation")
    if not isinstance(mfa_reference,str) or not mfa_reference.startswith("secret://") or len(mfa_reference)<=9 or len(mfa_reference)>1024:
        raise ValueError("MFA secret reference required")
    password_hash = PasswordHasher().hash(password)
    user, factor = uuid4(), uuid4()
    with connection.transaction():
        validate_schema(connection)
        # Unique tenant/name constraints make repeated bootstrap fail, never
        # replace credentials or grant permissions on an existing tenant.
        connection.execute("INSERT INTO tenants(id,name) VALUES (%s,%s)",(tenant,name))
        for group_name in ("super-admin", "read-only"):
            connection.execute(
                "INSERT INTO identity_groups(id,tenant_id,name) VALUES (%s,%s,%s)",
                (uuid4(), tenant, group_name),
            )
        connection.execute("INSERT INTO users(id,tenant_id,username,password_hash) VALUES (%s,%s,%s,%s)",
                           (user,tenant,username,password_hash))
        for permission in sorted(PERMISSIONS):
            connection.execute("INSERT INTO admin_grants(tenant_id,user_id,permission) VALUES (%s,%s,%s)",
                               (tenant,user,permission))
        connection.execute("INSERT INTO mfa_factors(id,tenant_id,user_id,secret_reference,enabled) VALUES (%s,%s,%s,%s,FALSE)",
                           (factor,tenant,user,mfa_reference))
        PostgresAuditWriter(None,str(tenant)).append_in_transaction(connection,actor="operator-bootstrap",
            source="local-cli",action="tenant.bootstrap",target=str(user),result="mfa-enrollment-required")
    return str(user),str(factor)


def main() -> int:
    parser=argparse.ArgumentParser(description="Bootstrap a new local tenant and MFA-pending administrator")
    parser.add_argument("--dsn-file",required=True,type=Path)
    parser.add_argument("--password-file",required=True,type=Path)
    parser.add_argument("--tenant-id",required=True)
    parser.add_argument("--name",required=True)
    parser.add_argument("--username",required=True)
    parser.add_argument("--mfa-reference",required=True)
    args=parser.parse_args()
    try:
        password=read_secret(args.password_file).decode("utf-8")
        with psycopg.connect(read_secret(args.dsn_file).decode().strip(),connect_timeout=5) as connection:
            user,factor=bootstrap_tenant(connection,tenant_id=args.tenant_id,name=args.name,
                username=args.username,password=password,mfa_reference=args.mfa_reference)
        print(f"Bootstrap committed. User ID: {user}; pending MFA factor ID: {factor}")
        return 0
    except Exception:
        print("Bootstrap failed; no credentials were overwritten. Check schema, duplicate tenant and protected input files.")
        return 1


if __name__=="__main__":
    raise SystemExit(main())
