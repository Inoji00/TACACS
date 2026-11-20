"""Interactive recovery of the administrator recorded at installation."""
import argparse
from getpass import GetPassWarning, getpass
import os
from pathlib import Path
import sys
from uuid import UUID
import warnings

from argon2 import PasswordHasher
import psycopg

from .password_policy import valid_new_password
from .postgres_audit import PostgresAuditWriter
from .runtime import read_secret
from .schema_manifest import validate_schema


def reset_admin(connection, tenant: UUID, user: UUID, password: str) -> None:
    if not valid_new_password(password):
        raise ValueError("invalid new password")
    password_hash = PasswordHasher().hash(password)
    with connection.transaction():
        validate_schema(connection)
        row = connection.execute(
            """UPDATE users AS u SET password_hash=%s, failed_logins=0, locked=false
               WHERE u.tenant_id=%s AND u.id=%s AND u.enabled AND NOT u.deleted
                   AND EXISTS (SELECT 1 FROM admin_grants g WHERE g.tenant_id=u.tenant_id
                               AND g.user_id=u.id AND g.permission='console.read')
                   AND EXISTS (SELECT 1 FROM admin_grants g WHERE g.tenant_id=u.tenant_id
                               AND g.user_id=u.id AND g.permission='users.manage')
               RETURNING u.id""",
            (password_hash, tenant, user),
        ).fetchone()
        if row is None:
            raise PermissionError("administrator unavailable")
        PostgresAuditWriter(None, str(tenant)).append_in_transaction(
            connection, actor="local-root", source="local-cli",
            action="admin.password.reset", target=str(user), result="success",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", type=UUID, required=True)
    parser.add_argument("--user-id", type=UUID, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Run from a private root terminal.", file=sys.stderr)
        return 1
    try:
        if input("Reset the installation administrator password and end its Web sessions? Type RESET: ") != "RESET":
            print("Password reset cancelled.")
            return 1
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("New administrator password: ")
            if not valid_new_password(password):
                print("Use 12–1024 characters with A–Z, a–z, 0–9 and an ASCII symbol.")
                return 1
            if getpass("Confirm password: ") != password:
                print("Passwords do not match.")
                return 1
        dsn = read_secret(Path("/run/provision/owner_dsn")).decode().strip()
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            reset_admin(connection, args.tenant_id, args.user_id, password)
    except (EOFError, KeyboardInterrupt):
        print("Password reset interrupted. Check the audit trail before retrying.")
        return 1
    except Exception:
        print("Password reset failed. Check database readiness, schema and administrator state.",
              file=sys.stderr)
        return 1
    print("Administrator password reset. Sign in with the new password and your existing MFA settings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
