"""Operator-only migration command using a secret file, never a CLI DSN."""
import argparse
from pathlib import Path
import psycopg
from .runtime import read_secret
from .migrations import migrate


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply local TACACS+ PostgreSQL migrations")
    parser.add_argument("--dsn-file", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        files = list(args.directory.glob("[0-9]*.sql"))
        if not files:
            raise ValueError("migration directory is empty")
        dsn = read_secret(args.dsn_file).decode("utf-8").strip()
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            migrate(connection, args.directory)
        print("Migrations applied successfully.")
        return 0
    except Exception:
        # Connection diagnostics can contain passwords or sensitive endpoints.
        print("Migration failed. Check database access, migration checksums and schema compatibility.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
