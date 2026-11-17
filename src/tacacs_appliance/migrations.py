"""Ordered PostgreSQL migrations with checksum and concurrent-run exclusion."""
import hashlib
from pathlib import Path


def migrate(connection, directory: Path) -> None:
    """Use a dedicated connection. Refuse edits to already applied migrations.

    Migration scripts are trusted application assets, never user input. The
    caller supplies an operator-controlled directory; SQL bodies execute within
    one transaction per version, with no automatic schema downgrade.
    """
    connection.execute("SELECT pg_advisory_lock(8907001)")
    connection.commit()
    try:
        with connection.transaction():
            connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations "
                               "(name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        for path in sorted(directory.glob("[0-9]*.sql")):
            content = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(content.encode()).hexdigest()
            with connection.transaction():
                row = connection.execute("SELECT checksum FROM schema_migrations WHERE name=%s", (path.name,)).fetchone()
                if row:
                    if row[0] != checksum:
                        raise ValueError("applied migration checksum mismatch")
                    continue
                # Existing checked-in scripts have outer BEGIN/COMMIT wrappers.
                # Strip only exact boundary statements; transaction ownership
                # belongs to the runner so metadata and schema commit together.
                lines = content.strip().splitlines()
                if lines and lines[0].strip().upper() == "BEGIN;": lines = lines[1:]
                if lines and lines[-1].strip().upper() == "COMMIT;": lines = lines[:-1]
                connection.execute("\n".join(lines))
                connection.execute("INSERT INTO schema_migrations(name,checksum) VALUES (%s,%s)", (path.name,checksum))
    except BaseException:
        # Clear any aborted transaction before unlocking; otherwise PostgreSQL
        # rejects the unlock statement and can conceal the migration failure.
        connection.rollback()
        raise
    finally:
        connection.execute("SELECT pg_advisory_unlock(8907001)")
        connection.commit()
