"""Container test entry point; creates an owner-only ephemeral test DSN file."""

import os
from pathlib import Path
import tempfile
import argparse
from run_tests import run


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--report")
    args = parser.parse_args()
    dsn = os.environ.pop("TACACS_EPHEMERAL_TEST_DSN")
    with tempfile.TemporaryDirectory(prefix="tacacs-db-test-") as directory:
        path = Path(directory) / "dsn"
        path.write_text(dsn, encoding="utf-8")
        path.chmod(0o600)
        os.environ["TACACS_TEST_DSN_FILE"] = str(path)
        raise SystemExit(
            run(
                pattern="test*.py" if args.full else "test_postgres_integration.py",
                report=args.report,
            )
        )
