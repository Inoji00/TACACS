"""Run committed unittest cases and record counts without treating skips as passes."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def run(*, pattern="test*.py", report=None, exclude=()):
    root = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern=pattern)
    excluded = []

    def selected(tests):
        result = unittest.TestSuite()
        for test in tests:
            if isinstance(test, unittest.TestSuite):
                result.addTests(selected(test))
            elif test.__class__.__module__ in exclude:
                excluded.append(test.id())
            else:
                result.addTest(test)
        return result

    suite = selected(suite)
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    evidence = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "run": result.testsRun,
        "passed": result.passed,
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "failures": [test.id() for test, _ in result.failures],
        "errors": [test.id() for test, _ in result.errors],
        "expected_failures": [test.id() for test, _ in result.expectedFailures],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "excluded": excluded,
        "successful": result.wasSuccessful() and result.testsRun > 0,
    }
    if report:
        path = Path(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"Passed: {len(result.passed)}; skipped: {len(result.skipped)}; "
          f"excluded: {len(excluded)}; failures: {len(result.failures)}; errors: {len(result.errors)}")
    return 0 if evidence["successful"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pattern", default="test*.py")
    parser.add_argument("--report")
    parser.add_argument("--exclude", action="append", default=[], help="Explicit module exclusion, recorded in report")
    args = parser.parse_args()
    raise SystemExit(run(pattern=args.pattern, report=args.report, exclude=args.exclude))
