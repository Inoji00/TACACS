"""Fail closed on missing/invalid image reports or any HIGH/CRITICAL finding."""

import argparse
from collections import Counter
import json
from pathlib import Path


def main(paths):
    failed = False
    for path in paths:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            if (
                report.get("SchemaVersion") != 2
                or not report.get("ArtifactName")
                or "Results" not in report
            ):
                raise ValueError("not a Trivy image vulnerability report")
            counts = Counter(
                item.get("Severity", "UNKNOWN")
                for result in report["Results"]
                for item in result.get("Vulnerabilities", [])
            )
            print(
                f"{path.name}: CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} "
                f"MEDIUM={counts['MEDIUM']} LOW={counts['LOW']} UNKNOWN={counts['UNKNOWN']}"
            )
            failed |= bool(counts["CRITICAL"] or counts["HIGH"])
        except (OSError, ValueError, TypeError, KeyError):
            print(f"{path.name}: missing or invalid image scan; security gate failed")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    raise SystemExit(main(parser.parse_args().reports))
