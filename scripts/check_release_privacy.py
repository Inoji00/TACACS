"""Check tracked release files without printing matching content."""
from pathlib import Path
import ipaddress
import re
import subprocess


PROTECTED_DIRS = {"data", "secrets", "admin-secrets", "provisioning", "artifacts"}
BROWSER_DATABASES = {
    "cookies", "history", "login data", "login data for account", "web data",
}
SQLITE_SIDECARS = ("-wal", "-shm", "-journal")
PROTECTED_SUFFIXES = {".dump", ".pem", ".key", ".p12", ".pfx", ".log", ".sqlite", ".sqlite3"}
SECRET_MARKERS = re.compile(
    rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
    rb"|hooks\.slack(?:-gov)?\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"
    rb"|\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b"
)


def browser_profile_file(name):
    normalized = name.lower()
    for suffix in SQLITE_SIDECARS:
        normalized = normalized.removesuffix(suffix)
    return normalized in BROWSER_DATABASES


def main():
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    errors = []
    private_ranges = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
    for entry in tracked.decode("utf-8").split("\0"):
        if not entry:
            continue
        path = root / entry
        if (path.relative_to(root).parts[0] in PROTECTED_DIRS or path.name == ".env"
                or path.name.startswith(".env.") or path.suffix.lower() in PROTECTED_SUFFIXES):
            errors.append((entry, "runtime data or credential file"))
            continue
        if browser_profile_file(path.name):
            errors.append((entry, "browser profile database"))
            continue
        content = path.read_bytes()
        if SECRET_MARKERS.search(content):
            errors.append((entry, "credential marker"))
        if path.suffix.lower() == ".md":
            for address in re.findall(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", content):
                try:
                    ip = ipaddress.ip_address(address.decode("ascii"))
                except ValueError:
                    continue
                if any(ip in network for network in private_ranges):
                    errors.append((entry, "private address in documentation; use an example address"))
                    break
    for path, reason in errors:
        print(f"{path}: {reason}")
    if not errors:
        print("Tracked release files passed privacy checks.")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
