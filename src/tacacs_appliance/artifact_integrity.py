"""Verify an externally trusted wheel checksum manifest; not a signature."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def verify_wheelhouse(directory: Path, expected: dict) -> bool:
    if not isinstance(expected,dict) or not expected or len(expected)>256:
        return False
    for name,digest in expected.items():
        if (not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl",name)
                or not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{64}",digest)):
            return False
    files=list(directory.glob("*.whl"))
    if {p.name for p in files} != set(expected):
        return False
    for path in files:
        if path.is_symlink() or not path.is_file():
            return False
        digest=hashlib.sha256()
        with path.open("rb") as stream:
            while chunk:=stream.read(1024*1024):
                digest.update(chunk)
        if digest.hexdigest()!=expected[path.name]:
            return False
    return True


def main() -> int:
    parser=argparse.ArgumentParser(description="Verify offline wheelhouse against trusted SHA256 manifest")
    parser.add_argument("--directory",required=True,type=Path)
    parser.add_argument("--manifest",required=True,type=Path)
    args=parser.parse_args()
    try:
        with args.manifest.open("rb") as stream: raw=stream.read(65537)
        if len(raw)>65536:raise ValueError("manifest too large")
        accepted=verify_wheelhouse(args.directory,json.loads(raw))
    except Exception:
        accepted=False
    print("Wheelhouse verified." if accepted else "Wheelhouse verification failed.")
    return 0 if accepted else 1


if __name__=="__main__":raise SystemExit(main())
