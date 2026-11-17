"""Local operator confirmation; neither MFA secret nor code is printed."""
import argparse
from getpass import getpass, GetPassWarning
import warnings
from pathlib import Path
import psycopg
from .runtime import read_secret
from .schema_manifest import validate_schema
from .mfa_enrollment import confirm_pending_factor


def matching_file_resolver(expected_reference: str, path: Path):
    if not expected_reference.startswith("secret://") or len(expected_reference)<=9:
        raise ValueError("valid secret reference required")
    def resolve(reference):
        if reference != expected_reference:
            raise ValueError("factor secret reference mismatch")
        return read_secret(path)
    return resolve


def main() -> int:
    parser=argparse.ArgumentParser(description="Confirm a pending local administrator TOTP factor")
    parser.add_argument("--dsn-file",required=True,type=Path)
    parser.add_argument("--secret-file",required=True,type=Path)
    parser.add_argument("--secret-reference",required=True)
    parser.add_argument("--tenant-id",required=True)
    parser.add_argument("--user-id",required=True)
    parser.add_argument("--factor-id",required=True)
    args=parser.parse_args()
    try:
        resolver=matching_file_resolver(args.secret_reference,args.secret_file)
        # No --code argument: process listings/history must not contain it.
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            code=getpass("TOTP confirmation code: ")
        with psycopg.connect(read_secret(args.dsn_file).decode().strip(),connect_timeout=5) as connection:
            validate_schema(connection)
            accepted=confirm_pending_factor(connection,tenant_id=args.tenant_id,user_id=args.user_id,
                                            factor_id=args.factor_id,code=code,resolve_secret=resolver)
        if not accepted:
            print("MFA confirmation rejected; factor was not enabled.")
            return 1
        print("MFA confirmation committed. Wait for the next TOTP interval before login.")
        return 0
    except Exception:
        print("MFA confirmation failed. Check protected files, reference and pending factor.")
        return 1


if __name__=="__main__":
    raise SystemExit(main())
