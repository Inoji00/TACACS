"""Offline TOTP enrollment URI export; never prints secret material."""
import argparse
import base64
import os
from pathlib import Path
import stat
from urllib.parse import quote,urlencode
from .runtime import read_secret


def enrollment_uri(secret: bytes,*,issuer: str,account: str) -> str:
    if not isinstance(secret,bytes) or not 20<=len(secret)<=4096:
        raise ValueError('bounded raw TOTP secret required')
    for value in (issuer,account):
        if not isinstance(value,str) or not 1<=len(value)<=253 or ':' in value or any(ord(c)<32 or ord(c)==127 for c in value):
            raise ValueError('bounded issuer and account without colons or controls required')
    label=quote(issuer,safe='')+':'+quote(account,safe='')
    parameters=urlencode({'secret':base64.b32encode(secret).decode('ascii').rstrip('='),
        'issuer':issuer,'algorithm':'SHA256','digits':'6','period':'30'})
    return 'otpauth://totp/'+label+'?'+parameters


def export_uri(path: Path,uri: str) -> None:
    # Windows chmod does not establish restrictive ACLs: fail explicitly rather
    # than pretend mode 0600 protects an exported enrollment credential.
    if os.name!='posix':raise ValueError('protected export currently requires POSIX permissions')
    parent=path.absolute().parent
    if parent.resolve()!=parent or path.is_symlink():raise ValueError('export links forbidden')
    payload=uri.encode('ascii')
    directory_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(directory_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.geteuid()) or info.st_mode & 0o077:
            raise ValueError('owner-only export directory required')
        # Anchor creation to the validated directory inode, not a path that
        # could be replaced between permission checking and credential export.
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory_fd)
        with os.fdopen(fd,'wb') as stream:
            stream.write(payload);stream.flush();os.fsync(stream.fileno())
        os.fsync(directory_fd)
    finally:os.close(directory_fd)


def main() -> int:
    parser=argparse.ArgumentParser(description='Export a protected local TOTP enrollment URI')
    parser.add_argument('--secret-file',required=True,type=Path)
    parser.add_argument('--output-file',required=True,type=Path)
    parser.add_argument('--issuer',required=True)
    parser.add_argument('--account',required=True)
    args=parser.parse_args()
    try:
        export_uri(args.output_file,enrollment_uri(read_secret(args.secret_file),issuer=args.issuer,account=args.account))
        print('Protected enrollment URI created. Import locally into a SHA-256-compatible authenticator, then confirm the pending factor.')
        return 0
    except Exception:
        print('Enrollment export failed. Check protected input/output paths; existing files are never replaced.')
        return 1


if __name__=='__main__':raise SystemExit(main())
