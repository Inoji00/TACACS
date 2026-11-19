import base64
import os
from pathlib import Path
import stat
import tempfile
import unittest
from urllib.parse import urlsplit,unquote,parse_qs
from unittest.mock import patch
from tacacs_appliance.mfa_setup import enrollment_uri,export_uri
from tacacs_appliance.mfa import totp


class MfaSetupTests(unittest.TestCase):
    def test_uri_roundtrip_matches_existing_raw_sha256_secret(self):
        secret=b'test-only-enrollment-secret-32bytes'
        parsed=urlsplit(enrollment_uri(secret,issuer='Local & On Prem',account='admin@example.test'))
        self.assertEqual(parsed.scheme,'otpauth');self.assertEqual(parsed.netloc,'totp')
        self.assertEqual(unquote(parsed.path),'/Local & On Prem:admin@example.test')
        parameters=parse_qs(parsed.query)
        self.assertEqual(parameters['algorithm'],['SHA256']);self.assertEqual(parameters['digits'],['6']);self.assertEqual(parameters['period'],['30'])
        encoded=parameters['secret'][0]
        decoded=base64.b32decode(encoded+'='*((-len(encoded))%8))
        self.assertEqual(decoded,secret);self.assertEqual(totp(decoded,123456),totp(secret,123456))

    def test_invalid_secret_or_ambiguous_label_rejected(self):
        with self.assertRaises(ValueError):enrollment_uri(b'short',issuer='Local',account='admin')
        for label in ('','tenant:admin','bad\nlabel','x'*254):
            with self.assertRaises(ValueError):enrollment_uri(b'x'*32,issuer=label,account='admin')

    @unittest.skipUnless(os.name=='posix','POSIX export permissions required')
    def test_export_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'enrollment.uri'
            export_uri(path,'test-only-uri')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):export_uri(path,'replacement')
            self.assertEqual(path.read_text(),'test-only-uri')

    @unittest.skipUnless(os.name=='posix','POSIX export permissions required')
    def test_unsafe_directory_and_link_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);parent.chmod(0o755);path=parent/'uri'
            with self.assertRaises(ValueError):export_uri(path,'test-only-uri')
            self.assertFalse(path.exists());parent.chmod(0o700)
            path.symlink_to(parent/'absent')
            with self.assertRaises(ValueError):export_uri(path,'test-only-uri')
            self.assertFalse((parent/'absent').exists())

    @unittest.skipUnless(os.name=='posix','POSIX directory descriptor required')
    def test_creation_stays_in_validated_directory_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);parent=root/'private';parent.mkdir(mode=0o700)
            original=root/'original';native_open=os.open
            def replace_before_create(path,flags,*args,**kwargs):
                if 'dir_fd' in kwargs:
                    parent.rename(original);parent.mkdir(mode=0o755)
                return native_open(path,flags,*args,**kwargs)
            with patch('tacacs_appliance.mfa_setup.os.open',side_effect=replace_before_create):
                export_uri(parent/'uri','test-only-uri')
            self.assertFalse((parent/'uri').exists())
            self.assertEqual((original/'uri').read_text(),'test-only-uri')
            self.assertEqual(stat.S_IMODE((original/'uri').stat().st_mode),0o600)
