from types import SimpleNamespace
import stat
import unittest
from tacacs_appliance.runtime import validate_secret_metadata


class SecretFilePermissionTests(unittest.TestCase):
    def metadata(self, mode, owner=10001):
        return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=owner)

    def test_private_owner_and_dedicated_group_read_allowed(self):
        for mode in (0o400, 0o600, 0o640, 0o440):
            for owner in (0,10001):
                validate_secret_metadata(self.metadata(mode,owner),posix=True,runtime_uid=10001)

    def test_group_write_execute_and_public_access_rejected(self):
        for mode in (0o660, 0o644, 0o700, 0o650, 0o601, 0o602):
            with self.assertRaises(ValueError):
                validate_secret_metadata(self.metadata(mode),posix=True,runtime_uid=10001)

    def test_untrusted_owner_rejected(self):
        with self.assertRaises(ValueError):
            validate_secret_metadata(self.metadata(0o600,20002),posix=True,runtime_uid=10001)

    def test_nonregular_file_rejected_on_every_platform(self):
        for posix in (True,False):
            with self.assertRaises(ValueError):
                validate_secret_metadata(SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=10001),posix=posix,runtime_uid=10001)
