import hashlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch
from tacacs_appliance.artifact_integrity import verify_wheelhouse


class ArtifactIntegrityTests(unittest.TestCase):
    def test_exact_wheel_digest_verified(self):
        expected={"package.whl":hashlib.sha256(b"wheel").hexdigest()}
        with patch.object(Path,"glob",return_value=[Path("package.whl")]), \
             patch.object(Path,"is_symlink",return_value=False),patch.object(Path,"is_file",return_value=True), \
             patch.object(Path,"open",side_effect=lambda *_:io.BytesIO(b"wheel")):
            self.assertTrue(verify_wheelhouse(Path("bundle"),expected))
            self.assertFalse(verify_wheelhouse(Path("bundle"),{"package.whl":"0"*64}))

    def test_traversal_empty_and_extra_wheels_rejected(self):
        for manifest in ({},{"../secret.whl":"0"*64},{"x.whl":"bad"}):
            self.assertFalse(verify_wheelhouse(Path("bundle"),manifest))
        with patch.object(Path,"glob",return_value=[Path("extra.whl")]):
            self.assertFalse(verify_wheelhouse(Path("bundle"),{"x.whl":"0"*64}))
