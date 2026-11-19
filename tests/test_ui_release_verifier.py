import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from verify_ui_release import verify


class UiReleaseVerifierTests(unittest.TestCase):
    def test_matches_actual_script_and_detects_wrong_release(self):
        script=b'Delete policy; Edit as new draft'
        html=b'<script src="/console.js?v=version"></script>'
        for expected,matches in ((hashlib.sha256(script).hexdigest(),True),('0'*64,False)):
            page,asset=MagicMock(),MagicMock()
            page.__enter__.return_value=page;asset.__enter__.return_value=asset
            page.read.return_value=html;page.geturl.return_value='https://192.0.2.2:8443/'
            asset.read.return_value=script;asset.geturl.return_value='https://192.0.2.2:8443/console.js?v=version'
            with patch('verify_ui_release.urlopen',side_effect=[page,asset]):
                result=verify('https://192.0.2.2:8443',{'console_js_sha256':expected},MagicMock())
            self.assertEqual(result['matches_release'],matches)
            self.assertTrue(result['delete_policy_code_present'])

    def test_refuses_external_script_reference(self):
        page=MagicMock();page.__enter__.return_value=page
        page.read.return_value=b'<script src="https://other.example/console.js"></script>'
        page.geturl.return_value='https://192.0.2.2:8443/'
        with patch('verify_ui_release.urlopen',return_value=page) as read:
            with self.assertRaises(ValueError):verify('https://192.0.2.2:8443',{'console_js_sha256':'0'*64},MagicMock())
            self.assertEqual(read.call_count,1)
