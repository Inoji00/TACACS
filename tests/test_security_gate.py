"""The CI gate must not pass a missing report or hide unfixed vulnerabilities."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

spec = importlib.util.spec_from_file_location('security_gate', Path(__file__).resolve().parents[1]/'scripts/check_trivy.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class SecurityGateTests(unittest.TestCase):
    def check(self, payload):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            path = Path(directory)/'report.json'
            if payload is not None:
                path.write_text(json.dumps(payload), encoding='utf-8')
            return gate.main([path])

    def report(self, severity):
        return {'SchemaVersion':2, 'ArtifactName':'tnac:ci', 'Results':[
            {'Vulnerabilities':[{'Severity':severity}]}]}

    def test_missing_or_unrelated_report_fails(self):
        self.assertEqual(self.check(None), 1)
        self.assertEqual(self.check({}), 1)

    def test_high_and_critical_without_fix_fail(self):
        self.assertEqual(self.check(self.report('HIGH')), 1)
        self.assertEqual(self.check(self.report('CRITICAL')), 1)

    def test_lower_severity_is_reported_without_blocking(self):
        self.assertEqual(self.check(self.report('MEDIUM')), 0)


if __name__ == '__main__':
    unittest.main()
