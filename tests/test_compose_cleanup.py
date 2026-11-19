import subprocess
import unittest
from unittest.mock import patch
import importlib.util
from pathlib import Path

spec=importlib.util.spec_from_file_location('compose_smoke_runner',Path(__file__).resolve().parents[1]/'scripts/test_compose.py')
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
cleanup_fixture=runner.cleanup_fixture


class ComposeCleanupTests(unittest.TestCase):
    project='tacacs-smoke-'+'a'*32

    def test_empty_verified_inventory_passes_even_when_already_removed(self):
        def run(command,**kwargs):
            return subprocess.CompletedProcess(command,1 if 'rm' in command else 0,'','')
        with patch.object(runner.subprocess,'run',side_effect=run):
            self.assertTrue(cleanup_fixture(['docker','compose'],self.project,{},configured=True))

    def test_leftover_volume_fails_cleanup(self):
        def run(command,**kwargs):
            return subprocess.CompletedProcess(command,0,self.project+'-runtime\n' if command[1:3]==['volume','ls'] else '','')
        with patch.object(runner.subprocess,'run',side_effect=run):
            self.assertFalse(cleanup_fixture([],self.project,{},configured=False))

    def test_timeout_does_not_prevent_remaining_cleanup_attempts(self):
        calls=[]
        def run(command,**kwargs):
            calls.append(command)
            if 'down' in command:raise subprocess.TimeoutExpired(command,30)
            return subprocess.CompletedProcess(command,0,'','')
        with patch.object(runner.subprocess,'run',side_effect=run):
            self.assertFalse(cleanup_fixture([],self.project,{'runtime':self.project+'-runtime'},configured=True))
        self.assertTrue(any(command[1:3]==['volume','rm'] for command in calls))
        self.assertTrue(any(command[1:3]==['network','ls'] for command in calls))

    def test_non_fixture_targets_rejected_before_commands(self):
        with patch.object(runner.subprocess,'run') as run:
            with self.assertRaises(ValueError):cleanup_fixture([],'operator',{},configured=False)
            with self.assertRaises(ValueError):cleanup_fixture([],self.project,{'runtime':'operator-volume'},configured=False)
        run.assert_not_called()
