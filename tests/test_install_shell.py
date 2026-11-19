"""Linux shell orchestration tests with a recording, non-mutating Docker stub."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name=='posix','Linux shell required')
class InstallShellTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='tacacs-install-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        for name in ('config','secrets','provisioning','tools'):(self.root/name).mkdir()
        (self.root/'config/service.toml').write_text('test configuration')
        (self.root/'secrets/postgres_password').write_text('test-only-password')
        for name in ('owner_dsn','aaa_password','admin_password','operator_password'):
            (self.root/'provisioning'/name).write_text('test-only-input')
        self.log=self.root/'calls'
        stub=self.root/'tools/docker'
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$INSTALL_TEST_LOG"\n'
            'case "$*" in *" run --rm --no-deps initialize") exit "${INSTALL_TEST_INIT_EXIT:-0}";; esac\nexit 0\n')
        stub.chmod(0o700)
        self.environment=os.environ|{'PATH':str(self.root/'tools')+os.pathsep+os.environ['PATH'],
            'INSTALL_TEST_LOG':str(self.log)}
        self.script=Path(__file__).resolve().parents[1]/'scripts/install.sh'
        self.environment['INSTALL_TEST_DOCKER']=str(stub)
        self.environment['INSTALL_TEST_SCRIPT']=str(self.script)

    def run_install(self,*args):
        # Source the script with a Docker function so fixtures work even when
        # the test container's temporary filesystem is deliberately noexec.
        wrapper='docker() { sh "$INSTALL_TEST_DOCKER" "$@"; }; . "$INSTALL_TEST_SCRIPT"'
        return subprocess.run(['sh','-c',wrapper,'installer-test',*args],cwd=self.root,
            env=self.environment,capture_output=True,text=True,timeout=10)

    def calls(self):return self.log.read_text().splitlines() if self.log.exists() else []

    def test_missing_database_password_never_generates_replacement_or_starts_database(self):
        password=self.root/'secrets/postgres_password';password.unlink()
        self.assertNotEqual(self.run_install('--initialize').returncode,0)
        self.assertFalse(password.exists())
        self.assertEqual(self.calls(),['compose version'])

    def test_provisioning_symlink_rejected_before_build(self):
        path=self.root/'provisioning/owner_dsn';path.unlink()
        path.symlink_to(self.root/'secrets/postgres_password')
        self.assertNotEqual(self.run_install('--initialize').returncode,0)
        self.assertEqual(self.calls(),['compose version'])

    def test_initializer_failure_prevents_runtime_start(self):
        self.environment['INSTALL_TEST_INIT_EXIT']='17'
        self.assertEqual(self.run_install('--initialize').returncode,17)
        calls=self.calls()
        self.assertTrue(any(call.endswith('up -d --wait postgres') for call in calls))
        self.assertFalse(any(call.endswith('--wait app') for call in calls))

    def test_success_orders_preflight_database_initializer_and_runtime(self):
        self.assertEqual(self.run_install('--initialize').returncode,0)
        calls=self.calls()
        preflight=next(i for i,c in enumerate(calls) if c.endswith('initialize.yml config --quiet'))
        database=next(i for i,c in enumerate(calls) if c.endswith('up -d --wait postgres'))
        initialize=next(i for i,c in enumerate(calls) if c.endswith('run --rm --no-deps initialize'))
        runtime=next(i for i,c in enumerate(calls) if c.endswith('--wait app'))
        self.assertLess(preflight,database);self.assertLess(database,initialize);self.assertLess(initialize,runtime)

    def test_normal_start_does_not_bootstrap(self):
        result=self.run_install()
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.assertFalse(any('initialize' in call for call in self.calls()))
