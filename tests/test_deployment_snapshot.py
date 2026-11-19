from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import deployment_snapshot


class DeploymentSnapshotTests(unittest.TestCase):
    def test_vm_probe_uses_configured_admin_ip_and_publishes_snapshot(self):
        project = 'tnac-' + 'a' * 32
        admin_ip = '192.0.2.152'
        writes = []

        def docker(args, **kwargs):
            if args[1:3] == ['ps', '-aq']:
                self.assertIn('label=com.docker.compose.project=' + project, args)
                self.assertIn('label=com.docker.compose.oneoff=False', args)
                return SimpleNamespace(stdout='')
            self.assertEqual(args[1], 'run')
            writes.append(json.loads(kwargs['input']))

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / 'vm-profile.json').write_text(
                json.dumps({'server_ip': admin_ip, 'admin_ip': admin_ip}), encoding='utf-8')
            response = MagicMock()
            response.__enter__.return_value.status = 200
            with patch.object(deployment_snapshot.local, 'run', side_effect=docker), \
                 patch.object(deployment_snapshot, 'host_metrics', return_value={
                     'uptime_seconds':60,'cpu_percent':1,'memory_percent':20,'disk_percent':30}), \
                 patch.object(deployment_snapshot.socket, 'create_connection'), \
                 patch.object(deployment_snapshot.ssl, 'create_default_context'), \
                 patch.object(deployment_snapshot, 'urlopen', return_value=response) as probe:
                deployment_snapshot.capture(directory, {'project': project}, 'vm', admin_ip)

        self.assertEqual(probe.call_args.args[0], 'https://192.0.2.152:8443/')
        self.assertEqual(len(writes), 1)
        self.assertTrue(writes[0]['https_probe'])
        self.assertIn('proxy', writes[0]['probe_latency_ms'])
