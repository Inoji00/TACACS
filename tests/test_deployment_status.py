from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import tempfile
import unittest
from tacacs_appliance.deployment_status import DeploymentStatus, validate_snapshot


class DeploymentStatusTests(unittest.TestCase):
    def test_service_metrics_require_valid_timestamps_and_successful_probe(self):
        data=dict(observed_at='2026-11-12T08:00:00+00:00',mode='vm',endpoints=[],
                  tcp_probe=True,https_probe=False,
                  service_started_at={'app':'2026-11-12T07:00:00+00:00'},
                  probe_latency_ms={'app':0.2})
        validate_snapshot(data)
        for update in (
            {'tcp_probe':False}, {'probe_latency_ms':{'admin':0.2}},
            {'probe_latency_ms':{'app':float('nan')}},
            {'service_started_at':{'app':'2026-11-12T09:00:00+00:00'}},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                validate_snapshot({**data,**update})

    def test_live_resources_expire_independently_of_docker_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'status.json'
            resource_path=path.with_name('resource-status.json')
            now=datetime.now(timezone.utc)
            resources=dict(observed_at=now.isoformat(),system=dict(
                cpu_percent=0,memory_percent=35,disk_percent=10,uptime_seconds=60))
            resource_path.write_text(json.dumps(resources))
            reader=DeploymentStatus(path)
            result=reader.read()
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(result['live_resources'],resources)
            resources['observed_at']=(now-timedelta(seconds=30)).isoformat()
            resource_path.write_text(json.dumps(resources))
            self.assertNotIn('live_resources',reader.read())

    def test_snapshot_stale_future_missing_and_secret_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'status.json';reader=DeploymentStatus(path)
            self.assertEqual(reader.read()['state'],'unknown')
            data=dict(observed_at=datetime.now(timezone.utc).isoformat(),mode='local',
                endpoints=[dict(service='tacacs',address='127.0.0.1',port=49)],tcp_probe=True,https_probe=True)
            path.write_text(json.dumps(data))
            self.assertEqual(reader.read()['state'],'snapshot')
            self.assertEqual(reader.read()['runtime_acknowledgement'],'not-measured')
            data['observed_at']=(datetime.now(timezone.utc)-timedelta(minutes=6)).isoformat()
            path.write_text(json.dumps(data));self.assertEqual(reader.read()['state'],'stale')
            data['observed_at']=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
            path.write_text(json.dumps(data));self.assertEqual(reader.read()['state'],'unknown')
            data['secret']='DO-NOT-RETURN'
            path.write_text(json.dumps(data));self.assertNotIn('DO-NOT-RETURN',str(reader.read()))

    def test_oversized_or_malformed_snapshot_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'status.json'
            for value in ('x'*8193,'{}','null','{"mode":"local"}'):
                path.write_text(value)
                self.assertEqual(DeploymentStatus(path).read()['state'],'unknown')
