import unittest
from tacacs_appliance.metrics import Metrics
class MetricsTests(unittest.TestCase):
 def test_allowlisted_metrics_only(self):
  m=Metrics();m.increment("tacacs_requests_total");self.assertEqual(m.prometheus(),"# TYPE tacacs_requests_total counter\ntacacs_requests_total 1\n")
  with self.assertRaises(ValueError):m.increment("tacacs_requests_total{username=alice}")
