from concurrent.futures import ThreadPoolExecutor
import http.client
import threading
import unittest
from tacacs_appliance.metrics import Metrics
from tacacs_appliance.health import create_health_server


class MetricsEndpointTests(unittest.TestCase):
    def test_concurrent_counter_updates_have_no_lost_increments(self):
        metrics=Metrics()
        def increment():
            for _ in range(1000): metrics.increment("tacacs_requests_total")
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(lambda _:increment(),range(8)))
        self.assertIn("tacacs_requests_total 8000\n",metrics.prometheus())
        with self.assertRaises(ValueError): metrics.increment("username_admin")

    def test_metrics_http_response_and_content_length(self):
        metrics=Metrics();metrics.increment("tacacs_requests_total")
        server=create_health_server(("127.0.0.1",0),lambda:True,metrics=metrics.prometheus)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        client=http.client.HTTPConnection(*server.server_address,timeout=2)
        try:
            client.request("GET","/metrics")
            response=client.getresponse();body=response.read()
            self.assertEqual(response.status,200)
            self.assertEqual(int(response.getheader("Content-Length")),len(body))
            self.assertIn(b"# TYPE tacacs_requests_total counter",body)
            self.assertTrue(response.getheader("Content-Type").startswith("text/plain"))
        finally:
            client.close();server.shutdown();server.server_close();thread.join(2)
