import threading,unittest,urllib.request,urllib.error
from tacacs_appliance.health import create_health_server
class HealthTests(unittest.TestCase):
 def test_dependency_exception_returns_generic_unavailable(self):
  def unavailable():raise OSError("sensitive database connection details")
  server=create_health_server(("127.0.0.1",0),unavailable);threading.Thread(target=server.serve_forever,daemon=True).start()
  try:
   with self.assertRaises(urllib.error.HTTPError) as caught:urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/health/ready")
   self.assertEqual(caught.exception.code,503)
   self.assertEqual(caught.exception.read(),b'{"status":"unavailable"}')
  finally:server.shutdown();server.server_close()
 def test_live_and_readiness(self):
  server=create_health_server(("127.0.0.1",0),lambda:False);threading.Thread(target=server.serve_forever,daemon=True).start();base=f"http://127.0.0.1:{server.server_port}"
  try:
   self.assertEqual(urllib.request.urlopen(base+"/health/live").status,200)
   with self.assertRaises(urllib.error.HTTPError) as e:urllib.request.urlopen(base+"/health/ready")
   self.assertEqual(e.exception.code,503)
  finally:server.shutdown();server.server_close()
