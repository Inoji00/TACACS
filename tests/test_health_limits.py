import socket
import threading
import time
import unittest
from tacacs_appliance.health import create_health_server


class HealthLimitTests(unittest.TestCase):
    def test_saturated_server_closes_extra_connection(self):
        server=create_health_server(("127.0.0.1",0),lambda:True,worker_limit=1)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        first=socket.create_connection(server.server_address,timeout=1)
        try:
            deadline=time.monotonic()+1
            while time.monotonic()<deadline:
                with server._clients_lock:
                    if len(server._clients)==1:break
                time.sleep(0.01)
            with server._clients_lock:self.assertEqual(len(server._clients),1)
            with socket.create_connection(server.server_address,timeout=1) as extra:
                self.assertEqual(extra.recv(16),b"")
            with server._clients_lock:self.assertEqual(len(server._clients),1)
        finally:
            server.shutdown();server.server_close();first.close();thread.join(1)

    def test_invalid_worker_limit_rejected(self):
        for limit in (0,65,True):
            with self.assertRaises(ValueError):
                create_health_server(("127.0.0.1",0),lambda:True,worker_limit=limit)
