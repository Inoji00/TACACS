import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch
from tacacs_appliance.loopback_proxy import relay
from tacacs_appliance import web_audit_network


class LoopbackProxyTests(unittest.TestCase):
    def test_opaque_bidirectional_forwarding_and_half_close(self):
        caller,front=socket.socketpair();back,server=socket.socketpair()
        for connection in (caller,front,back,server):connection.settimeout(2)
        errors=[]
        def worker():
            try:relay(front,back,timeout=2)
            except Exception as error:errors.append(error)
        thread=threading.Thread(target=worker);thread.start()
        try:
            caller.sendall(b'opaque TLS request');self.assertEqual(server.recv(100),b'opaque TLS request')
            caller.shutdown(socket.SHUT_WR);self.assertEqual(server.recv(1),b'')
            server.sendall(b'opaque TLS response');self.assertEqual(caller.recv(100),b'opaque TLS response')
            server.shutdown(socket.SHUT_WR);thread.join(2)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        finally:
            for connection in (caller,front,back,server):connection.close()
            thread.join(2)

    def test_idle_deadline_is_bounded(self):
        caller,front=socket.socketpair();back,server=socket.socketpair()
        try:
            started=time.monotonic();relay(front,back,timeout=0.05)
            self.assertLess(time.monotonic()-started,1)
        finally:
            for connection in (caller,front,back,server):connection.close()


    def test_proxy_peer_requires_matching_uid_and_reads_only_the_ipv4_prefix(self):
        connection=Mock()
        connection.gettimeout.return_value=5
        connection.getsockopt.return_value=struct.pack('3i',42,10001,10001)
        connection.recv.side_effect=(bytes((192,0)),bytes((2,27)))
        with patch.object(socket,'SO_PEERCRED',17,create=True):
            self.assertEqual(web_audit_network.proxy_peer(connection),'192.0.2.27')
            self.assertEqual([call.args for call in connection.recv.call_args_list],[(4,),(2,)])
            connection.recv.reset_mock()
            connection.getsockopt.return_value=struct.pack('3i',42,10002,10002)
            with self.assertRaises(ValueError):
                web_audit_network.proxy_peer(connection)
            connection.recv.assert_not_called()
