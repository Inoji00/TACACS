import socket
import struct
import threading
import time
import unittest

from tacacs_appliance.protocol import AUTHENTICATION
from tacacs_appliance.server import ListenerConfig, TacacsListener, _read_exact


def frame(body=b"ok", sequence=1, session_id=7):
    return struct.pack("!BBBBII", 0xC0, AUTHENTICATION, sequence, 0, session_id, len(body)) + body


class ListenerTests(unittest.TestCase):
    def test_valid_received_frame_increments_metric(self):
        from tacacs_appliance.metrics import Metrics
        metrics=Metrics()
        self.listener._metrics=metrics
        with socket.create_connection(self.listener.address,timeout=1) as client:
            client.sendall(frame())
        self.assertTrue(self.ready.wait(1))
        self.assertIn("tacacs_requests_total 1\n",metrics.prometheus())
    def test_default_port_is_standard_tcp_49(self):
        self.assertEqual(ListenerConfig().port, 49)

    def test_shutdown_closes_active_and_queued_connections(self):
        listener = TacacsListener(
            ListenerConfig(host="127.0.0.1", port=0,
                           allowed_sources=("127.0.0.0/8",), worker_limit=1,
                           read_timeout_seconds=30), lambda *_: None)
        listener.start()
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        clients = [socket.create_connection(listener.address, timeout=1) for _ in range(3)]
        stopped = threading.Event()
        shutdown_thread = None
        try:
            until = time.monotonic() + 1
            while time.monotonic() < until:
                with listener._clients_lock:
                    if len(listener._clients) == 3:
                        break
                time.sleep(0.01)
            with listener._clients_lock:
                self.assertEqual(len(listener._clients), 3)
            shutdown_thread = threading.Thread(target=lambda: (listener.shutdown(), stopped.set()), daemon=True)
            shutdown_thread.start()
            self.assertTrue(stopped.wait(2), "shutdown waited for client read timeout")
            with listener._clients_lock:
                self.assertEqual(len(listener._clients), 0)
            with self.assertRaises(RuntimeError):
                listener.start()
        finally:
            for client in clients:
                client.close()
            if shutdown_thread is None:
                listener.shutdown()
            else:
                shutdown_thread.join(2)
            thread.join(1)

    def test_slow_drip_cannot_extend_absolute_read_deadline(self):
        receiver, sender = socket.socketpair()
        stop = threading.Event()
        def drip():
            while not stop.wait(0.03):
                try:
                    sender.sendall(b"x")
                except OSError:
                    break
        thread = threading.Thread(target=drip, daemon=True)
        thread.start()
        try:
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                _read_exact(receiver, 100, deadline=start + 0.15)
            self.assertLess(time.monotonic() - start, 0.6)
        finally:
            stop.set()
            receiver.close()
            sender.close()
            thread.join(1)

    def setUp(self):
        self.seen = []
        self.ready = threading.Event()
        self.listener = TacacsListener(
            ListenerConfig(host="127.0.0.1", port=0, allowed_sources=("127.0.0.0/8",)),
            lambda remote, parsed: (self.seen.append((remote, parsed)), self.ready.set(), None)[2],
        )
        self.listener.start()
        self.thread = threading.Thread(target=self.listener.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.listener.shutdown()
        self.thread.join(timeout=1)

    def test_accepts_allowlisted_valid_frame(self):
        host, port = self.listener.address
        with socket.create_connection((host, port), timeout=1) as client:
            client.sendall(frame())
        self.assertTrue(self.ready.wait(1), "listener did not dispatch frame")
        self.assertEqual(self.seen[0][0], "127.0.0.1")
        self.assertEqual(self.seen[0][1].body, b"ok")

    def test_default_deny_source_list(self):
        listener = TacacsListener(
            ListenerConfig(host="127.0.0.1", port=0), lambda *_: self.ready.set()
        )
        listener.start()
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = listener.address
            with socket.create_connection((host, port), timeout=1) as client:
                client.sendall(frame())
                time.sleep(0.05)
            self.assertFalse(self.ready.is_set())
        finally:
            listener.shutdown()
            thread.join(timeout=1)

        self.assertEqual(listener._source_limiter._buckets, {})

    def test_exhausted_dynamic_source_skips_registry_lookup(self):
        from unittest.mock import Mock

        registry = Mock(return_value=True)
        listener = TacacsListener(
            ListenerConfig(source_rate_capacity=1), lambda *_: None, source_state=registry
        )
        try:
            self.assertTrue(listener._source_limiter.allow("192.0.2.10"))
            self.assertTrue(listener._slots.acquire(blocking=False))
            client = Mock()
            listener._handle_client(client, "192.0.2.10")
            registry.assert_not_called()
            client.close.assert_called_once()
        finally:
            listener.shutdown()

    def test_slow_dynamic_acl_does_not_block_a_second_connection(self):
        first_started = threading.Event()
        release_first = threading.Event()
        second_dispatched = threading.Event()
        lock = threading.Lock()
        calls = 0

        def source_state(_):
            nonlocal calls
            with lock:
                calls += 1
                is_first = calls == 1
            if is_first:
                first_started.set()
                release_first.wait(timeout=5)
                return False
            return True

        listener = TacacsListener(
            ListenerConfig(host="127.0.0.1", port=0, worker_limit=2),
            lambda *_: second_dispatched.set(),
            source_state=source_state,
        )
        listener.start()
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(listener.address, timeout=1):
                self.assertTrue(first_started.wait(1))
                with socket.create_connection(listener.address, timeout=1) as second:
                    second.sendall(frame())
                    self.assertTrue(second_dispatched.wait(1))
        finally:
            release_first.set()
            listener.shutdown()
            thread.join(timeout=1)

    def test_handler_can_return_protocol_response(self):
        self.listener.shutdown(); self.thread.join(timeout=1)
        self.listener = TacacsListener(
            ListenerConfig(host="127.0.0.1", port=0, allowed_sources=("127.0.0.0/8",)),
            lambda *_: frame(b"safe-reply", sequence=2),
        )
        self.listener.start(); self.thread=threading.Thread(target=self.listener.serve_forever,daemon=True);self.thread.start()
        host,port=self.listener.address
        with socket.create_connection((host,port),timeout=1) as client:
            client.sendall(frame());self.assertEqual(client.recv(64),frame(b"safe-reply", sequence=2))

    def test_listener_drops_response_for_another_session(self):
        self.listener.shutdown(); self.thread.join(timeout=1)
        self.listener = TacacsListener(
            ListenerConfig(host="127.0.0.1", port=0, allowed_sources=("127.0.0.0/8",)),
            lambda *_: frame(b"reply", sequence=2, session_id=8),
        )
        self.listener.start()
        self.thread = threading.Thread(target=self.listener.serve_forever, daemon=True)
        self.thread.start()
        with socket.create_connection(self.listener.address, timeout=1) as client:
            client.sendall(frame())
            self.assertEqual(client.recv(64), b"")

    def test_listener_drops_invalid_handler_response(self):
        self.listener.shutdown(); self.thread.join(timeout=1)
        self.listener = TacacsListener(
            ListenerConfig(host="127.0.0.1", port=0, allowed_sources=("127.0.0.0/8",)),
            lambda *_: b"not-a-tacacs-frame",
        )
        self.listener.start(); self.thread=threading.Thread(target=self.listener.serve_forever,daemon=True);self.thread.start()
        host,port=self.listener.address
        with socket.create_connection((host,port),timeout=1) as client:
            client.sendall(frame()); client.settimeout(1)
            self.assertEqual(client.recv(64),b"")
