"""Authentication flow exercised over a real loopback TCP connection."""
import socket
import struct
import threading
import unittest

from argon2 import PasswordHasher
from tacacs_appliance.authentication_service import AuthenticationService
from tacacs_appliance.local_identity import LocalProvider, LocalUser
from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.protocol import Frame, Header, Limits, parse_frame
from tacacs_appliance.secrets import StaticDeviceSecretProvider
from tacacs_appliance.server import ListenerConfig, TacacsListener
from tacacs_appliance.tacacs_handler import TacacsAuthenticationHandler


def read_exact(client, size):
    result = b""
    while len(result) < size:
        chunk = client.recv(size - len(result))
        if not chunk:
            raise AssertionError("server closed before complete reply")
        result += chunk
    return result


class AuthenticationSocketTests(unittest.TestCase):
    def test_start_and_password_continue_over_tcp(self):
        secret = b"z" * 14
        service = AuthenticationService(LocalProvider({"alice": LocalUser("alice", PasswordHasher().hash("good"))}))
        template = TacacsAuthenticationHandler(StaticDeviceSecretProvider({"127.0.0.1": secret}), service)
        listener = TacacsListener(ListenerConfig(host="127.0.0.1", port=0, allowed_sources=("127.0.0.1/32",)), template, handler_factory=template.new_connection)
        listener.start()
        thread = threading.Thread(target=listener.serve_forever)
        thread.start()
        try:
            with socket.create_connection(listener.address, timeout=2) as client:
                for sequence, body, expected_status in (
                    (1, bytes((1, 15, 1, 1, 5, 0, 0, 0)) + b"alice", 5),
                    (3, b"\x00\x04\x00\x00\x00good", 1),
                ):
                    request = Frame(Header(0xc0, 1, sequence, 0, 123, len(body)), body)
                    wire = struct.pack("!BBBBII", 0xc0, 1, sequence, 0, 123, len(body)) + xor_body(request, secret)
                    client.sendall(wire)
                    raw_header = read_exact(client, 12)
                    header = Header.parse(raw_header, Limits())
                    reply = parse_frame(raw_header + read_exact(client, header.length))
                    self.assertEqual(reply.header.session_id, 123)
                    self.assertEqual(reply.header.sequence, sequence + 1)
                    self.assertEqual(xor_body(reply, secret)[0], expected_status)
        finally:
            listener.shutdown()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_getuser_exchange_and_out_of_order_continue(self):
        ip, secret = "127.0.0.1", b"z" * 14
        provider = LocalProvider({"alice": LocalUser("alice", PasswordHasher().hash("good"))})
        handler = TacacsAuthenticationHandler(StaticDeviceSecretProvider({ip: secret}), AuthenticationService(provider))

        def send(sequence, body):
            header = Header(0xc0, 1, sequence, 0, 123, len(body))
            return handler(ip, Frame(header, xor_body(Frame(header, body), secret)))

        password = b"\x00\x04\x00\x00\x00good"
        address = b"2001:db8::27"
        for sequence, body, status, username in (
            (1, bytes((1, 15, 1, 1, 0, 0, len(address), 0)) + address, 4, ""),
            (3, b"\x00\x05\x00\x00\x00alice", 5, "alice"),
            (5, password, 1, "alice"),
        ):
            if sequence == 3:
                self.assertIsNone(send(5, password))
                self.assertIsNone(handler.remote_address)
            reply = parse_frame(send(sequence, body))
            self.assertEqual(reply.header.sequence, sequence + 1)
            self.assertEqual(xor_body(reply, secret)[:2], bytes((status, int(status == 5))))
            self.assertEqual(handler.attempted_username, username)
            self.assertEqual(handler.remote_address, address.decode())
        self.assertIsNone(send(5, password))
        self.assertIsNone(handler.remote_address)
