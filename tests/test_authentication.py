import unittest

from tacacs_appliance.authentication import AuthenticationLimits, AuthenticationPacketError, AuthenticationReply, encode_authentication_reply, parse_authentication_continue, parse_authentication_start


def start_body(user=b"alice", port=b"vty0", remote=b"10.0.0.8", data=b""):
    return bytes((1, 15, 1, 1, len(user), len(port), len(remote), len(data))) + user + port + remote + data


class AuthenticationStartTests(unittest.TestCase):
    def test_parses_exact_length_fields(self):
        result = parse_authentication_start(start_body(data=b"password-prompt"))
        self.assertEqual(result.username, "alice")
        self.assertEqual(result.port, "vty0")
        self.assertEqual(result.remote_address, "10.0.0.8")
        self.assertEqual(result.privilege_level, 15)

    def test_rejects_truncated_or_hidden_suffix(self):
        for body in (b"\x01", start_body()[:-1], start_body() + b"hidden"):
            with self.subTest(body=body):
                with self.assertRaises(AuthenticationPacketError):
                    parse_authentication_start(body)

    def test_rejects_control_and_oversized_username(self):
        with self.assertRaises(AuthenticationPacketError):
            parse_authentication_start(start_body(user=b"alice\nadmin"))
        with self.assertRaises(AuthenticationPacketError):
            parse_authentication_start(start_body(user=b"a" * 20), AuthenticationLimits(max_username_bytes=16))

    def test_continue_and_reply_encoding(self):
        body = b"\x00\x06\x00\x02\x00secret\x01\x02"
        result = parse_authentication_continue(body)
        self.assertEqual(result.user_message, "secret")
        self.assertEqual(result.user_data, b"\x01\x02")
        encoded = encode_authentication_reply(AuthenticationReply(status=1, server_message="ok"))
        self.assertEqual(encoded, b"\x01\x00\x00\x02\x00\x00ok")

    def test_rejects_invalid_continue_lengths(self):
        with self.assertRaises(AuthenticationPacketError):
            parse_authentication_continue(b"\x00\x05\x00\x00\x00bad")
