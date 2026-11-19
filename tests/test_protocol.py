import struct
import unittest

from tacacs_appliance.protocol import AUTHENTICATION, HEADER_LENGTH, Header, Limits, ProtocolError, encode_frame, parse_frame


def frame(*, version=0xC0, packet_type=AUTHENTICATION, sequence=1, flags=0, body=b"x"):
    return struct.pack("!BBBBII", version, packet_type, sequence, flags, 42, len(body)) + body


class ProtocolTests(unittest.TestCase):
    def test_parses_valid_frame(self):
        parsed = parse_frame(frame(body=b"abc"))
        self.assertEqual(parsed.header.session_id, 42)
        self.assertEqual(parsed.body, b"abc")

    def test_rejects_malformed_inputs(self):
        cases = [b"", frame(version=0xB0), frame(sequence=0), frame(flags=1)]
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(ProtocolError):
                    parse_frame(raw)

    def test_rejects_oversize_before_body_slice(self):
        raw = frame(body=b"ab")
        with self.assertRaises(ProtocolError):
            parse_frame(raw, Limits(max_packet_size=1))

    def test_encodes_even_server_response(self):
        raw=encode_frame(Header(0xC0,AUTHENTICATION,2,0,42,0),b"ok")
        self.assertEqual(parse_frame(raw).body,b"ok")
        with self.assertRaises(ProtocolError): encode_frame(Header(0xC0,AUTHENTICATION,1,0,42,0),b"")

    def test_fuzz_like_arbitrary_frames_never_escape_protocol_error(self):
        # Deterministic corpus is dependency-free and exercises arbitrary bytes.
        for length in range(0, 96):
            raw = bytes((index * 37 + length) % 256 for index in range(length))
            try:
                parse_frame(raw)
            except ProtocolError:
                pass
