import os
import unittest

from tacacs_appliance.protocol import Limits, ProtocolError, parse_frame


class ProtocolFuzzRegressionTests(unittest.TestCase):
    def test_ten_thousand_arbitrary_frames_do_not_crash(self):
        # Availability invariant: untrusted TCP bytes yield only a valid frame
        # or ProtocolError; no exception type may escape the parser.
        for length in range(10_000):
            raw = os.urandom(length % 257)
            try:
                parse_frame(raw, Limits(max_packet_size=1024))
            except ProtocolError:
                pass
