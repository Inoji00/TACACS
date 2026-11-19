import io
import unittest
from http.client import LineTooLong,HTTPException
from tacacs_appliance.admin_server import BoundedHeaderReader


class HeaderBoundsTests(unittest.TestCase):
    def test_eof_and_partial_or_lf_only_headers_are_rejected(self):
        for body in (b'',b'Host: localhost',b'Host: localhost\n'):
            with self.assertRaises(HTTPException):BoundedHeaderReader(io.BytesIO(body)).readline()
    def test_single_line_read_does_not_allocate_unbounded_header(self):
        source=io.BytesIO(b'X: '+b'x'*100000+b'\r\n')
        with self.assertRaises(LineTooLong):BoundedHeaderReader(source).readline(65537)
        self.assertEqual(source.tell(),8193)

    def test_total_read_budget_limits_many_lines(self):
        source=io.BytesIO((b'X: '+b'x'*4090+b'\r\n')*10)
        reader=BoundedHeaderReader(source)
        with self.assertRaises(LineTooLong):
            for _ in range(10):reader.readline()
        self.assertEqual(source.tell(),32769)

    def test_body_remains_in_original_stream_after_headers(self):
        source=io.BytesIO(b'Host: localhost\r\n\r\nbody')
        reader=BoundedHeaderReader(source)
        self.assertEqual(reader.readline(),b'Host: localhost\r\n')
        self.assertEqual(reader.readline(),b'\r\n')
        self.assertEqual(source.read(),b'body')
