import unittest

from tacacs_appliance.accounting_packet import (
    AccountingPacketError, encode_accounting_reply, parse_accounting_request,
)


class AccountingPacketTests(unittest.TestCase):
    def test_start_fields_and_reply_layout(self):
        body = bytes((2, 6, 15, 1, 1, 1, 0, 0, 1, 3)) + b"u" + b"x=y"
        parsed = parse_accounting_request(body)
        self.assertEqual(parsed.fields.username, "u")
        self.assertEqual(parsed.fields.arguments, ("x=y",))
        self.assertEqual(encode_accounting_reply(1, "ok"), b"\x00\x02\x00\x00\x01ok")

    def test_rejects_conflicting_flags_and_length_mismatch(self):
        for body in (bytes((6,)) + bytes(8), bytes((2,)) + bytes(8) + b"suffix"):
            with self.subTest(body=body), self.assertRaises(AccountingPacketError):
                parse_accounting_request(body)
