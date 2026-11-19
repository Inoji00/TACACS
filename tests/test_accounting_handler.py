import unittest
from tacacs_appliance.accounting_handler import TacacsAccountingHandler
from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.protocol import Header, Frame, parse_frame
from tacacs_appliance.secrets import StaticDeviceSecretProvider


class Store:
    def __init__(self, fail=False): self.records = []; self.fail = fail
    def append(self, record):
        if self.fail: raise OSError("storage unavailable")
        self.records.append(record)


class AccountingHandlerTests(unittest.TestCase):
    def test_success_only_after_store_commit(self):
        secret = b"s" * 32
        for fail, expected in ((False, 1), (True, 2)):
            with self.subTest(fail=fail):
                store = Store(fail)
                handler = TacacsAccountingHandler(StaticDeviceSecretProvider({"127.0.0.1": secret}), store, "tenant")
                argument = b"password=x"
                body = bytes((2,6,15,1,1,1,0,0,1,len(argument))) + b"u" + argument
                request = Frame(Header(0xc0,3,1,0,7,len(body)),body)
                reply = parse_frame(handler("127.0.0.1",Frame(request.header,xor_body(request,secret))))
                self.assertEqual(xor_body(reply,secret)[4], expected)
                if not fail: self.assertEqual(store.records[0].arguments, ("<redacted>",))
