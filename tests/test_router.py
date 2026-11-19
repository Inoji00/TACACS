import unittest
from unittest.mock import Mock

from tacacs_appliance.protocol import Frame, Header
from tacacs_appliance.router import TacacsRouter


class RouterTests(unittest.TestCase):
    def test_dispatch_and_reject_server_sequence(self):
        handlers = [Mock(return_value=b"auth"), Mock(return_value=b"author"), Mock(return_value=b"acct")]
        router = TacacsRouter(*handlers)
        for kind, expected in ((1,b"auth"),(2,b"author"),(3,b"acct")):
            self.assertEqual(router("d",Frame(Header(0xc0,kind,1,0,7,0),b"")),expected)
        self.assertIsNone(router("d",Frame(Header(0xc0,1,2,0,7,0),b"")))
        self.assertEqual(handlers[0].call_count,1)

    def test_connection_factory_creates_separate_authentication(self):
        authentication = Mock()
        authorization, accounting = Mock(), Mock()
        child = TacacsRouter(authentication,authorization,accounting).new_connection()
        authentication.new_connection.assert_called_once_with()
        self.assertIs(child._authentication,authentication.new_connection.return_value)
