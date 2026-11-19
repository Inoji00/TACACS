import unittest
from tacacs_appliance.authorization import AuthorizationEngine, AuthorizationRequest, PolicyRule, Decision
from tacacs_appliance.authorization_packet import encode_authorization_reply, AuthorizationPacketError

class AuthorizationSecurityTests(unittest.TestCase):
    def test_command_boundaries_and_injection(self):
        engine = AuthorizationEngine("v1", (PolicyRule("r", frozenset(), frozenset(), "show", Decision.ALLOW),))
        for command in ("showevil", "show\nreload", "show $(reload)", "   "):
            with self.subTest(command=command):
                self.assertEqual(engine.evaluate(AuthorizationRequest("u", "d", command)).decision, Decision.DENY)
        self.assertEqual(engine.evaluate(AuthorizationRequest("u", "d", "show version")).decision, Decision.ALLOW)

    def test_reply_wire_layout(self):
        self.assertEqual(encode_authorization_reply(1, ("priv-lvl=15",)), b"\x01\x01\x00\x00\x00\x00\x0bpriv-lvl=15")
        with self.assertRaises(AuthorizationPacketError):
            encode_authorization_reply(1, ("a" * 256,))
