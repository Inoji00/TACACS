import unittest
from tacacs_appliance.authorization import AuthorizationEngine, PolicyRule, Decision
from tacacs_appliance.authorization_handler import TacacsAuthorizationHandler, extract_command
from tacacs_appliance.protocol import Header, Frame, parse_frame, encode_frame
from tacacs_appliance.obfuscation import xor_body
from tacacs_appliance.secrets import StaticDeviceSecretProvider

class AuthorizationHandlerTests(unittest.TestCase):
    def test_obfuscated_allow_deny_and_untrusted_groups(self):
        secret = b"q" * 32
        engine = AuthorizationEngine("v1", (PolicyRule("r", frozenset({"ops"}), frozenset({"127.0.0.1"}), "show", Decision.ALLOW),))
        handler = TacacsAuthorizationHandler(StaticDeviceSecretProvider({"127.0.0.1": secret}), engine, lambda u: frozenset({"ops"}) if u == "u" else None)
        for cmd, expected, reason, rule in ((b"show", 1, "matched-rule", "r"), (b"reload", 0x10, "no-matching-rule", None)):
            args = (b"service=shell", b"cmd=" + cmd, b"cmd-arg=version")
            address = b"192.0.2.27"
            body = bytes((6,15,1,1,1,0,len(address),3)) + bytes(map(len,args)) + b"u" + address + b"".join(args)
            request = Frame(Header(0xc0,2,1,0,9,len(body)),body)
            encoded = Frame(request.header,xor_body(request,secret))
            observed = []
            reply = parse_frame(handler.handle("127.0.0.1",encoded,observed.append))
            self.assertEqual(handler("127.0.0.1",encoded), encode_frame(reply.header,reply.body))
            self.assertEqual(observed,[dict(attempted_username="u",authorization_kind="command",
                remote_address="192.0.2.27",reason=reason,policy_version="v1",matched_rule_id=rule)])
            self.assertEqual(xor_body(reply,secret)[0], expected)
        with self.assertRaises(ValueError):
            extract_command(("service=shell", "cmd=show", "groups=ops"))
