import unittest
from unittest.mock import Mock
from argon2 import PasswordHasher
from tacacs_appliance.authentication import AuthenticationContinue, AuthenticationStart
from tacacs_appliance.authentication_service import AuthenticationService, STATUS_ERROR, STATUS_FAIL, STATUS_GETPASS, STATUS_PASS
from tacacs_appliance.local_identity import LocalProvider, LocalUser
from tacacs_appliance.password_timing import PasswordWorkUnavailable

class AuthenticationServiceTests(unittest.TestCase):
    def setUp(self):
        self.service = AuthenticationService(LocalProvider({"alice": LocalUser("alice", PasswordHasher().hash("good-password"))}))
    def _start(self, username="alice", auth_type=1):
        return AuthenticationStart(1, 15, auth_type, 1, username, "vty0", "10.0.0.1", b"")
    def test_ascii_password_flow(self):
        reply, pending = self.service.begin(self._start())
        self.assertEqual(reply.status, STATUS_GETPASS); self.assertIsNotNone(pending)
        self.assertEqual(reply.flags, 1, "password prompt must request NOECHO")
        self.assertEqual(self.service.continue_password(pending, AuthenticationContinue("good-password", b"", 0)).status, STATUS_PASS)
    def test_invalid_method_and_password_fail_closed(self):
        self.assertEqual(self.service.begin(self._start(auth_type=3))[0].status, STATUS_ERROR)
        _, pending = self.service.begin(self._start())
        self.assertEqual(self.service.continue_password(pending, AuthenticationContinue("bad", b"", 0)).status, STATUS_FAIL)

    def test_abort_with_correct_password_does_not_authenticate(self):
        _, pending = self.service.begin(self._start())
        for flags in (1, 2, 255):
            with self.subTest(flags=flags):
                self.assertEqual(self.service.continue_password(pending, AuthenticationContinue("good-password", b"", flags)).status, STATUS_FAIL)


    def test_password_work_timeout_returns_service_error(self):
        provider = Mock()
        provider.authenticate.side_effect = PasswordWorkUnavailable
        service = AuthenticationService(provider)
        _, pending = service.begin(self._start())
        reply = service.continue_password(pending, AuthenticationContinue("password", b"", 0))
        self.assertEqual(reply.status, STATUS_ERROR)
