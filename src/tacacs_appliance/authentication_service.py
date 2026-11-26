"""Stateful TACACS+ ASCII authentication flow over parsed protocol bodies."""

from __future__ import annotations
from dataclasses import dataclass
from .authentication import (
    AuthenticationContinue,
    AuthenticationReply,
    AuthenticationStart,
)
from .local_identity import AuthenticationResult
from .password_timing import PasswordWorkUnavailable
from typing import Protocol


class AuthenticationProvider(Protocol):
    def authenticate(self, username: str, password: str) -> AuthenticationResult: ...


AUTHEN_ACTION_LOGIN = 0x01
AUTHEN_TYPE_ASCII = 0x01
STATUS_PASS = 0x01
STATUS_FAIL = 0x02
STATUS_GETUSER = 0x04
STATUS_GETPASS = 0x05
STATUS_ERROR = 0x07


@dataclass(frozen=True, slots=True)
class PendingPasswordChallenge:
    username: str


@dataclass(frozen=True, slots=True)
class PendingUsernameChallenge:
    pass


class AuthenticationService:
    """Only supports the explicitly configured ASCII login flow in this slice.

    Unimplemented types fail closed. No caller receives detailed identity errors.
    """

    def __init__(self, local_provider: AuthenticationProvider) -> None:
        self._local_provider = local_provider

    def begin(
        self, request: AuthenticationStart
    ) -> tuple[
        AuthenticationReply, PendingPasswordChallenge | PendingUsernameChallenge | None
    ]:
        if (
            request.action != AUTHEN_ACTION_LOGIN
            or request.authentication_type != AUTHEN_TYPE_ASCII
        ):
            return AuthenticationReply(
                status=STATUS_ERROR, server_message="authentication method unavailable"
            ), None
        if not request.username:
            return AuthenticationReply(
                status=STATUS_GETUSER, server_message="Username: "
            ), PendingUsernameChallenge()
        return self._prompt_password(request.username)

    def continue_username(
        self, request: AuthenticationContinue
    ) -> tuple[AuthenticationReply, PendingPasswordChallenge | None]:
        username = request.user_message
        if request.flags or not username or len(username.encode("utf-8")) > 253:
            return AuthenticationReply(
                status=STATUS_FAIL, server_message="authentication failed"
            ), None
        return self._prompt_password(username)

    @staticmethod
    def _prompt_password(
        username: str,
    ) -> tuple[AuthenticationReply, PendingPasswordChallenge]:
        return AuthenticationReply(
            status=STATUS_GETPASS, flags=1, server_message="Password: "
        ), PendingPasswordChallenge(username)

    def continue_password(
        self, pending: PendingPasswordChallenge, request: AuthenticationContinue
    ) -> AuthenticationReply:
        # user_message can contain a password; never include it in result/log/audit.
        if request.flags != 0:
            # ABORT (bit 0) ends the exchange; unknown flags fail closed too.
            return AuthenticationReply(
                status=STATUS_FAIL, server_message="authentication failed"
            )
        try:
            result = self._local_provider.authenticate(
                pending.username, request.user_message
            )
        except PasswordWorkUnavailable:
            return AuthenticationReply(
                status=STATUS_ERROR, server_message="authentication service unavailable"
            )
        if result.authenticated:
            return AuthenticationReply(status=STATUS_PASS)
        return AuthenticationReply(
            status=STATUS_FAIL, server_message="authentication failed"
        )
