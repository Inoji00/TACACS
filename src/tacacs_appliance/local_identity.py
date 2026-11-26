"""Local authentication provider using Argon2id password hashes."""

from __future__ import annotations
from dataclasses import dataclass
import threading
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from .password_timing import (
    DummyPasswordVerifier,
    bounded_password_work,
    acceptable_password_hash,
)


@dataclass(slots=True)
class LocalUser:
    username: str
    password_hash: str
    enabled: bool = True
    failed_logins: int = 0
    locked: bool = False


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    authenticated: bool
    subject: str | None = None
    reason: str = "invalid credentials"


class LocalProvider:
    """In-memory repository adapter; production will persist this model in PostgreSQL.

    The externally visible result deliberately does not distinguish unknown,
    disabled, locked, or wrong-password accounts.
    """

    def __init__(self, users: dict[str, LocalUser], lockout_after: int = 5) -> None:
        if lockout_after < 1:
            raise ValueError("lockout threshold must be positive")
        self._users, self._lockout_after = users, lockout_after
        self._hasher = PasswordHasher()
        self._dummy = DummyPasswordVerifier()
        self._lock = threading.Lock()

    @bounded_password_work
    def authenticate(self, username: str, password: str) -> AuthenticationResult:
        # Lock covers state inspection/update; password material is never stored.
        with self._lock:
            user = self._users.get(username)
            if user is None or not user.enabled or user.locked:
                self._dummy.verify(password)
                return AuthenticationResult(False)
            if not acceptable_password_hash(user.password_hash):
                self._dummy.verify(password)
                return AuthenticationResult(False)
            try:
                valid = self._hasher.verify(user.password_hash, password)
            except (VerifyMismatchError, InvalidHashError):
                valid = False
            if not valid:
                user.failed_logins += 1
                user.locked = user.failed_logins >= self._lockout_after
                return AuthenticationResult(False)
            user.failed_logins = 0
            if self._hasher.check_needs_rehash(user.password_hash):
                user.password_hash = self._hasher.hash(password)
            return AuthenticationResult(True, subject=user.username, reason="")
