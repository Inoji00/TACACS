"""Dummy Argon2 work for unavailable identities; not constant-time proof."""

import secrets
import threading
from functools import wraps
from argon2 import PasswordHasher, extract_parameters
from argon2.low_level import Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Shared by password operations within each process.
PASSWORD_WORK_SLOTS = threading.BoundedSemaphore(4)
PASSWORD_WORK_WAIT_SECONDS = 1.5


class PasswordWorkUnavailable(RuntimeError):
    """No password-work slot became available before the deadline."""


def acceptable_password_hash(encoded: str) -> bool:
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 1024:
        return False
    try:
        parameters = extract_parameters(encoded)
    except (ValueError, TypeError, InvalidHashError):
        return False
    return (
        parameters.type is Type.ID
        and parameters.version == 19
        and 19456 <= parameters.memory_cost <= 131072
        and 1 <= parameters.time_cost <= 6
        and 1 <= parameters.parallelism <= 8
        and 16 <= parameters.salt_len <= 64
        and 16 <= parameters.hash_len <= 64
    )


def bounded_password_work(method):
    @wraps(method)
    def authenticate(*args, **kwargs):
        if not PASSWORD_WORK_SLOTS.acquire(timeout=PASSWORD_WORK_WAIT_SECONDS):
            raise PasswordWorkUnavailable("password service temporarily unavailable")
        try:
            return method(*args, **kwargs)
        finally:
            PASSWORD_WORK_SLOTS.release()

    return authenticate


class DummyPasswordVerifier:
    def __init__(self):
        self._hasher = PasswordHasher()
        self._hash = self._hasher.hash(secrets.token_urlsafe(32))

    def verify(self, password: str) -> None:
        try:
            self._hasher.verify(self._hash, password)
        except (VerifyMismatchError, InvalidHashError):
            pass
