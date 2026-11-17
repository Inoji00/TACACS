"""Device shared-secret boundary.

Secrets are deliberately resolved by source identity and never represented in
logs, exceptions, configuration values, or HTTP-facing types.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping


class SecretNotFoundError(LookupError):
    """Raised without exposing whether other device secrets exist."""


class DeviceSecretProvider(ABC):
    """Resolves the dedicated RFC 8907 secret for an allow-listed device."""

    @abstractmethod
    def resolve(self, device_identity: str) -> bytes:
        """Return the secret or raise SecretNotFoundError; never log the value."""


class StaticDeviceSecretProvider(DeviceSecretProvider):
    """Evaluation-only in-memory provider.

    Production composition will use a reference-backed KeyProvider. This class
    is not a configuration format and rejects weak or shared device secrets.
    """

    def __init__(self, secrets: Mapping[str, bytes]) -> None:
        if not secrets:
            raise ValueError("at least one device secret is required")
        values = list(secrets.values())
        if len(set(values)) != len(values):
            raise ValueError("each device must have a unique shared secret")
        for secret in values:
            if len(secret) < 14:
                raise ValueError("device secret must be at least 14 bytes")
        self._secrets = dict(secrets)

    def resolve(self, device_identity: str) -> bytes:
        try:
            return self._secrets[device_identity]
        except KeyError as exc:
            raise SecretNotFoundError("device secret unavailable") from exc
