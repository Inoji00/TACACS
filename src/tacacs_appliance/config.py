"""Validated runtime settings; secrets are references, never values."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    dsn_reference: str

    def __post_init__(self):
        if not self.dsn_reference.startswith("secret://"):
            raise ValueError("database DSN must be a secret reference")
