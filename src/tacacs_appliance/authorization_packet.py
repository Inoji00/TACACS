"""Hostile-input parser for TACACS+ Authorization REQUEST bodies."""

from __future__ import annotations
from dataclasses import dataclass


class AuthorizationPacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AuthorizationPacketLimits:
    max_attributes: int = 64
    max_attribute_bytes: int = 1024
    max_text_bytes: int = 253


@dataclass(frozen=True, slots=True)
class AuthorizationRequestBody:
    authentication_method: int
    privilege_level: int
    authentication_type: int
    service: int
    username: str
    port: str
    remote_address: str
    arguments: tuple[str, ...]


def parse_authorization_request(
    body: bytes, limits: AuthorizationPacketLimits = AuthorizationPacketLimits()
) -> AuthorizationRequestBody:
    """Validate all byte lengths before slicing or policy evaluation."""
    if len(body) < 8:
        raise AuthorizationPacketError("authorization request too short")
    method, privilege, auth_type, service, user_len, port_len, remote_len, arg_count = (
        body[:8]
    )
    if arg_count > limits.max_attributes:
        raise AuthorizationPacketError("too many authorization attributes")
    fixed = 8 + arg_count
    if len(body) < fixed:
        raise AuthorizationPacketError("authorization argument lengths truncated")
    lengths = body[8:fixed]
    if any(length > limits.max_attribute_bytes for length in lengths):
        raise AuthorizationPacketError("authorization attribute too large")
    expected = fixed + user_len + port_len + remote_len + sum(lengths)
    if len(body) != expected:
        raise AuthorizationPacketError("authorization field lengths mismatch")
    if any(value > limits.max_text_bytes for value in (user_len, port_len, remote_len)):
        raise AuthorizationPacketError("authorization text field too large")
    offset = fixed
    username = _text(body[offset : offset + user_len])
    offset += user_len
    port = _text(body[offset : offset + port_len])
    offset += port_len
    remote = _text(body[offset : offset + remote_len])
    offset += remote_len
    arguments = []
    for length in lengths:
        arguments.append(_text(body[offset : offset + length]))
        offset += length
    return AuthorizationRequestBody(
        method, privilege, auth_type, service, username, port, remote, tuple(arguments)
    )


def _text(raw: bytes) -> str:
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AuthorizationPacketError("invalid authorization text") from exc
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise AuthorizationPacketError("invalid authorization control character")
    return value


def encode_authorization_reply(
    status: int, arguments: tuple[str, ...] = (), message: str = "", data: bytes = b""
) -> bytes:
    """RFC 8907 REPLY: status/count, 16-bit lengths, argument lengths and values.

    Validate local output so truncation cannot change the granted attributes.
    """
    if status not in (1, 2, 0x10, 0x11):
        raise AuthorizationPacketError("invalid reply status")
    if len(arguments) > 64:
        raise AuthorizationPacketError("too many reply arguments")
    encoded = tuple(arg.encode("ascii") for arg in arguments)
    if any(len(arg) > 255 for arg in encoded):
        raise AuthorizationPacketError("reply argument too long")
    msg = message.encode("ascii")
    if len(msg) > 4096 or len(data) > 4096:
        raise AuthorizationPacketError("reply field too long")
    return (
        bytes((status, len(encoded)))
        + len(msg).to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
        + bytes(map(len, encoded))
        + msg
        + data
        + b"".join(encoded)
    )
