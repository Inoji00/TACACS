"""TACACS+ Authentication packet bodies (RFC 8907 section 5).

Only decoded body bytes enter this module. It has no access to transport
secrets, databases, or authorization policy.
"""

from __future__ import annotations

from dataclasses import dataclass


class AuthenticationPacketError(ValueError):
    """Malformed decoded authentication body; safe to map to TACACS+ ERROR."""


@dataclass(frozen=True, slots=True)
class AuthenticationLimits:
    max_username_bytes: int = 253
    max_port_bytes: int = 253
    max_remote_address_bytes: int = 253
    max_data_bytes: int = 4096


@dataclass(frozen=True, slots=True)
class AuthenticationStart:
    action: int
    privilege_level: int
    authentication_type: int
    service: int
    username: str
    port: str
    remote_address: str
    data: bytes


@dataclass(frozen=True, slots=True)
class AuthenticationContinue:
    user_message: str
    user_data: bytes
    flags: int


@dataclass(frozen=True, slots=True)
class AuthenticationReply:
    """Protocol reply without credentials or internal diagnostic details."""

    status: int
    flags: int = 0
    server_message: str = ""
    data: bytes = b""


def parse_authentication_start(
    body: bytes, limits: AuthenticationLimits = AuthenticationLimits()
) -> AuthenticationStart:
    """Parse RFC 8907 Authentication START body without ambiguous truncation.

    Threat: attacker-controlled length octets can cause parser confusion or
    hidden suffixes. Invariant: all four fields are capped locally and their
    summed size must exactly equal the body size before decoding strings.
    """

    if len(body) < 8:
        raise AuthenticationPacketError("authentication start body too short")
    action, privilege, auth_type, service, user_len, port_len, remote_len, data_len = (
        body[:8]
    )
    _validate_lengths(user_len, port_len, remote_len, data_len, limits)
    expected = 8 + user_len + port_len + remote_len + data_len
    if len(body) != expected:
        raise AuthenticationPacketError("authentication start field lengths mismatch")

    offset = 8
    username = _decode_text(body[offset : offset + user_len], "username")
    offset += user_len
    port = _decode_text(body[offset : offset + port_len], "port")
    offset += port_len
    remote_address = _decode_text(body[offset : offset + remote_len], "remote address")
    offset += remote_len
    return AuthenticationStart(
        action=action,
        privilege_level=privilege,
        authentication_type=auth_type,
        service=service,
        username=username,
        port=port,
        remote_address=remote_address,
        data=bytes(body[offset:]),
    )


def parse_authentication_continue(
    body: bytes, limits: AuthenticationLimits = AuthenticationLimits()
) -> AuthenticationContinue:
    """Parse the 5-byte fixed Authentication CONTINUE header plus exact fields."""
    if len(body) < 5:
        raise AuthenticationPacketError("authentication continue body too short")
    message_len = int.from_bytes(body[0:2], "big")
    data_len = int.from_bytes(body[2:4], "big")
    flags = body[4]
    if message_len > limits.max_data_bytes or data_len > limits.max_data_bytes:
        raise AuthenticationPacketError(
            "authentication continue field exceeds configured maximum"
        )
    if len(body) != 5 + message_len + data_len:
        raise AuthenticationPacketError(
            "authentication continue field lengths mismatch"
        )
    message = _decode_text(body[5 : 5 + message_len], "user message")
    return AuthenticationContinue(message, bytes(body[5 + message_len :]), flags)


def encode_authentication_reply(
    reply: AuthenticationReply, limits: AuthenticationLimits = AuthenticationLimits()
) -> bytes:
    """Encode an RFC 8907 Authentication REPLY with bounded public text."""
    message = reply.server_message.encode("utf-8")
    if len(message) > limits.max_data_bytes or len(reply.data) > limits.max_data_bytes:
        raise AuthenticationPacketError(
            "authentication reply field exceeds configured maximum"
        )
    return (
        bytes((reply.status, reply.flags))
        + len(message).to_bytes(2, "big")
        + len(reply.data).to_bytes(2, "big")
        + message
        + reply.data
    )


def _validate_lengths(
    user: int, port: int, remote: int, data: int, limits: AuthenticationLimits
) -> None:
    if user > limits.max_username_bytes:
        raise AuthenticationPacketError("username exceeds configured maximum")
    if port > limits.max_port_bytes:
        raise AuthenticationPacketError("port exceeds configured maximum")
    if remote > limits.max_remote_address_bytes:
        raise AuthenticationPacketError("remote address exceeds configured maximum")
    if data > limits.max_data_bytes:
        raise AuthenticationPacketError(
            "authentication data exceeds configured maximum"
        )


def _decode_text(raw: bytes, field: str) -> str:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthenticationPacketError(f"invalid {field} encoding") from exc
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise AuthenticationPacketError(f"invalid control character in {field}")
    return value
