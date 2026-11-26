"""Hostile-input TACACS+ RFC 8907 frame parsing.

This module has no database, identity, policy, or network-listener dependency.
It validates the fixed header before a caller may allocate a peer-sized body.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

HEADER_LENGTH = 12
MAJOR_VERSION = 0x0C
AUTHENTICATION = 0x01
AUTHORIZATION = 0x02
ACCOUNTING = 0x03
UNENCRYPTED_FLAG = 0x01


class ProtocolError(ValueError):
    """A public, non-sensitive error for an invalid protocol frame."""


@dataclass(frozen=True, slots=True)
class Limits:
    """Local caps; a remote TACACS+ peer cannot select these values."""

    max_packet_size: int = 1 << 16
    allow_unencrypted_body: bool = False


@dataclass(frozen=True, slots=True)
class Header:
    version: int
    packet_type: int
    sequence: int
    flags: int
    session_id: int
    length: int

    @classmethod
    def parse(cls, raw: bytes, limits: Limits) -> "Header":
        if len(raw) != HEADER_LENGTH:
            raise ProtocolError("invalid TACACS+ header length")
        version, packet_type, sequence, flags, session_id, length = struct.unpack(
            "!BBBBII", raw
        )
        header = cls(version, packet_type, sequence, flags, session_id, length)
        header.validate(limits)
        return header

    def validate(self, limits: Limits) -> None:
        # Invariant: validate before any body allocation/slice based on length.
        if limits.max_packet_size <= 0 or self.length > limits.max_packet_size:
            raise ProtocolError("TACACS+ packet exceeds configured maximum")
        if self.version >> 4 != MAJOR_VERSION:
            raise ProtocolError("unsupported TACACS+ major version")
        if self.packet_type not in (AUTHENTICATION, AUTHORIZATION, ACCOUNTING):
            raise ProtocolError("unsupported TACACS+ packet type")
        if self.sequence == 0:
            raise ProtocolError("invalid TACACS+ sequence number")
        if self.flags & UNENCRYPTED_FLAG and not limits.allow_unencrypted_body:
            raise ProtocolError("unencrypted TACACS+ body is disabled")


@dataclass(frozen=True, slots=True)
class Frame:
    header: Header
    body: bytes


def parse_frame(raw: bytes, limits: Limits = Limits()) -> Frame:
    """Parse one exact frame without decoding its shared-secret body.

    Shared-secret decoding belongs after device identification through a secret
    provider. This prevents the parser from depending on credential storage.
    """

    if len(raw) < HEADER_LENGTH:
        raise ProtocolError("TACACS+ frame shorter than header")
    header = Header.parse(raw[:HEADER_LENGTH], limits)
    if len(raw) != HEADER_LENGTH + header.length:
        raise ProtocolError("TACACS+ frame length mismatch")
    return Frame(header=header, body=bytes(raw[HEADER_LENGTH:]))


def encode_frame(header: Header, body: bytes, limits: Limits = Limits()) -> bytes:
    """Encode a response only after local code has selected a valid header.

    The caller must set an even server sequence number; this boundary prevents
    accidental length/header disagreement in network replies.
    """
    response = Header(
        header.version,
        header.packet_type,
        header.sequence,
        header.flags,
        header.session_id,
        len(body),
    )
    response.validate(limits)
    if response.sequence % 2:
        raise ProtocolError("server TACACS+ response sequence must be even")
    return (
        bytes(
            (response.version, response.packet_type, response.sequence, response.flags)
        )
        + response.session_id.to_bytes(4, "big")
        + response.length.to_bytes(4, "big")
        + body
    )
