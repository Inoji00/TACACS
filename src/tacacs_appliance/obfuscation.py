"""RFC 8907 section 4.5 TACACS+ body obfuscation.

MD5 is used only because the wire protocol mandates its pad construction. This
is not encryption and must never be reused as a general cryptographic primitive.
"""

from __future__ import annotations

import hashlib
import struct

from .protocol import Frame, UNENCRYPTED_FLAG


def xor_body(frame: Frame, secret: bytes) -> bytes:
    """Obfuscate or de-obfuscate a body (XOR is symmetric).

    Invariant: callers must have already authenticated the source device via
    network ACL and resolved its dedicated secret. The cleartext flag is always
    rejected so it cannot downgrade a production connection.
    """

    if frame.header.flags & UNENCRYPTED_FLAG:
        raise ValueError("unencrypted TACACS+ body is disabled")
    if len(secret) < 14:
        raise ValueError("device secret must be at least 14 bytes")
    pad = _pseudo_pad(
        session_id=frame.header.session_id,
        secret=secret,
        version=frame.header.version,
        sequence=frame.header.sequence,
        length=len(frame.body),
    )
    return bytes(value ^ mask for value, mask in zip(frame.body, pad, strict=True))


def _pseudo_pad(*, session_id: int, secret: bytes, version: int, sequence: int, length: int) -> bytes:
    """Create MD5_1 || MD5_2 ... as specified by RFC 8907 section 4.5."""

    seed = struct.pack("!I", session_id) + secret + bytes((version, sequence))
    pad = bytearray()
    previous = b""
    while len(pad) < length:
        previous = hashlib.md5(seed + previous, usedforsecurity=False).digest()
        pad.extend(previous)
    return bytes(pad[:length])
