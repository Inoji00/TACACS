"""RFC 8907 accounting codec, independent of persistence and audit."""
from dataclasses import dataclass

from .authorization_packet import (
    AuthorizationPacketLimits,
    AuthorizationRequestBody,
    parse_authorization_request,
)


class AccountingPacketError(ValueError):
    """Invalid accounting input or output."""


@dataclass(frozen=True, slots=True)
class AccountingRequestBody:
    flags: int
    fields: AuthorizationRequestBody


def parse_accounting_request(
    body: bytes, limits: AuthorizationPacketLimits = AuthorizationPacketLimits()
) -> AccountingRequestBody:
    """Accounting adds a flags octet before the common AAA request fields.

    START, STOP and WATCHDOG are mutually exclusive record types. MORE is an
    optional modifier. Refuse ambiguous combinations before storing records.
    """
    if len(body) < 9:
        raise AccountingPacketError("accounting body too short")
    flags = body[0]
    record_type = flags & 0x0E
    if flags & ~0x0F or record_type not in (0x02, 0x04, 0x08):
        raise AccountingPacketError("invalid accounting flags")
    try:
        fields = parse_authorization_request(body[1:], limits)
    except ValueError as exc:
        raise AccountingPacketError("invalid accounting fields") from exc
    return AccountingRequestBody(flags, fields)


def encode_accounting_reply(status: int, message: str = "", data: bytes = b"") -> bytes:
    """Encode message length, data length, status, then message and data."""
    if status not in (1, 2):
        raise AccountingPacketError("invalid accounting reply status")
    encoded = message.encode("ascii")
    if len(encoded) > 4096 or len(data) > 4096:
        raise AccountingPacketError("accounting reply too large")
    return len(encoded).to_bytes(2, "big") + len(data).to_bytes(2, "big") + bytes((status,)) + encoded + data
