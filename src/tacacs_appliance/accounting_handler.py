"""Accounting acknowledges only after the configured store commits."""
from typing import Protocol

from .accounting import AccountingRecord, redact_arguments
from .accounting_packet import parse_accounting_request, encode_accounting_reply
from .obfuscation import xor_body
from .protocol import ACCOUNTING, Frame, Header, encode_frame
from .secrets import DeviceSecretProvider


class AccountingStore(Protocol):
    def append(self, record: AccountingRecord) -> None:
        """Commit or raise; implementers must not acknowledge buffered-only data."""


class TacacsAccountingHandler:
    def __init__(self, secrets: DeviceSecretProvider, store: AccountingStore, tenant_id: str):
        self._secrets, self._store, self._tenant = secrets, store, tenant_id

    def __call__(self, remote_ip: str, frame: Frame) -> bytes | None:
        if frame.header.packet_type != ACCOUNTING or frame.header.sequence != 1:
            return None
        secret = self._secrets.resolve(remote_ip)
        status = 2
        try:
            request = parse_accounting_request(xor_body(frame, secret))
            action = {2: "start", 4: "stop", 8: "watchdog"}[request.flags & 14]
            record = AccountingRecord(self._tenant, str(frame.header.session_id), request.fields.username,
                                      remote_ip, action, redact_arguments(request.fields.arguments))
            self._store.append(record)
            status = 1
        except Exception:
            # The wire error contains no database diagnostic or sensitive input.
            status = 2
        body = encode_accounting_reply(status)
        response = Frame(Header(frame.header.version, ACCOUNTING, 2, 0, frame.header.session_id, len(body)), body)
        return encode_frame(response.header, xor_body(response, secret))
