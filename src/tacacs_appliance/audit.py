"""Canonical, per-tenant tamper-evident audit event chain."""

from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import threading


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    tenant_id: str
    timestamp: str
    actor: str
    source: str
    action: str
    target: str
    result: str
    policy_version: str | None
    session_id: str | None
    correlation_id: str
    security_context: dict[str, str]
    previous_hash: str
    event_hash: str


class AuditWriter:
    """In-memory adapter; PostgreSQL will serialize per-tenant append operations."""

    def __init__(self):
        self._events: dict[str, list[AuditEvent]] = {}
        self._lock = threading.Lock()

    def append(
        self,
        *,
        event_id: str,
        tenant_id: str,
        actor: str,
        source: str,
        action: str,
        target: str,
        result: str,
        policy_version: str | None = None,
        session_id: str | None = None,
        correlation_id: str = "",
        security_context: dict[str, str] | None = None,
    ) -> AuditEvent:
        with self._lock:
            prior = self._events.get(tenant_id, [])
            previous = prior[-1].event_hash if prior else "0" * 64
            base = {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "source": source,
                "action": action,
                "target": target,
                "result": result,
                "policy_version": policy_version,
                "session_id": session_id,
                "correlation_id": correlation_id,
                "security_context": security_context or {},
                "previous_hash": previous,
            }
            digest = hashlib.sha256(_canonical(base).encode()).hexdigest()
            event = AuditEvent(**base, event_hash=digest)
            self._events.setdefault(tenant_id, []).append(event)
            return event

    def verify(self, tenant_id: str) -> bool:
        previous = "0" * 64
        for event in self._events.get(tenant_id, []):
            base = asdict(event)
            claimed = base.pop("event_hash")
            if (
                event.previous_hash != previous
                or hashlib.sha256(_canonical(base).encode()).hexdigest() != claimed
            ):
                return False
            previous = claimed
        return True


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
