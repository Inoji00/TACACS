"""Safe AAA outcomes: stdout JSON plus durable tenant audit summaries."""

from datetime import datetime, timezone, timedelta
import json
import threading
import re
from uuid import UUID
from .protocol import parse_frame
from .obfuscation import xor_body
from .postgres_audit import PostgresAuditWriter
from .web_audit_network import audit_ip

_lock = threading.Lock()
VIETNAM_TIMEZONE = timezone(timedelta(hours=7), "Asia/Ho_Chi_Minh")


def safe_attempted_username(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or any(
            not c.isprintable()
            or c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
            for c in value
        )
    ):
        return None
    return value


AUTHORIZATION_REASONS = frozenset(
    {
        "exec-granted",
        "exec-not-granted",
        "matched-rule",
        "no-matching-rule",
        "invalid-command",
        "identity-unavailable",
        "device-access-denied",
        "unsupported-profile",
        "invalid-request",
        "authorization-error",
    }
)


def safe_authorization_details(value):
    if not isinstance(value, dict):
        return {}
    details = {}
    kind = value.get("authorization_kind")
    if kind in ("exec", "command"):
        details["authorization_kind"] = kind
    reason = value.get("reason")
    if isinstance(reason, str) and reason in AUTHORIZATION_REASONS:
        details["reason"] = reason
    rule = value.get("matched_rule_id")
    if isinstance(rule, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", rule):
        details["matched_rule_id"] = rule
    return details


class AaaEvents:
    def __init__(self, pool, tenant):
        self.audit = PostgresAuditWriter(pool, tenant)

    def emit(
        self,
        device,
        session,
        category,
        result,
        *,
        attempted_username=None,
        remote_address=None,
        command_authorization=False,
        authorization_details=None,
    ):
        # Keep only bounded, allowlisted metadata.
        event = dict(
            timestamp=datetime.now(VIETNAM_TIMEZONE).isoformat(),
            source="tacacs",
            device=device,
            session=str(session),
            action="aaa." + category,
            result=result,
        )
        details = (
            authorization_details
            if category == "authorization" and isinstance(authorization_details, dict)
            else {}
        )
        username = (
            safe_attempted_username(
                details.get("attempted_username", attempted_username)
            )
            if category in ("authentication", "authorization")
            else None
        )
        policy = {}
        if isinstance(details.get("policy_version"), str):
            try:
                policy["policy_version"] = str(UUID(details["policy_version"]))
            except ValueError:
                pass
        if username is not None:
            event["attempted_username"] = username
        context = safe_authorization_details(details)
        if username is not None:
            context["attempted_username"] = username
        if category in ("authentication", "authorization"):
            address = audit_ip(details.get("remote_address", remote_address))
            if address is not None:
                context["remote_address"] = event["remote_address"] = address
        if command_authorization:
            context["authorization_kind"] = "command"
        try:
            digest = self.audit.append(
                actor="device",
                source="tacacs",
                action=event["action"],
                target=device,
                result=result,
                session_id=str(session),
                **policy,
                **({"security_context": context} if context else {}),
            )
            event.update(persisted=True, event_hash=digest)
        except Exception:
            event.update(persisted=False)
        with _lock:
            print(json.dumps(event, separators=(",", ":")), flush=True)


class ObservedRouter:
    def __init__(self, router, secrets, events):
        self.router, self.secrets, self.events = router, secrets, events

    def new_connection(self):
        return ObservedRouter(self.router.new_connection(), self.secrets, self.events)

    def _emit(self, device, frame, category, result):
        details = {}
        if category == "authentication":
            try:
                username = getattr(
                    self.router, "authentication_username", lambda: None
                )()
                if safe_attempted_username(username) is not None:
                    details["attempted_username"] = username
                address = audit_ip(
                    getattr(
                        self.router, "authentication_remote_address", lambda: None
                    )()
                )
                if address is not None:
                    details["remote_address"] = address
            except Exception:
                pass
        if category == "authorization":
            metadata = getattr(self.router, "authorization_details", None)
            if isinstance(metadata, dict):
                details["authorization_details"] = metadata
        self.events.emit(device, frame.header.session_id, category, result, **details)

    def __call__(self, device, frame):
        category = {1: "authentication", 2: "authorization", 3: "accounting"}.get(
            frame.header.packet_type, "protocol"
        )
        try:
            response = self.router(device, frame)
        except Exception:
            self._emit(device, frame, category, "error")
            raise
        result = "no-reply"
        if response is not None:
            try:
                reply = parse_frame(response)
                clear = xor_body(reply, self.secrets.resolve(device))
                # Authentication/authorization put status first; accounting last.
                status = clear[4] if category == "accounting" else clear[0]
                result = {
                    "authentication": {
                        1: "pass",
                        2: "fail",
                        3: "challenge",
                        4: "challenge",
                        5: "challenge",
                        6: "restart",
                        7: "error",
                    },
                    "authorization": {1: "allow", 2: "allow", 16: "deny", 17: "error"},
                    "accounting": {1: "committed", 2: "error"},
                }.get(category, {}).get(status, "unknown")
            except Exception:
                result = "unclassified"
        self._emit(device, frame, category, result)
        return response
