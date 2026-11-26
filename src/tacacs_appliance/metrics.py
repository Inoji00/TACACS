"""Low-cardinality Prometheus metrics; never attach user/command/secret labels."""

from collections import Counter
import threading


class Metrics:
    def __init__(self):
        self._values = Counter()
        self._lock = threading.Lock()

    def increment(self, name: str):
        if name not in {
            "tacacs_requests_total",
            "tacacs_authentication_success_total",
            "tacacs_authentication_failure_total",
            "tacacs_authorization_allow_total",
            "tacacs_authorization_deny_total",
            "audit_events_total",
            "tls_handshake_failures_total",
        }:
            raise ValueError("metric not allowlisted")
        with self._lock:
            self._values[name] += 1

    def prometheus(self) -> str:
        with self._lock:
            snapshot = sorted(self._values.items())
        return "".join(
            f"# TYPE {name} counter\n{name} {value}\n" for name, value in snapshot
        )
