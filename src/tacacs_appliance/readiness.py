"""Readiness aggregation for required security dependencies."""

from collections.abc import Callable


class ReadinessChecks:
    def __init__(
        self,
        *,
        database: Callable[[], bool],
        policy: Callable[[], bool],
        listener: Callable[[], bool],
        key_provider: Callable[[], bool],
    ):
        self._checks = (database, policy, listener, key_provider)

    def __call__(self) -> bool:
        # Fail closed on any unavailable dependency. Diagnostics are kept out
        # of the public health response by design.
        for check in self._checks:
            try:
                if not check():
                    return False
            except Exception:
                return False
        return True
