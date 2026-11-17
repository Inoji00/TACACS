"""Deterministic policy regression suite, not a risk/MFA assessment."""
from dataclasses import dataclass
import hashlib
import json
from .authorization import AuthorizationEngine, AuthorizationRequest, Decision
from .postgres_policy import decode_rules


@dataclass(frozen=True)
class PolicyTestReport:
    rules_digest: str
    cases_digest: str
    total: int
    failures: tuple[int, ...]


def run_policy_tests(version: str, rules: list, cases: list) -> PolicyTestReport:
    engine = AuthorizationEngine(version, decode_rules(rules))
    if not isinstance(cases, list) or not 2 <= len(cases) <= 1024:
        raise ValueError("bounded policy test suite required")
    failures, expectations = [], set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {"subject", "device_id", "command", "groups", "expected"}:
            raise ValueError("invalid policy test case")
        for name in ("subject", "device_id", "command"):
            value = case[name]
            if not isinstance(value, str) or not 1 <= len(value) <= 1024:
                raise ValueError("invalid test input")
        groups = case["groups"]
        if not isinstance(groups, list) or len(groups) > 128 or any(not isinstance(g, str) or not 1 <= len(g) <= 253 for g in groups):
            raise ValueError("invalid test groups")
        expected = Decision(case["expected"])
        expectations.add(expected)
        actual = engine.evaluate(AuthorizationRequest(case["subject"], case["device_id"], case["command"], frozenset(groups)))
        if actual.decision != expected:
            failures.append(index)
    if expectations != {Decision.ALLOW, Decision.DENY}:
        raise ValueError("both allow and deny expectations required")
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return PolicyTestReport(digest(rules), digest(cases), len(cases), tuple(failures))
