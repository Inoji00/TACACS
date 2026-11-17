"""Deterministic, default-deny authorization core."""
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum
from .command import normalize, CommandError

class Decision(StrEnum): ALLOW = "allow"; DENY = "deny"
@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    subject: str; device_id: str; command: str; groups: frozenset[str] = frozenset()
@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str; groups: frozenset[str]; device_ids: frozenset[str]; command_prefix: str; decision: Decision
@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    decision: Decision; policy_version: str; matched_rule_id: str | None; explanation: str

class AuthorizationEngine:
    """Rules are evaluated in immutable declared order; no match is always deny."""
    def __init__(self, policy_version: str, rules: tuple[PolicyRule, ...]) -> None:
        if not policy_version: raise ValueError("policy version required")
        self._version, self._rules = policy_version, rules
    @property
    def rule_count(self) -> int:
        """Immutable rule inventory for bounded offline simulation work."""
        return len(self._rules)
    def evaluate(self, request: AuthorizationRequest) -> AuthorizationResult:
        try:
            command = normalize(request.command).canonical
        except CommandError:
            return AuthorizationResult(Decision.DENY, self._version, None, "invalid command")
        for rule in self._rules:
            if rule.groups and not request.groups.intersection(rule.groups): continue
            if rule.device_ids and request.device_id not in rule.device_ids: continue
            prefix = rule.command_prefix.strip()
            if prefix and (command == prefix or command.startswith(prefix + " ")):
                return AuthorizationResult(rule.decision, self._version, rule.rule_id, "matched policy rule")
        return AuthorizationResult(Decision.DENY, self._version, None, "no policy rule matched")
def _normalize(command: str) -> str:
    normalized = " ".join(command.strip().split())
    if not normalized or any(ord(c) < 32 or ord(c) == 127 for c in normalized):
        return "\0"  # impossible policy command; fail closed
    return normalized
