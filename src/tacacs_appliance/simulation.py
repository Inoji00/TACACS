"""Read-only policy simulator sharing the production deterministic evaluator."""

from dataclasses import dataclass
from .authorization import AuthorizationEngine, AuthorizationRequest, Decision

# Bound multiplicative rule/sample work before evaluation. This is a conservative
# operation budget, not a CPU deadline or a replacement for request rate limits.
MAX_SIMULATION_RULE_CHECKS = 262144


@dataclass(frozen=True, slots=True)
class SimulationResult:
    decision: Decision
    matched_policy: str | None
    policy_version: str
    explanation: str
    required_mfa: bool | None = None
    risk: str = "unassessed"
    obligations: tuple[str, ...] | None = None


def simulate(
    engine: AuthorizationEngine, request: AuthorizationRequest
) -> SimulationResult:
    result = engine.evaluate(request)
    # The current authorization schema has no risk/MFA/obligation assessment.
    # Unknown is not evidence of low risk or absence of required MFA.
    return SimulationResult(
        result.decision,
        result.matched_rule_id,
        result.policy_version,
        result.explanation,
    )


@dataclass(frozen=True, slots=True)
class DecisionComparison:
    index: int
    baseline: SimulationResult
    candidate: SimulationResult
    effect: str


@dataclass(frozen=True, slots=True)
class PolicyImpact:
    total: int
    newly_allowed: tuple[int, ...]
    newly_denied: tuple[int, ...]
    unchanged: int
    comparisons: tuple[DecisionComparison, ...]
    coverage: str = "provided-samples-only"


def compare_policies(
    baseline: AuthorizationEngine,
    candidate: AuthorizationEngine,
    requests: tuple[AuthorizationRequest, ...],
) -> PolicyImpact:
    """Read-only sample delta, not proof about untested identities or commands.

    No raw commands are echoed in the report: input commands may contain secrets.
    Engines are the same immutable evaluators used for live authorization.
    """
    if not isinstance(requests, tuple) or not 1 <= len(requests) <= 1024:
        raise ValueError("bounded immutable simulation sample required")
    if (baseline.rule_count + candidate.rule_count) * len(
        requests
    ) > MAX_SIMULATION_RULE_CHECKS:
        raise ValueError("simulation work budget exceeded; reduce sample count")
    comparisons = []
    allowed = []
    denied = []
    unchanged = 0
    for index, request in enumerate(requests):
        if not isinstance(request, AuthorizationRequest):
            raise ValueError("authorization request required")
        if any(
            not isinstance(value, str) or not 1 <= len(value) <= 1024
            for value in (request.subject, request.device_id, request.command)
        ):
            raise ValueError("invalid simulation input")
        if (
            not isinstance(request.groups, frozenset)
            or len(request.groups) > 128
            or any(
                not isinstance(group, str) or not 1 <= len(group) <= 253
                for group in request.groups
            )
        ):
            raise ValueError("invalid simulation groups")
        before, after = simulate(baseline, request), simulate(candidate, request)
        if before.decision is Decision.DENY and after.decision is Decision.ALLOW:
            effect = "newly-allowed"
            allowed.append(index)
        elif before.decision is Decision.ALLOW and after.decision is Decision.DENY:
            effect = "newly-denied"
            denied.append(index)
        else:
            effect = "unchanged"
            unchanged += 1
        comparisons.append(DecisionComparison(index, before, after, effect))
    return PolicyImpact(
        len(requests), tuple(allowed), tuple(denied), unchanged, tuple(comparisons)
    )
