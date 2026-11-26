"""Tenant-authorized read-only policy impact from one database snapshot."""

from dataclasses import asdict
import hashlib
import json
from uuid import UUID, uuid4
from psycopg.types.json import Jsonb
from .authorization import AuthorizationEngine, AuthorizationRequest
from .postgres_policy import decode_rules
from .simulation import compare_policies
from .simulation_evidence import validate_report


def canonical_digest(value):
    """Stable evidence encoding; array order and duplicate values remain significant."""
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


class PostgresPolicySimulation:
    def __init__(self, pool, tenant_id, audit=None):
        self.pool, self.tenant, self.audit = pool, UUID(tenant_id), audit

    @staticmethod
    def _requests(samples):
        if not isinstance(samples, list) or not 1 <= len(samples) <= 1024:
            raise ValueError("bounded simulation sample required")
        requests = []
        for sample in samples:
            if not isinstance(sample, dict) or set(sample) != {
                "subject",
                "device_id",
                "command",
                "groups",
            }:
                raise ValueError("invalid simulation sample")
            if any(
                not isinstance(sample[name], str) or not 1 <= len(sample[name]) <= 1024
                for name in ("subject", "device_id", "command")
            ):
                raise ValueError("invalid simulation input")
            groups = sample["groups"]
            if (
                not isinstance(groups, list)
                or len(groups) > 128
                or any(
                    not isinstance(group, str) or not 1 <= len(group) <= 253
                    for group in groups
                )
            ):
                raise ValueError("invalid simulation groups")
            requests.append(
                AuthorizationRequest(
                    sample["subject"],
                    sample["device_id"],
                    sample["command"],
                    frozenset(groups),
                )
            )
        return tuple(requests)

    def _permission(self, connection, user, permission):
        granted = connection.execute(
            "SELECT 1 FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
            "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission=%s AND u.enabled AND NOT u.locked",
            (self.tenant, user, permission),
        ).fetchone()
        if granted is None:
            raise PermissionError("simulation permission required")

    def _load(self, connection, version, user, permission):
        self._permission(connection, user, permission)
        rows = connection.execute(
            "SELECT id,rules,state FROM policy_versions WHERE tenant_id=%s "
            "AND (id=%s OR state='active')",
            (self.tenant, version),
        ).fetchall()
        candidate = next((row for row in rows if row[0] == version), None)
        if candidate is None:
            raise ValueError("candidate unavailable")
        active = [row for row in rows if row[2] == "active"]
        if len(active) > 1:
            raise ValueError("ambiguous active policy")
        return candidate, active[0] if active else None

    @staticmethod
    def _evaluate(candidate, active, requests):
        baseline = (
            AuthorizationEngine(str(active[0]), decode_rules(active[1]))
            if active
            else AuthorizationEngine("default-deny", ())
        )
        target = AuthorizationEngine(str(candidate[0]), decode_rules(candidate[1]))
        report = compare_policies(baseline, target, requests)
        return dict(
            baseline_version=str(active[0]) if active else "default-deny",
            candidate_version=str(candidate[0]),
            **asdict(report),
        )

    def compare(self, version_id, actor, samples):
        version, user = UUID(version_id), UUID(actor)
        requests = self._requests(samples)
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                candidate, active = self._load(
                    connection, version, user, "console.read"
                )
                return self._evaluate(candidate, active, requests)

    def record(self, version_id, actor, samples):
        if not callable(self.audit):
            raise ValueError("transaction-bound audit writer required")
        version, user = UUID(version_id), UUID(actor)
        requests = self._requests(samples)
        digest = canonical_digest
        report_id = uuid4()
        with self.pool.connection() as connection:
            with connection.transaction():
                # Activation uses this same tenant lock. No policy state changes.
                if (
                    connection.execute(
                        "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self.tenant,)
                    ).fetchone()
                    is None
                ):
                    raise ValueError("tenant unavailable")
                candidate, active = self._load(
                    connection, version, user, "policy.draft"
                )
                report = self._evaluate(candidate, active, requests)
                validate_report(
                    report,
                    baseline_version=report["baseline_version"],
                    candidate_version=str(version),
                    sample_count=len(samples),
                )
                baseline_digest, candidate_digest, samples_digest = (
                    digest(active[1] if active else []),
                    digest(candidate[1]),
                    digest(samples),
                )
                connection.execute(
                    "INSERT INTO policy_simulation_reports(id,tenant_id,simulated_by,candidate_id,baseline_id,"
                    "baseline_rules_digest,candidate_rules_digest,samples_digest,sample_count,report) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        report_id,
                        self.tenant,
                        user,
                        version,
                        active[0] if active else None,
                        baseline_digest,
                        candidate_digest,
                        samples_digest,
                        len(samples),
                        Jsonb(report),
                    ),
                )
                self.audit(
                    connection,
                    actor=str(user),
                    source="admin-simulation",
                    action="policy.simulation.record",
                    target=str(report_id),
                    result="success",
                    policy_version=str(version),
                    security_context=dict(
                        baseline_version=report["baseline_version"],
                        samples_digest=samples_digest,
                        report_digest=digest(report),
                    ),
                )
        return dict(report_id=str(report_id), report=report)

    def list_records(self, version_id, actor, *, before=None, limit=20):
        version, user = UUID(version_id), UUID(actor)
        cursor = UUID(before) if before is not None else None
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("invalid evidence pagination")
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                self._permission(connection, user, "console.read")
                if (
                    connection.execute(
                        "SELECT id FROM policy_versions WHERE tenant_id=%s AND id=%s",
                        (self.tenant, version),
                    ).fetchone()
                    is None
                ):
                    return None
                # Cursor lookup is scoped to the same tenant AND policy. A cursor
                # cannot leak another tenant's record or navigate another policy.
                boundary = None
                if cursor is not None:
                    boundary = connection.execute(
                        "SELECT created_at,id FROM policy_simulation_reports "
                        "WHERE tenant_id=%s AND candidate_id=%s AND id=%s",
                        (self.tenant, version, cursor),
                    ).fetchone()
                    if boundary is None:
                        raise ValueError("invalid evidence cursor")
                clause = " AND (created_at,id)<(%s,%s)" if boundary else ""
                values = (self.tenant, version, *(boundary or ()), limit + 1)
                rows = connection.execute(
                    "SELECT id,simulated_by,created_at,candidate_id,baseline_id,sample_count "
                    "FROM policy_simulation_reports WHERE tenant_id=%s AND candidate_id=%s"
                    + clause
                    + " ORDER BY created_at DESC,id DESC LIMIT %s",
                    values,
                ).fetchall()
        items = [self._metadata(row) for row in rows[:limit]]
        return dict(
            items=items,
            next_before=items[-1]["report_id"] if len(rows) > limit else None,
        )

    @staticmethod
    def _metadata(row):
        return dict(
            report_id=str(row[0]),
            simulated_by=str(row[1]),
            created_at=row[2].isoformat(),
            candidate_version=str(row[3]),
            baseline_version=str(row[4]) if row[4] else "default-deny",
            sample_count=row[5],
            integrity_status="not-verified",
        )

    def inspect_record(self, version_id, actor, report_id):
        version, user, report = UUID(version_id), UUID(actor), UUID(report_id)
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                self._permission(connection, user, "console.read")
                row = connection.execute(
                    "SELECT id,simulated_by,created_at,candidate_id,baseline_id,sample_count,"
                    "baseline_rules_digest,candidate_rules_digest,samples_digest,report "
                    "FROM policy_simulation_reports WHERE tenant_id=%s AND candidate_id=%s AND id=%s",
                    (self.tenant, version, report),
                ).fetchone()
                if row is None:
                    return None
                item = self._metadata(row)
                item.update(
                    baseline_rules_digest=row[6],
                    candidate_rules_digest=row[7],
                    samples_digest=row[8],
                    report=validate_report(
                        row[9],
                        baseline_version=item["baseline_version"],
                        candidate_version=item["candidate_version"],
                        sample_count=item["sample_count"],
                    ),
                )
                return item

    def verify_record(self, version_id, actor, report_id, samples):
        """Replay recorded versions, without claiming provenance or writing evidence."""
        version, user, record = UUID(version_id), UUID(actor), UUID(report_id)
        requests = self._requests(samples)
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
                self._permission(connection, user, "console.read")
                row = connection.execute(
                    "SELECT baseline_id,sample_count,baseline_rules_digest,"
                    "candidate_rules_digest,samples_digest,report FROM policy_simulation_reports "
                    "WHERE tenant_id=%s AND candidate_id=%s AND id=%s",
                    (self.tenant, version, record),
                ).fetchone()
                if row is None:
                    return None
                (
                    baseline_id,
                    count,
                    baseline_digest,
                    target_digest,
                    sample_digest,
                    stored,
                ) = row
                validate_report(
                    stored,
                    baseline_version=str(baseline_id)
                    if baseline_id
                    else "default-deny",
                    candidate_version=str(version),
                    sample_count=count,
                )
                rows = connection.execute(
                    "SELECT id,rules,state FROM policy_versions WHERE tenant_id=%s "
                    "AND (id=%s OR id=%s)",
                    (self.tenant, version, baseline_id),
                ).fetchall()
                candidate = next((item for item in rows if item[0] == version), None)
                baseline = (
                    next((item for item in rows if item[0] == baseline_id), None)
                    if baseline_id
                    else None
                )
                samples_match = (
                    len(samples) == count and canonical_digest(samples) == sample_digest
                )
                available = candidate is not None and (
                    baseline_id is None or baseline is not None
                )
                rules_match = (
                    available
                    and canonical_digest(candidate[1]) == target_digest
                    and canonical_digest(baseline[1] if baseline else [])
                    == baseline_digest
                )
                decisions_match = None
                if samples_match and rules_match:
                    replay = self._evaluate(candidate, baseline, requests)
                    decisions_match = canonical_digest(replay) == canonical_digest(
                        stored
                    )
                return dict(
                    report_id=str(record),
                    candidate_version=str(version),
                    baseline_version=str(baseline_id)
                    if baseline_id
                    else "default-deny",
                    samples_match=samples_match,
                    rules_match=bool(rules_match),
                    decisions_match=decisions_match,
                    integrity_status="not-verified",
                    coverage="provided-samples-only",
                )
