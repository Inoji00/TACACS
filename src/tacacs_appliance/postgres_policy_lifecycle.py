"""Tenant-serialized policy transitions with transaction-bound audit callback."""
from uuid import UUID, uuid4
from psycopg.types.json import Jsonb
from .postgres_policy import decode_rules
from .policy_testing import run_policy_tests


class PostgresPolicyLifecycle:
    def __init__(self, pool, tenant_id: str, audit):
        if not callable(audit):
            raise ValueError("transaction-bound audit writer required")
        self._pool, self._tenant, self._audit = pool, UUID(tenant_id), audit

    def _actor(self, connection, actor, permission):
        actor = UUID(actor)
        tenant = connection.execute("SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self._tenant,)).fetchone()
        if tenant is None:
            raise ValueError("tenant unavailable")
        granted = connection.execute(
            "SELECT 1 FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
            "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission=%s AND u.enabled AND NOT u.locked",
            (self._tenant, actor, permission)).fetchone()
        if granted is None:
            raise PermissionError("policy permission required")
        return actor

    def list_versions(self,actor: str,*,before: int=9223372036854775807,limit: int=50) -> dict:
        if type(before) is not int or not 1<=before<=9223372036854775807 or type(limit) is not int or not 1<=limit<=100:
            raise ValueError('invalid pagination')
        with self._pool.connection() as connection:
            with connection.transaction():
                self._actor(connection,actor,'console.read')
                rows=connection.execute('SELECT id,revision,state,author_id,approver_id FROM policy_versions '
                    'WHERE tenant_id=%s AND revision<%s AND NOT EXISTS (SELECT 1 FROM policy_retirements r WHERE r.version_id=policy_versions.id AND r.tenant_id=policy_versions.tenant_id) ORDER BY revision DESC LIMIT %s',
                    (self._tenant,before,limit+1)).fetchall()
        items=[dict(version_id=str(row[0]),revision=row[1],state=row[2],author_id=str(row[3]),
                    approver_id=str(row[4]) if row[4] else None) for row in rows[:limit]]
        return dict(items=items,next_before=items[-1]['revision'] if len(rows)>limit else None)

    def _available(self,connection,version):
        if connection.execute('SELECT 1 FROM policy_retirements WHERE tenant_id=%s AND version_id=%s',(self._tenant,version)).fetchone():
            raise ValueError('policy removed from workflow')

    def discard(self,version_id,actor):
        version=UUID(version_id)
        with self._pool.connection() as connection:
            with connection.transaction():
                subject=self._actor(connection,actor,'policy.draft')
                self._available(connection,version)
                row=connection.execute('SELECT state,author_id,approver_id FROM policy_versions WHERE id=%s AND tenant_id=%s AND NOT EXISTS (SELECT 1 FROM policy_retirements r WHERE r.version_id=policy_versions.id AND r.tenant_id=policy_versions.tenant_id) FOR UPDATE',(version,self._tenant)).fetchone()
                if row is None or row[0] not in ('draft','test','approval') or row[2] is not None:raise ValueError('unapproved inactive policy required')
                if row[1]!=subject:raise PermissionError('policy author required')
                connection.execute('INSERT INTO policy_retirements(version_id,tenant_id,retired_by) VALUES (%s,%s,%s)',(version,self._tenant,subject))
                self._audit(connection,actor=str(subject),action='policy.discard',target=str(version))

    def inspect(self, version_id: str, actor: str) -> dict | None:
        version=UUID(version_id)
        with self._pool.connection() as connection:
            with connection.transaction():
                self._actor(connection,actor,"console.read")
                row=connection.execute("SELECT revision,state,author_id,approver_id,rules,rollback_source_id "
                                       "FROM policy_versions WHERE id=%s AND tenant_id=%s",(version,self._tenant)).fetchone()
                if row is None:return None
                decode_rules(row[4])
                evidence=connection.execute("SELECT rules_digest,cases_digest,total,cases,tested_by FROM policy_test_reports "
                                            "WHERE version_id=%s AND tenant_id=%s",(version,self._tenant)).fetchone()
                report=None
                if evidence is not None:
                    report=dict(rules_digest=evidence[0],cases_digest=evidence[1],total=evidence[2],
                                cases=evidence[3],tested_by=str(evidence[4]))
                return dict(version_id=str(version),revision=row[0],state=row[1],author_id=str(row[2]),
                            approver_id=str(row[3]) if row[3] else None,rules=row[4],
                            rollback_source_id=str(row[5]) if row[5] else None,test_report=report)

    def draft(self, actor: str, rules: list) -> str:
        decode_rules(rules)
        version = uuid4()
        with self._pool.connection() as connection:
            with connection.transaction():
                author = self._actor(connection, actor, "policy.draft")
                revision = connection.execute("SELECT COALESCE(MAX(revision),0)+1 FROM policy_versions WHERE tenant_id=%s",
                                              (self._tenant,)).fetchone()[0]
                connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules) "
                                   "VALUES (%s,%s,%s,'draft',%s,%s)",
                                   (version, self._tenant, revision, author, Jsonb(rules)))
                self._audit(connection, actor=str(author), action="policy.draft", target=str(version))
        return str(version)

    def rollback_draft(self, source_id: str, actor: str) -> str:
        """Copy a formerly active version; never bypass review or mutate history."""
        source, version = UUID(source_id), uuid4()
        with self._pool.connection() as connection:
            with connection.transaction():
                author = self._actor(connection, actor, "policy.draft")
                row = connection.execute("SELECT state,rules FROM policy_versions WHERE id=%s AND tenant_id=%s AND NOT EXISTS (SELECT 1 FROM policy_retirements r WHERE r.version_id=policy_versions.id AND r.tenant_id=policy_versions.tenant_id) FOR UPDATE",
                                         (source, self._tenant)).fetchone()
                if row is None or row[0] not in ("active", "archived"):
                    raise ValueError("rollback source must be a previously activated policy")
                decode_rules(row[1])
                revision = connection.execute("SELECT COALESCE(MAX(revision),0)+1 FROM policy_versions WHERE tenant_id=%s",
                                              (self._tenant,)).fetchone()[0]
                connection.execute("INSERT INTO policy_versions(id,tenant_id,revision,state,author_id,rules,rollback_source_id) "
                                   "VALUES (%s,%s,%s,'draft',%s,%s,%s)",
                                   (version, self._tenant, revision, author, Jsonb(row[1]), source))
                self._audit(connection, actor=str(author), action="policy.rollback_draft", target=str(version))
        return str(version)

    def transition(self, version_id: str, actor: str, action: str) -> None:
        if action == "test":
            raise ValueError("use test_version with an explicit regression suite")
        transitions = {"test": ("draft", "test", "policy.draft"),
                       "submit": ("test", "approval", "policy.draft"),
                       "approve": ("approval", "approval", "policy.approve"),
                       "activate": ("approval", "active", "policy.activate")}
        if action not in transitions:
            raise ValueError("unsupported policy transition")
        old, new, permission = transitions[action]
        version = UUID(version_id)
        with self._pool.connection() as connection:
            with connection.transaction():
                subject = self._actor(connection, actor, permission)
                row = connection.execute("SELECT state,author_id,approver_id,rules FROM policy_versions "
                                         "WHERE id=%s AND tenant_id=%s AND NOT EXISTS (SELECT 1 FROM policy_retirements r WHERE r.version_id=policy_versions.id AND r.tenant_id=policy_versions.tenant_id) FOR UPDATE", (version, self._tenant)).fetchone()
                if row is None or row[0] != old:
                    raise ValueError("invalid policy state")
                decode_rules(row[3])
                if action in ("test", "submit") and subject != row[1]:
                    raise PermissionError("policy author required")
                if action in ("approve", "activate") and subject == row[1]:
                    raise PermissionError("independent policy actor required")
                if action == "activate" and row[2] is None:
                    raise ValueError("approval required")
                evidence = connection.execute("SELECT rules_digest,cases_digest,total,cases,tested_by FROM policy_test_reports "
                                              "WHERE version_id=%s AND tenant_id=%s", (version, self._tenant)).fetchone()
                if evidence is None or evidence[3] is None or evidence[4] != row[1]:
                    raise ValueError("policy test evidence required")
                report = run_policy_tests(str(version), row[3], evidence[3])
                if report.failures or (report.rules_digest, report.cases_digest, report.total) != evidence[:3]:
                    raise ValueError("policy test evidence mismatch")
                if action == "approve":
                    if row[2] is not None:
                        raise ValueError("policy already approved")
                    connection.execute("UPDATE policy_versions SET approver_id=%s WHERE id=%s AND tenant_id=%s",
                                       (subject, version, self._tenant))
                else:
                    if action == "activate":
                        if row[2] is None:
                            raise ValueError("approval required")
                        connection.execute("UPDATE policy_versions SET state='archived' WHERE tenant_id=%s AND state='active'",
                                           (self._tenant,))
                    connection.execute("UPDATE policy_versions SET state=%s WHERE id=%s AND tenant_id=%s",
                                       (new, version, self._tenant))
                self._audit(connection, actor=str(subject), action="policy." + action, target=str(version))

    def test_version(self, version_id: str, actor: str, cases: list):
        version = UUID(version_id)
        with self._pool.connection() as connection:
            with connection.transaction():
                subject = self._actor(connection, actor, "policy.draft")
                row = connection.execute("SELECT state,author_id,rules FROM policy_versions WHERE id=%s AND tenant_id=%s AND NOT EXISTS (SELECT 1 FROM policy_retirements r WHERE r.version_id=policy_versions.id AND r.tenant_id=policy_versions.tenant_id) FOR UPDATE",
                                         (version, self._tenant)).fetchone()
                if row is None or row[0] != "draft" or row[1] != subject:
                    raise ValueError("author-owned draft required")
                report = run_policy_tests(str(version), row[2], cases)
                if report.failures:
                    raise ValueError("policy regression suite failed")
                connection.execute("INSERT INTO policy_test_reports(version_id,tenant_id,tested_by,rules_digest,cases_digest,total,cases) "
                                   "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                                   (version, self._tenant, subject, report.rules_digest, report.cases_digest, report.total, Jsonb(cases)))
                connection.execute("UPDATE policy_versions SET state='test' WHERE id=%s AND tenant_id=%s", (version, self._tenant))
                self._audit(connection, actor=str(subject), action="policy.test", target=str(version))
                return report
