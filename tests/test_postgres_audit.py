import hashlib
from datetime import datetime, timezone
from uuid import UUID
import unittest
from contextlib import contextmanager, nullcontext
from unittest.mock import Mock
from tacacs_appliance.audit import _canonical
from tacacs_appliance.postgres_audit import PostgresAuditWriter
from psycopg.pq import TransactionStatus

TENANT = "00000000-0000-0000-0000-000000000001"

class Pool:
    def __init__(self, rows):
        self.db = Mock()
        self.db.transaction.side_effect = lambda: nullcontext()
        self.db.execute.return_value.fetchall.return_value = rows
    @contextmanager
    def connection(self): yield self.db

class PostgresAuditTests(unittest.TestCase):
    def test_malformed_canonical_and_hash_fail_closed(self):
        for canonical, digest in (("[]", "0"*64), ("null", "0"*64), ("{}", None),
                                  ("{}", "z"*64), (123, "0"*64), ("{broken", "0"*64)):
            row = (canonical, "0"*64, digest, *([None]*11))
            self.assertFalse(PostgresAuditWriter(Pool([row]), TENANT).verify())
        self.assertFalse(PostgresAuditWriter(Pool([("short",)]), TENANT).verify())
    def test_transaction_append_never_opens_or_commits_another_connection(self):
        pool, connection = Mock(), Mock()
        connection.info.transaction_status = TransactionStatus.INTRANS
        connection.execute.return_value.fetchone.side_effect = [(TENANT,), None]
        digest = PostgresAuditWriter(pool, TENANT).policy_callback(connection, actor="a", action="policy.activate", target="v")
        self.assertEqual(len(digest), 64)
        pool.connection.assert_not_called()
        connection.commit.assert_not_called()
        connection.rollback.assert_not_called()

    def test_aaa_target_name_is_snapshotted_with_audit_event(self):
        pool = Pool([])
        pool.db.info.transaction_status = TransactionStatus.INTRANS
        pool.db.execute.return_value.fetchone.side_effect = [(TENANT,), None, ('Core-SW',)]
        writer = PostgresAuditWriter(pool, TENANT)
        writer.append(actor='device',source='tacacs',action='aaa.authorization',
                      target='192.0.2.7',result='allow',security_context={'reason':'exec-granted'})
        lookup = pool.db.execute.call_args_list[-2].args
        self.assertIn('tenant_id=%s AND address=%s AND NOT deleted',lookup[0])
        self.assertEqual(lookup[1],(UUID(TENANT),'192.0.2.7'))
        inserted = pool.db.execute.call_args.args[1]
        self.assertEqual(inserted[11].obj, {'target_name':'Core-SW','reason':'exec-granted'})
        self.assertIn('"target_name":"Core-SW"',inserted[14])

    def test_transaction_append_rejects_autocommit(self):
        pool, connection = Mock(), Mock()
        connection.info.transaction_status = TransactionStatus.IDLE
        with self.assertRaises(ValueError):
            PostgresAuditWriter(pool, TENANT).policy_callback(connection, actor="a", action="policy.activate", target="v")
        connection.execute.assert_not_called()
    def test_verifies_chain_and_rejects_tampered_data(self):
        previous = "0" * 64
        timestamp=datetime.now(timezone.utc)
        identifier=UUID("00000000-0000-0000-0000-000000000003")
        event=dict(tenant_id=TENANT,previous_hash=previous,result="pass",actor="u",source="d",action="auth",target="d",policy_version=None,session_id="s",correlation_id="c",security_context={},event_id=str(identifier),timestamp=timestamp.isoformat())
        canonical = _canonical(event)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        tail=("u","d","auth","d","pass",None,"s","c",{},identifier,timestamp)
        self.assertTrue(PostgresAuditWriter(Pool([(canonical,previous,digest,*tail)]),TENANT).verify())
        self.assertFalse(PostgresAuditWriter(Pool([(canonical.replace("pass","fail"),previous,digest,*tail)]),TENANT).verify())
        self.assertFalse(PostgresAuditWriter(Pool([(None,previous,digest,*tail)]),TENANT).verify())
        altered=list(tail);altered[4]="fail"
        self.assertFalse(PostgresAuditWriter(Pool([(canonical,previous,digest,*altered)]),TENANT).verify())
