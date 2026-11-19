import unittest
from contextlib import contextmanager, nullcontext
from unittest.mock import Mock
from tacacs_appliance.mfa import totp
from tacacs_appliance.postgres_mfa import PostgresTotpVerifier

ID="00000000-0000-0000-0000-000000000001"
class Pool:
    def __init__(self,last):
        self.db=Mock();self.db.transaction.side_effect=lambda:nullcontext()
        self.db.execute.return_value.fetchone.return_value=("secret://mfa/factor",last,0,False,False)
    @contextmanager
    def connection(self):yield self.db
class MfaReplayTests(unittest.TestCase):
    def test_missing_or_disabled_identity_does_not_resolve_secret(self):
        pool=Pool(-1);pool.db.execute.return_value.fetchone.return_value=None
        resolver=Mock()
        self.assertFalse(PostgresTotpVerifier(pool,ID,resolver).verify(ID,ID,"123456",1700000010))
        resolver.assert_not_called()
        query=pool.db.execute.call_args.args[0]
        self.assertIn("u.enabled AND NOT u.locked",query)
        self.assertIn("u.tenant_id=mfa_factors.tenant_id",query)
    def test_accepted_step_cannot_be_replayed(self):
        secret=b"m"*32; now=1700000010;step=now//30;code=totp(secret,now)
        pool=Pool(-1); verifier=PostgresTotpVerifier(pool,ID,lambda _:secret)
        self.assertTrue(verifier.verify(ID,ID,code,now))
        self.assertEqual(pool.db.execute.call_args.args[1][0],step)
        replay_pool=Pool(step)
        self.assertFalse(PostgresTotpVerifier(replay_pool,ID,lambda _:secret).verify(ID,ID,code,now))
        self.assertEqual(replay_pool.db.execute.call_count,2)

    def test_locked_factor_does_not_resolve_secret(self):
        pool=Pool(-1)
        pool.db.execute.return_value.fetchone.return_value=("secret://mfa/factor",-1,5,True,False)
        resolver=Mock()
        self.assertFalse(PostgresTotpVerifier(pool,ID,resolver).verify(ID,ID,"123456",1700000010))
        resolver.assert_not_called()
        self.assertEqual(pool.db.execute.call_count,1)

    def test_fifth_failure_persists_lockout_parameters(self):
        pool=Pool(-1)
        pool.db.execute.return_value.fetchone.return_value=("secret://mfa/factor",-1,4,False,False)
        secret=b"m"*32;now=1700000010
        invalid=next(code for code in ("000000","111111","222222","333333")
                     if all(code!=totp(secret,now+offset*30) for offset in (-1,0,1)))
        self.assertFalse(PostgresTotpVerifier(pool,ID,lambda _:secret).verify(ID,ID,invalid,now))
        self.assertEqual(pool.db.execute.call_args.args[1][:2],(5,5))

    def test_expired_lockout_restarts_failure_counter(self):
        pool=Pool(-1)
        pool.db.execute.return_value.fetchone.return_value=("secret://mfa/factor",999999999,5,False,True)
        self.assertFalse(PostgresTotpVerifier(pool,ID,lambda _:b"m"*32).verify(ID,ID,"000000",1700000010))
        self.assertEqual(pool.db.execute.call_args.args[1][:2],(1,1))
