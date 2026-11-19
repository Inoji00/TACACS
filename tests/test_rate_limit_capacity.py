import unittest
from tacacs_appliance.rate_limit import SourceRateLimiter

class RateLimitCapacityTests(unittest.TestCase):
    def test_new_sources_fail_closed_until_idle_expiry(self):
        limiter = SourceRateLimiter(2,1,max_sources=1,idle_seconds=3)
        self.assertTrue(limiter.allow("first",0))
        self.assertFalse(limiter.allow("second",1))
        self.assertTrue(limiter.allow("second",3))
        self.assertEqual(len(limiter._buckets),1)
