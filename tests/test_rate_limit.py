import unittest
from tacacs_appliance.rate_limit import SourceRateLimiter
class RateLimitTests(unittest.TestCase):
 def test_capacity_and_refill(self):
  r=SourceRateLimiter(2,1);self.assertTrue(r.allow("ip",0));self.assertTrue(r.allow("ip",0));self.assertFalse(r.allow("ip",0));self.assertTrue(r.allow("ip",1))
