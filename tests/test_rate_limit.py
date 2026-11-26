import unittest
from tacacs_appliance.rate_limit import SourceRateLimiter
class RateLimitTests(unittest.TestCase):
 def test_capacity_and_refill(self):
  r=SourceRateLimiter(2,1);self.assertTrue(r.allow("ip",0));self.assertTrue(r.allow("ip",0));self.assertFalse(r.allow("ip",0));self.assertTrue(r.allow("ip",1))

 def test_exhaustion_check_preserves_unknown_sources_and_available_tokens(self):
  limiter = SourceRateLimiter(1, 1, max_sources=1)
  self.assertFalse(limiter.is_exhausted("unknown", 0))
  self.assertTrue(limiter.allow("allowed", 0))
  self.assertTrue(limiter.is_exhausted("allowed", 0.5))
  self.assertFalse(limiter.is_exhausted("allowed", 1))
  self.assertTrue(limiter.allow("allowed", 1))
