import unittest
from tacacs_appliance.readiness import ReadinessChecks

class ReadinessTests(unittest.TestCase):
    def test_all_four_dependencies_required(self):
        for missing in range(4):
            callbacks = [lambda: True for _ in range(4)]
            callbacks[missing] = lambda: False
            readiness = ReadinessChecks(database=callbacks[0],policy=callbacks[1],listener=callbacks[2],key_provider=callbacks[3])
            self.assertFalse(readiness())
        self.assertTrue(ReadinessChecks(database=lambda:True,policy=lambda:True,listener=lambda:True,key_provider=lambda:True)())
