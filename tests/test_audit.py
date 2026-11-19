import unittest
from dataclasses import replace
from tacacs_appliance.audit import AuditWriter
class AuditTests(unittest.TestCase):
 def test_chain_is_per_tenant_and_detects_tampering(self):
  writer=AuditWriter(); one=writer.append(event_id="1",tenant_id="t",actor="a",source="x",action="AUTH",target="r",result="PASS")
  two=writer.append(event_id="2",tenant_id="t",actor="a",source="x",action="AUTHOR",target="r",result="ALLOW")
  writer.append(event_id="3",tenant_id="other",actor="a",source="x",action="AUTH",target="r",result="PASS")
  self.assertEqual(two.previous_hash,one.event_hash);self.assertTrue(writer.verify("t"));self.assertTrue(writer.verify("other"))
  writer._events["t"][1]=replace(two,result="DENY")
  self.assertFalse(writer.verify("t"))
