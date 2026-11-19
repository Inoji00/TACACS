import unittest
from tacacs_appliance.accounting import redact_arguments, accounting_details
class AccountingTests(unittest.TestCase):
 def test_redacts_sensitive_arguments(self):self.assertEqual(redact_arguments(("cmd=show","password=x")),("cmd=show","<redacted>"))
 def test_split_password_command_redacts_all_command_material(self):
  args=('service=shell','cmd=username','cmd-arg=admin','cmd-arg=secret','cmd-arg=9','cmd-arg=HASHVALUE')
  self.assertEqual(redact_arguments(args),('service=shell',)+('<redacted>',)*5)
 def test_optional_secret_attributes_and_case(self):
  self.assertEqual(redact_arguments(('PASSWORD*value','Secret=value','token*abc')),('<redacted>',)*3)
 def test_snmp_community_and_inline_secret_commands(self):
  for args in (('cmd=snmp-server','cmd-arg=community','cmd-arg=VALUE'),
               ('cmd=set password VALUE',),('cmd=crypto','cmd-arg=private-key','cmd-arg=VALUE')):
   self.assertEqual(redact_arguments(args),('<redacted>',)*len(args))
 def test_safe_show_command_preserved(self):
  args=('service=shell','cmd=show','cmd-arg=interfaces','task_id=42')
  self.assertEqual(redact_arguments(args),args)
 def test_redaction_is_idempotent(self):
  args=('cmd=configure','cmd-arg=secret','cmd-arg=VALUE','password*VALUE')
  redacted=redact_arguments(args)
  self.assertEqual(redact_arguments(redacted),redacted)

 def test_safe_command_projection_and_task_context(self):
  details=accounting_details(['service=shell','cmd=show','cmd-arg=interfaces','cmd-arg=status','cmd-arg=<cr>','task_id=task-A','priv-lvl=15'])
  self.assertEqual(details,dict(kind='command',command='show interfaces status <cr>',redacted=False,task_id='task-A',privilege=15))
  self.assertEqual(accounting_details(['service=shell','cmd='])['kind'],'exec')
 def test_test_aaa_and_abbreviated_secrets_hidden_before_storage_and_display(self):
  for args in [('cmd=test','cmd-arg=aaa','cmd-arg=group','cmd-arg=LAB','cmd-arg=user','cmd-arg=LEAK','cmd-arg=legacy'),('cmd=test aaa group LAB user LEAK legacy',),('cmd=username','cmd-arg=user','cmd-arg=sec','cmd-arg=LEAK'),('cmd=copy','cmd-arg=scp://user:LEAK@host/file','cmd-arg=flash:'),('cmd=snmp-server','cmd-arg=user','cmd-arg=user group v3 auth sha LEAK'),('cmd=snmp-server host 192.0.2.1 version 2c LEAK',)]:
   self.assertNotIn('LEAK',str(redact_arguments(args)))
   details=accounting_details(args);self.assertTrue(details['redacted']);self.assertIsNone(details['command']);self.assertNotIn('LEAK',str(details))
 def test_projection_rejects_ambiguous_unbounded_and_control_commands(self):
  for args in [None,['cmd=show','cmd=evil'],['cmd=show\nSECRET'],['cmd='+('x'*2049)],['cmd=show',123]]:
   details=accounting_details(args);self.assertTrue(details['redacted']);self.assertIsNone(details['command'])
