import unittest
from tacacs_appliance.device_access import assignment,validate_mappings,read_only_command


class DeviceAccessTests(unittest.TestCase):
    def test_names_do_not_grant_access_and_conflicts_never_elevate(self):
        mappings=[dict(group='admins',privilege=15,mode='policy'),dict(group='readers',privilege=1,mode='read_only')]
        self.assertEqual(assignment({'admins'},mappings),(15,'policy'))
        self.assertEqual(assignment({'readers'},mappings),(1,'read_only'))
        self.assertIsNone(assignment({'admins','readers'},mappings))
        self.assertIsNone(assignment({'SuperAdmin'},mappings))
        self.assertIsNone(assignment({'admins'},[]))
        self.assertIsNone(assignment({'admins'},[dict(group='admins',privilege=99,mode='policy')]))

    def test_duplicate_groups_invalid_levels_and_readonly_elevation_rejected(self):
        row=dict(group='ops',privilege=1,mode='policy')
        for value in ([row,row],[dict(row,privilege=True)],[dict(row,mode='read_only',privilege=15)],[dict(row,group='bad group')],{},[row]*65):
            with self.assertRaises(ValueError):validate_mappings(value)

    def test_readonly_cap_rejects_modification_abbreviation_and_shell_operators(self):
        for command in ('show version','show interfaces status'):
            self.assertTrue(read_only_command(command))
        for command in ('configure terminal','reload','copy run start','sh version','show run | redirect flash:test','show run > file','show version;reload','show version\nreload',''):
            self.assertFalse(read_only_command(command))
