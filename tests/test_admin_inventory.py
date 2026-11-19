import unittest
from unittest.mock import MagicMock
from tacacs_appliance.admin_inventory import AdminInventory

TENANT='00000000-0000-0000-0000-000000000001'
class InventoryTests(unittest.TestCase):
    def test_scoped_bounded_projection_never_selects_password(self):
        pool=MagicMock();connection=pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchall.side_effect=[[(TENANT,'admin',True,False)]*201,[]]
        result=AdminInventory(pool,TENANT).read()
        self.assertEqual(len(result['users']),200);self.assertTrue(result['truncated'])
        self.assertEqual(set(result['users'][0]),{'id','username','enabled','locked'})
        for call in connection.execute.call_args_list:
            self.assertIn('WHERE tenant_id=%s',call.args[0]);self.assertIn('LIMIT 201',call.args[0])
            self.assertNotIn('password',call.args[0]);self.assertEqual(str(call.args[1][0]),TENANT)
