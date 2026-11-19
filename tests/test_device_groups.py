import unittest
from uuid import uuid4
from unittest.mock import MagicMock
from tacacs_appliance.device_groups import DeviceGroups,validate_tree,description,identifier


class DeviceGroupTests(unittest.TestCase):
    def test_hierarchy_rejects_cycles_missing_parents_and_depth_overflow(self):
        a,b=uuid4(),uuid4()
        validate_tree([(a,'location','A','',None),(b,'location','B','',a)])
        for rows in ([(a,'location','A','',a)],[(a,'location','A','',b),(b,'location','B','',a)],[(a,'location','A','',b)]):
            with self.assertRaises(ValueError):validate_tree(rows)
        ids=[uuid4() for _ in range(9)]
        with self.assertRaises(ValueError):validate_tree([(value,'location','A','',ids[i-1] if i else None) for i,value in enumerate(ids)])

    def test_invalid_payloads_never_open_database(self):
        pool=MagicMock();service=DeviceGroups(pool,uuid4());actor=str(uuid4())
        valid=dict(operation='save',id=None,kind='location',name='HCM-DC',description='',parent_id=None)
        for changes in ({'kind':'radius'},{'name':' bad '},{'name':'x'*65},{'description':'x'*257},{'parent_id':True},{'id':12}):
            with self.assertRaises(ValueError):service.save(actor,dict(valid,**changes),MagicMock())
        pool.connection.assert_not_called()
        with self.assertRaises(ValueError):description('\x00')
        with self.assertRaises(ValueError):identifier(True)

    def test_denied_actor_cannot_mutate_groups(self):
        pool=MagicMock();connection=pool.connection.return_value.__enter__.return_value
        connection.execute.return_value.fetchone.return_value=None
        with self.assertRaises(PermissionError):DeviceGroups(pool,uuid4()).save(str(uuid4()),dict(operation='delete',id=str(uuid4())),MagicMock())
        self.assertEqual(connection.execute.call_count,2)
