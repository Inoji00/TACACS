from pathlib import Path
import sys
import tempfile
import json
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from logging_defaults import configure,persist


class LoggingDefaultsTests(unittest.TestCase):
    def test_defaults_do_not_overwrite_custom_logging_or_ports(self):
        config={'services':{'app':{'ports':['192.0.2.2:49:49']},'admin':{'logging':{'driver':'local'}},'initialize':{}}}
        configure(config)
        self.assertEqual(config['services']['app']['logging']['options']['max-file'],'5')
        self.assertEqual(config['services']['admin']['logging'],{'driver':'local'})
        self.assertEqual(config['services']['app']['ports'],['192.0.2.2:49:49'])
        self.assertNotIn('logging',config['services']['initialize'])
        self.assertEqual(config['services']['app']['environment']['TZ'],'Asia/Ho_Chi_Minh')

    def test_timezone_handles_environment_list_and_preserves_overrides(self):
        config={'services':{'app':{'environment':['TOKEN=kept','PASSTHROUGH']},
            'admin':{'environment':{'TZ':'UTC','PGTZ':'UTC'}},
            'postgres':{'command':['postgres','-c','max_connections=200']}}}
        configure(config)
        self.assertEqual(config['services']['app']['environment'],{'TOKEN':'kept','PASSTHROUGH':None,'TZ':'Asia/Ho_Chi_Minh','PGTZ':'UTC'})
        self.assertEqual(config['services']['admin']['environment']['TZ'],'UTC')
        self.assertEqual(config['services']['postgres']['command'],['postgres','-c','max_connections=200'])
        default={'services':{'postgres':{}}};configure(default)
        self.assertEqual(default['services']['postgres']['command'],['postgres','-c','timezone=UTC','-c','log_timezone=Asia/Ho_Chi_Minh'])

    def test_persistent_defaults_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'compose.json';path.write_text(json.dumps({'services':{'app':{}}}),encoding='utf-8')
            persist(directory);first=path.read_bytes();persist(directory)
            self.assertEqual(path.read_bytes(),first)
