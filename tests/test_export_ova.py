import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('export_ova', Path(__file__).resolve().parents[1]/'scripts/export_ova.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OvaExportTests(unittest.TestCase):
    def test_local_export_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'template.vmx'
            source.write_text('scsi0:0.fileName = "disk.vmdk"\n')
            (root/'disk.vmdk').touch()
            target = root/'release.ova'
            command = module.export_command('ovftool', source, target)
            self.assertEqual(command[1], '--shaAlgorithm=SHA256')
            self.assertEqual(command[-2:], [str(source.resolve()), str(target.resolve())])
            target.touch()
            with self.assertRaises(FileExistsError):
                module.export_command('ovftool', source, target)

    def test_locked_and_wrong_format_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'template.vmx'
            source.touch()
            (root/'template.vmx.lck').mkdir()
            with self.assertRaises(ValueError):
                module.export_command('ovftool', source, root/'release.ova')
            with self.assertRaises(ValueError):
                module.export_command('ovftool', source, root/'release.zip')

    def test_template_rejects_seed_media_suspend_and_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'template.vmx'
            (root/'disk-000001.vmdk').touch()
            for content in ('ide1:0.fileName = "seed.iso"',
                            'checkpoint.vmState = "state.vmss"',
                            'scsi0:0.fileName = "disk-000001.vmdk"'):
                source.write_text(content)
                with self.assertRaises(ValueError):
                    module.validate_template(source)
