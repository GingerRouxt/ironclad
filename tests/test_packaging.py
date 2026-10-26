import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('manage',ROOT/'packaging/manage.py')
manage=importlib.util.module_from_spec(spec); spec.loader.exec_module(manage)


class InstallTests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)/'config'
    def tearDown(self): self.tmp.cleanup()
    def test_install_remove_reinstall(self):
        target=manage.install(self.root)
        self.assertTrue((target/'manifest.json').is_file())
        env={'PATH':'/usr/bin','HOME':str(Path(self.tmp.name)/'home'),'XDG_RUNTIME_DIR':self.tmp.name}
        result=subprocess.run([sys.executable,'-I','-B',str(target/'engine.py'),'check','--profile','quick'],env=env,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['schema_version'],'1.0')
        doctor=subprocess.run([str(target/'zds-ironclad'),'doctor'],env=env,capture_output=True,text=True,timeout=5)
        self.assertEqual(doctor.returncode,0,doctor.stderr); self.assertTrue(json.loads(doctor.stdout)['network_guard'])
        manage.remove(self.root); self.assertFalse(target.exists()); manage.install(self.root)
    @unittest.skipUnless(Path('/usr/bin/omarchy').exists(), 'Omarchy host validator unavailable')
    def test_host_manifest_validator(self):
        target=manage.install(self.root)
        subprocess.run(['/usr/bin/omarchy','plugin','validate',str(target)],check=True,capture_output=True)
    def test_installed_uninstaller_self_contained(self):
        target=manage.install(self.root)
        result=subprocess.run([sys.executable,'-I','-B',str(target/'packaging/manage.py'),'--root',str(self.root),'--remove','--apply'],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr); self.assertFalse(target.exists())
    def test_existing_refused(self):
        target=manage.install(self.root); (target/'sentinel').write_text('user')
        with self.assertRaises(FileExistsError): manage.install(self.root)
        self.assertEqual((target/'sentinel').read_text(),'user')
    def test_modified_preserved(self):
        target=manage.install(self.root); (target/'README.md').write_text('user')
        with self.assertRaises(ValueError): manage.remove(self.root)
        self.assertEqual((target/'README.md').read_text(),'user')
    def test_extra_preserved(self):
        target=manage.install(self.root); (target/'notes').write_text('user')
        with self.assertRaises(ValueError): manage.remove(self.root)
        self.assertTrue((target/'engine.py').exists())
    def test_symlink_preserved(self):
        target=manage.install(self.root); (target/'ironclad/extra').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): manage.remove(self.root)
    def test_receipt_traversal(self):
        target=manage.install(self.root); p=target/'.ironclad-install.json'; receipt=json.loads(p.read_text()); receipt['files']['../../victim']='bad'; p.write_text(json.dumps(receipt))
        with self.assertRaises(ValueError): manage.remove(self.root)
        self.assertTrue((target/'engine.py').exists())
    def test_dry_run_no_write(self):
        subprocess.run([sys.executable,str(ROOT/'packaging/manage.py'),'--root',str(self.root),'--dry-run'],check=True,capture_output=True)
        self.assertFalse(self.root.exists())
    def test_symlink_root_refused(self):
        self.root.symlink_to(self.tmp.name,target_is_directory=True)
        with self.assertRaises(OSError): manage.install(self.root)
    def test_state_retained(self):
        state=Path(self.tmp.name)/'history'; state.write_text('retain')
        manage.install(self.root); manage.remove(self.root); self.assertEqual(state.read_text(),'retain')

    def test_diagnostic_schedule_blocks_removal_until_owned_units_removed(self):
        home=Path(self.tmp.name)/'home'
        root=home/'.config'
        units=root/'systemd/user'
        units.mkdir(parents=True)
        target=manage.install(root)
        exists=Path.exists
        def fixture_exists(path):
            if str(path) in ('/usr/lib/ironclad/antimalware-helper','/usr/lib/ironclad/sensor-helper'):
                return False
            return exists(path)
        with patch.object(Path,'home',return_value=home), patch.object(Path,'exists',fixture_exists), \
                patch('ironclad.scheduling.unit_directory',return_value=units), \
                patch('ironclad.protection_updates.unit_directory',return_value=units):
            for name in ('zds-ironclad.service','zds-ironclad.timer'):
                for linked in (False,True):
                    with self.subTest(name=name,linked=linked):
                        unit=units/name
                        if linked: unit.symlink_to(units/'missing')
                        else: unit.write_text('synthetic schedule')
                        with self.assertRaisesRegex(ValueError,'diagnostic schedule'):
                            manage.remove(root)
                        self.assertTrue((target/'engine.py').exists())
                        self.assertTrue(unit.exists() or unit.is_symlink())
                        unit.unlink()
            manage.remove(root)
            self.assertFalse(target.exists())

    def test_existing_safe_shared_plugin_parent(self):
        parent=manage.target_path(self.root).parent; parent.mkdir(parents=True,mode=0o755)
        target=manage.install(self.root)
        self.assertEqual(target.stat().st_mode&0o777,0o700)
        self.assertEqual(parent.stat().st_mode&0o777,0o755)
    def test_writable_shared_plugin_parent_refused(self):
        parent=manage.target_path(self.root).parent; parent.mkdir(parents=True); parent.chmod(0o777)
        with self.assertRaises(ValueError): manage.install(self.root)
