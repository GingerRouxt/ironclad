from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ironclad import scheduling


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.home=patch('ironclad.scheduling.home',return_value=self.root); self.home.start()
        self.engine=scheduling.installed_engine(); self.engine.parent.mkdir(parents=True); self.engine.write_text('# fixture')
        self.commands=[]
        def control(op): self.commands.append(op); return 0
        self.control=patch('ironclad.scheduling.control',side_effect=control); self.control.start()
    def tearDown(self): self.control.stop(); self.home.stop(); self.tmp.cleanup()
    def test_preview_no_mutation(self):
        scheduling.plan('enable'); self.assertFalse(scheduling.unit_directory().exists()); self.assertEqual(self.commands,[])
    def test_enable_disable_owned(self):
        scheduling.enable(scheduling.plan('enable')['digest']); self.assertEqual(self.commands,['reload','enable'])
        self.assertEqual((scheduling.unit_directory()/'zds-ironclad.timer').stat().st_mode&0o777,0o600)
        scheduling.disable(scheduling.plan('disable')['digest']); self.assertFalse((scheduling.unit_directory()/'zds-ironclad.timer').exists())
    def test_existing_preserved(self):
        d=scheduling.unit_directory(); d.mkdir(parents=True); (d/'zds-ironclad.service').write_text('user')
        with self.assertRaises(ValueError): scheduling.enable(scheduling.plan('enable')['digest'])
        self.assertEqual((d/'zds-ironclad.service').read_text(),'user'); self.assertEqual(self.commands,[])
    def test_modified_unit_refuses_disable(self):
        scheduling.enable(scheduling.plan('enable')['digest']); self.commands.clear()
        (scheduling.unit_directory()/'zds-ironclad.timer').write_text('user')
        with self.assertRaises(ValueError): scheduling.disable(scheduling.plan('disable')['digest'])
        self.assertEqual(self.commands,[])
    def test_failed_activation_rollback(self):
        with patch('ironclad.scheduling.control',side_effect=lambda op:1 if op=='enable' else 0):
            with self.assertRaises(ValueError): scheduling.enable(scheduling.plan('enable')['digest'])
        self.assertEqual(list(scheduling.unit_directory().iterdir()),[])
    def test_failed_cleanup_preserves(self):
        with patch('ironclad.scheduling.control',side_effect=lambda op:0 if op=='reload' else 1):
            with self.assertRaises(ValueError): scheduling.enable(scheduling.plan('enable')['digest'])
        self.assertTrue((scheduling.unit_directory()/'zds-ironclad.timer').exists())
    def test_missing_engine_refuses(self):
        self.engine.unlink()
        with self.assertRaises(ValueError): scheduling.enable(scheduling.plan('enable')['digest'])
        self.assertFalse(scheduling.unit_directory().exists())
    def test_altered_plan_refuses(self):
        with self.assertRaises(ValueError): scheduling.enable('bad')
    def test_symlink_parent_refuses(self):
        directory=self.root/'.config/systemd'; directory.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError): scheduling.enable(scheduling.plan('enable')['digest'])
    def test_templates_match_reviewed_files(self):
        root=Path(__file__).resolve().parents[1]
        for name,body in scheduling.UNITS.items(): self.assertEqual((root/'packaging/systemd-user'/name).read_text(),body)
