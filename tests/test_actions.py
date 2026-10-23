from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from ironclad import actions
from ironclad.cli import main
from ironclad.storage import Store


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); self.home=self.root/'home'; self.home.mkdir(mode=0o702)
        # umask may clear the fixture bit; explicitly set only this synthetic target.
        self.home.chmod(0o702)
        self.home_patch=patch('ironclad.actions.account_home',return_value=self.home); self.home_patch.start()
        self.store=Store(self.root/'state')
    def tearDown(self):
        self.store.close(); self.home_patch.stop(); self.tmp.cleanup()
    def mode(self): return self.home.stat().st_mode&0o7777
    def test_preview_read_only(self):
        p=actions.preview(actions.ACTION_ID); self.assertEqual(self.mode(),0o702); self.assertEqual(p.after,0o700)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM remediation').fetchone()[0],0)
    def test_apply_and_undo(self):
        p=actions.preview(actions.ACTION_ID); receipt=actions.apply(self.store,p,p.digest()); self.assertEqual(self.mode(),0o700)
        actions.rollback(self.store,receipt); self.assertEqual(self.mode(),0o702)
        with self.assertRaises(ValueError): actions.rollback(self.store,receipt)
    def test_altered_digest(self):
        p=actions.preview(actions.ACTION_ID)
        with self.assertRaises(ValueError): actions.apply(self.store,p,'bad')
        self.assertEqual(self.mode(),0o702)
    def test_altered_args(self):
        p=actions.preview(actions.ACTION_ID); other=replace(p,after=0o777)
        with self.assertRaises(ValueError): actions.apply(self.store,other,p.digest())
        with self.assertRaises(ValueError): actions.apply(self.store,other,other.digest())
    def test_expired(self):
        p=actions.preview(actions.ACTION_ID)
        p=replace(p,created=p.created-121)
        with self.assertRaises(ValueError): actions.apply(self.store,p,p.digest())
    def test_metadata_changed(self):
        p=actions.preview(actions.ACTION_ID); self.home.chmod(0o722)
        with self.assertRaises(ValueError): actions.apply(self.store,p,p.digest())
        self.assertEqual(self.mode(),0o722)
    def test_symlink_swap(self):
        p=actions.preview(actions.ACTION_ID); self.home.rename(self.root/'old'); self.home.symlink_to(self.root/'old',target_is_directory=True)
        with self.assertRaises(OSError): actions.apply(self.store,p,p.digest())
        self.assertEqual((self.root/'old').stat().st_mode&0o777,0o702)
    def test_inode_swap(self):
        p=actions.preview(actions.ACTION_ID); self.home.rename(self.root/'old'); self.home.mkdir(); self.home.chmod(0o702)
        with self.assertRaises(ValueError): actions.apply(self.store,p,p.digest())
    def test_noop_refused(self):
        self.home.chmod(0o700)
        with self.assertRaises(ValueError): actions.preview(actions.ACTION_ID)
    def test_unknown_action(self):
        with self.assertRaises(ValueError): actions.preview('exec.arbitrary')
    def test_replay(self):
        p=actions.preview(actions.ACTION_ID); actions.apply(self.store,p,p.digest())
        with self.assertRaises(ValueError): actions.apply(self.store,p,p.digest())
    def test_stale_undo(self):
        p=actions.preview(actions.ACTION_ID); receipt=actions.apply(self.store,p,p.digest()); self.home.chmod(0o750)
        with self.assertRaises(ValueError): actions.rollback(self.store,receipt)
        self.assertEqual(self.mode(),0o750)
    def test_failed_journal_compensates(self):
        p=actions.preview(actions.ACTION_ID)
        self.store.db.execute("CREATE TRIGGER refuse BEFORE UPDATE ON remediation WHEN NEW.status='applied' BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError): actions.apply(self.store,p,p.digest())
        self.assertEqual(self.mode(),0o702)
        self.assertEqual(self.store.db.execute('SELECT status FROM remediation').fetchone()[0],'failed')
    def test_prepared_recovery(self):
        p=actions.preview(actions.ACTION_ID)
        with self.store.db:
            self.store.db.execute('INSERT INTO remediation VALUES (?,?,?,?,?,?)',('fixture',p.canonical(),'prepared',None,'now',None))
        self.home.chmod(p.after); actions.rollback(self.store,'fixture'); self.assertEqual(self.mode(),0o702)
    def test_cli_apply_requires_terminal(self):
        from io import StringIO
        self.store.close()
        with patch('sys.stdin',StringIO('yes')),patch('sys.stdout',StringIO()),patch('sys.stderr',StringIO()):
            self.assertEqual(main(['--state',str(self.root/'state'),'action','apply',actions.ACTION_ID]),2)
        self.assertEqual(self.mode(),0o702)
