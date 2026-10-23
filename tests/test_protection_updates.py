import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ironclad import protection_updates as updates
from ironclad.model import now


class ProtectionUpdatesTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.state=self.home/'state';self.units=self.home/'units'
        self.addCleanup(patch.stopall)
        patch.object(updates,'unit_directory',return_value=self.units).start()
        patch.object(updates,'PLUGIN',self.home/'plugin').start()
        patch.object(updates,'conflicts',return_value=False).start()
        patch.object(updates,'control',return_value='LoadState=loaded\nActiveState=active\nUnitFileState=enabled').start()
        patch('ironclad.maintenance.capture',return_value='ClamAV 1.5.4/123').start()

    def test_packaged_templates_match_runtime_and_no_install_commands(self):
        root=Path(__file__).resolve().parents[1]
        for name,body in updates.UNITS.items():
            self.assertEqual((root/'packaging/systemd-user'/name).read_text(),body)
        self.assertIn('CPUQuota=20%',updates.SERVICE)
        self.assertIn('MemoryMax=1G',updates.SERVICE)
        self.assertNotIn('pkexec',updates.SERVICE)
        self.assertNotIn('pacman',updates.SERVICE)
        self.assertIn('Persistent=true',updates.TIMER)

    def test_read_only_status_missing_state_is_not_healthy(self):
        result=updates.status(self.state)
        self.assertTrue(result['issues']);self.assertIsNone(result['last_success'])
        self.assertFalse(result['plugin_managed']);self.assertIn('no published',result['plugin_update'])
        self.assertFalse(self.state.exists())

    def test_no_network_without_authorization(self):
        with patch.object(updates,'release_version') as fetch,patch('ironclad.malware.update_signatures') as refresh:
            with self.assertRaises(ValueError):updates.maintain(self.state,False)
            fetch.assert_not_called();refresh.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_success_persists_and_engine_checks_daily_only(self):
        with patch.object(updates,'release_version',side_effect=['1.5.5','0.45.2']) as fetch,patch('ironclad.malware.update_signatures') as refresh:
            first=updates.maintain(self.state,True);second=updates.maintain(self.state,True)
        self.assertEqual(first['outcome'],'ok');self.assertEqual(second['releases'],first['releases'])
        self.assertEqual(fetch.call_count,2);self.assertEqual(refresh.call_count,2)
        refresh.assert_called_with(self.state,True,_locked=True)
        self.assertEqual((self.state/updates.NAME).stat().st_mode&0o777,0o600)
        result=updates.status(self.state)
        self.assertTrue(all(row['update_available'] for row in result['engines']))
        self.assertTrue(any('newer upstream' in issue for issue in result['issues']))

    def test_failure_preserves_last_success_and_releases(self):
        prior={'schema':1,'outcome':'ok','attempted_at':now(),'signature_success_at':now(),'release_checked_at':'2020-01-01T00:00:00+00:00','releases':{'falco':'0.45.1','clamav':'1.5.4'}}
        updates.write(self.state,prior)
        with patch.object(updates,'release_version',side_effect=OSError),patch('ironclad.malware.update_signatures',side_effect=ValueError):
            result=updates.maintain(self.state,True)
        self.assertEqual(result['outcome'],'failed');self.assertEqual(result['signature_success_at'],prior['signature_success_at'])
        self.assertEqual(result['releases'],prior['releases'])
        self.assertTrue(any('last protection update failed' in issue for issue in updates.status(self.state)['issues']))

    def test_interrupted_and_future_timestamps_do_not_claim_success(self):
        updates.write(self.state,{'schema':1,'outcome':'running','attempted_at':now(),'signature_success_at':'2099-01-01T00:00:00+00:00'})
        result=updates.status(self.state)
        self.assertTrue(any('interrupted' in i for i in result['issues']))
        self.assertTrue(any('24 hours' in i for i in result['issues']))

    def test_symlink_and_corrupt_records_refused(self):
        self.state.mkdir(mode=0o700);target=self.home/'target';target.write_text('do not change')
        record=self.state/updates.NAME;record.symlink_to(target)
        with self.assertRaises(OSError):updates.read(self.state)
        self.assertTrue(updates.status(self.state)['issues']);self.assertEqual(target.read_text(),'do not change')
        record.unlink();record.write_text('{}');record.chmod(0o600)
        with self.assertRaises(ValueError):updates.read(self.state)

    def test_service_failure_visible_even_when_previous_record_succeeded(self):
        updates.write(self.state,{'schema':1,'outcome':'ok','attempted_at':now(),'signature_success_at':now(),'release_checked_at':now()})
        updates.control.side_effect=['LoadState=loaded\nActiveState=active\nUnitFileState=enabled','Result=exit-code\nExecMainStatus=2']
        self.assertTrue(any('maintenance service failed' in issue for issue in updates.status(self.state)['issues']))

    def test_shared_lock_prevents_concurrent_updaters(self):
        with updates.signature_lock(self.state):
            with self.assertRaises(BlockingIOError):
                with updates.signature_lock(self.state):pass

    def test_enable_disable_only_owned_units_and_retains_state(self):
        (updates.PLUGIN).mkdir();(updates.PLUGIN/'companion.py').touch()
        with patch('ironclad.protection_updates.Path.home',return_value=self.home):updates.configure(True)
        for name,body in updates.UNITS.items():
            self.assertEqual((self.units/name).read_text(),body)
            self.assertEqual((self.units/name).stat().st_mode&0o777,0o600)
        updates.control.assert_any_call('enable','--now',updates.TIMER_NAME)
        updates.configure(False)
        self.assertFalse(any(self.units.iterdir()));self.assertTrue((self.home/'.local/state/ironclad').is_dir())

    def test_modified_unit_refuses_all_changes(self):
        self.units.mkdir();bad=self.units/updates.SERVICE_NAME;bad.write_text('foreign content');bad.chmod(0o600)
        with self.assertRaises(ValueError):updates.configure(False)
        self.assertEqual(bad.read_text(),'foreign content');updates.control.assert_not_called()

    def test_activation_failure_rolls_back_created_units(self):
        updates.PLUGIN.mkdir();(updates.PLUGIN/'companion.py').touch()
        updates.control.side_effect=[None,ValueError('failed'),None,None]
        with patch('ironclad.protection_updates.Path.home',return_value=self.home):
            with self.assertRaises(ValueError):updates.configure(True)
        self.assertFalse(any(self.units.iterdir()))

    def test_untrusted_release_metadata_refused(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):return json.dumps({'tag_name':self.tag,'draft':False,'prerelease':False}).encode()
        response=Response()
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.return_value=response
            for tag in ('v0.45.2','1.5.4'):
                response.tag=tag;self.assertEqual(updates.release_version('falcosecurity/falco'),tag.removeprefix('v'))
            response.tag='clamav-1.5.4';self.assertEqual(updates.release_version('Cisco-Talos/clamav'),'1.5.4')
            with self.assertRaises(ValueError):updates.release_version('falcosecurity/falco')
            for tag in ('v0.45.2-rc1','https://evil/engine','1.2'):
                response.tag=tag
                with self.assertRaises(ValueError):updates.release_version('falcosecurity/falco')
            with self.assertRaises(ValueError):updates.release_version('evil/repo')
