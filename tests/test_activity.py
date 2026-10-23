from pathlib import Path
import json
import os
import tempfile
import unittest
from ironclad.activity import history
from ironclad.storage import export, private_dir
from ironclad.collectors import failed_units


class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)/'state'

    def write(self, folder, name, body):
        dest = self.state/folder
        os.close(private_dir(dest))
        export(dest/name, json.dumps(body))
        return dest/name

    def test_empty_history_does_not_create_state(self):
        self.assertEqual(history(self.state), {'entries':[], 'limits':[]})
        self.assertFalse(self.state.exists())

    def test_update_versions_recovery_and_recorded_verification(self):
        plan = {'name':'node', 'target':'mise:node', 'installed':'24.0', 'recovery':'Restore the reviewed version.'}
        self.write('maintenance','1-started.json', {'started_at':'2026-10-22T10:00:00+00:00', 'plan':plan})
        self.write('maintenance','1-finished.json', {'finished_at':'2026-10-22T10:01:00+00:00', 'verified':True, 'observed_versions':['24.1'], 'verification_scope':'Version observed; compatibility is not certified.'})
        row = history(self.state)['entries'][0]
        self.assertEqual(row['outcome'], 'verified')
        self.assertEqual(row['target'], 'mise:node')
        self.assertIn('24.0', row['versions']); self.assertIn('24.1', row['versions'])
        self.assertEqual(row['recovery'], plan['recovery'])
        self.assertIn('not certified', row['detail'])

    def test_repair_without_scan_history_and_missing_completion(self):
        ticket = 'a'*32
        plan = {'title':'Retry demo service', 'target':'demo.service', 'check_id':'startup.units.user_failed', 'created':1792670000, 'undo':'Restart effects cannot be undone.'}
        self.write('repairs',ticket+'.request.json', {'plan':plan})
        row = history(self.state)['entries'][0]
        self.assertEqual(row['outcome'], 'incomplete'); self.assertTrue(row['at'])
        self.assertIn('may be running or interrupted', row['detail'])
        self.write('repairs',ticket+'.result.json', {'verified':False, 'applied':True, 'message':'Service restarted but its result could not be verified.', 'finished_at':'2026-10-22T11:00:00+00:00'})
        row = history(self.state)['entries'][0]
        self.assertEqual(row['outcome'], 'unverified')
        self.assertEqual(row['check_id'], plan['check_id'])
        self.assertIn('could not be verified', row['detail'])

    def test_failed_update_is_not_success_and_interrupted_orphan_is_visible(self):
        self.write('maintenance', '1-finished.json', {'verified':False, 'target':'uv tool:demo', 'reason':'interrupted_or_unavailable', 'finished_at':'2026-10-22T11:00:00+00:00'})
        row = history(self.state)['entries'][0]
        self.assertEqual(row['outcome'], 'unverified'); self.assertIn('interrupted', row['detail'])
        self.assertEqual(row['target'], 'uv tool:demo')

    def test_symlink_fifo_hardlink_shared_and_malformed_receipts_are_skipped(self):
        dest=self.state/'maintenance';os.close(private_dir(dest))
        victim=Path(self.temp.name)/'private';victim.write_text('{"verified":true}')
        (dest/'1-finished.json').symlink_to(victim)
        os.link(victim,dest/'2-finished.json')
        os.mkfifo(dest/'3-finished.json',0o600)
        (dest/'4-finished.json').write_text('not json');(dest/'4-finished.json').chmod(0o600)
        self.write('maintenance','5-finished.json',{'verified':True}).chmod(0o644)
        result=history(self.state)
        self.assertEqual(result['entries'],[]);self.assertTrue(result['limits'])
        self.assertEqual(victim.read_text(),'{"verified":true}')

    def test_linked_directory_refused(self):
        self.state.mkdir();(self.state/'maintenance').symlink_to(self.temp.name,target_is_directory=True)
        result=history(self.state)
        self.assertEqual(result['entries'],[]);self.assertTrue(result['limits'])

    def test_newest_records_bounded_and_older_files_retained(self):
        for i in range(70):
            self.write('maintenance',str(i)+'-finished.json',{'verified':True, 'target':'mise:demo', 'finished_at':f'2026-10-22T11:{i//60:02d}:{i%60:02d}+00:00'})
        result=history(self.state)
        self.assertEqual(len(result['entries']),64)
        self.assertEqual(result['entries'][0]['id'],'update:69')
        self.assertEqual(len(list((self.state/'maintenance').iterdir())),70)
        self.assertTrue(result['limits'])

    def test_service_context_omits_custom_names_descriptions_and_instances(self):
        check=failed_units('systemd-pcrlogin@1000.service loaded failed failed private description\nprivate-project.service loaded failed failed secret\n', 'startup.units.system_failed','fixture')
        evidence=str(check.dict())
        self.assertIn('systemd-pcrlogin@.service',evidence)
        self.assertNotIn('1000',evidence);self.assertNotIn('private-project',evidence);self.assertNotIn('secret',evidence)
        self.assertIn('2 failed units',check.summary)
