import copy
import json
from pathlib import Path
import tempfile
import unittest
from ironclad.finding_preferences import apply, NAME
from ironclad.model import Check, Evidence


class FindingPreferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name)/'state'
        self.check=Check('system.failed','attention','medium','Platform service failed',[Evidence('systemd','systemd-pcrproduct.service')]).dict()

    def request(self,action='status',checks=None):
        return apply(self.state,{'action':action,'check_id':self.check['check_id'],'checks':checks if checks is not None else [self.check]})

    def test_status_does_not_create_storage(self):
        self.assertEqual(self.request()['ignored'],[])
        self.assertFalse(self.state.exists())

    def test_ignore_survives_reload_and_timestamp_change_then_restore(self):
        original=copy.deepcopy(self.check)
        self.assertEqual(self.request('ignore')['ignored'],['system.failed'])
        self.assertEqual(self.request()['ignored'],['system.failed'])
        self.check['evidence'][0]['observed_at']='2026-10-22T10:00:00+00:00'
        self.check['elapsed_ms']=200
        self.assertEqual(self.request()['ignored'],['system.failed'])
        self.assertEqual(self.request('restore')['ignored'],[])
        self.assertEqual(original['status'],self.check['status'])
        self.assertEqual((self.state/NAME).stat().st_mode&0o777,0o600)
        self.assertEqual(self.state.stat().st_mode&0o777,0o700)

    def test_new_evidence_or_severity_resurfaces_ignored_category(self):
        self.request('ignore')
        for key,value in [('severity','high'),('status','critical')]:
            check=copy.deepcopy(self.check);check[key]=value
            self.assertEqual(self.request(checks=[check])['ignored'],[])
        check=copy.deepcopy(self.check);check['evidence'][0]['value']='systemd-pcrproduct.service; NetworkManager.service'
        self.assertEqual(self.request(checks=[check])['ignored'],[])

    def test_every_classification_can_be_ignored_without_changing_the_scan(self):
        for status in ('pass','attention','critical','unavailable','error','not_applicable'):
            self.check['status']=status
            before=copy.deepcopy(self.check)
            self.assertEqual(self.request('ignore')['ignored'],['system.failed'])
            self.assertEqual(self.check,before)

    def test_corrupt_or_linked_state_fails_instead_of_hiding_findings(self):
        self.request('ignore');path=self.state/NAME
        path.write_text(json.dumps({'schema':1,'ignored':{'system.failed':'bad'}}))
        with self.assertRaises(ValueError):self.request()
        path.unlink();target=Path(self.temp.name)/'target';target.write_text('untouched')
        path.symlink_to(target)
        with self.assertRaises(OSError):self.request('ignore')
        self.assertEqual(target.read_text(),'untouched')

    def test_unknown_action_missing_target_and_malformed_check_are_rejected(self):
        with self.assertRaises(ValueError):self.request('shell')
        with self.assertRaises(ValueError):self.request('ignore',[])
        check=copy.deepcopy(self.check);check['check_id']='../../etc/tpm'
        with self.assertRaises(ValueError):self.request(checks=[check])


if __name__=='__main__':
    unittest.main()
