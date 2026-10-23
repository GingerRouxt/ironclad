"""Installation audit regressions use only a disposable plugin installation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class InstalledAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        package=load('fixture_package','packaging/manage.py')
        self.destination=package.install(Path(self.temporary.name)/'config')
        self.audit=load('fixture_installed_audit','tools/verify_installed.py').audit

    def test_extra_bookkeeping_cannot_pass_even_with_a_matching_receipt_hash(self):
        self.assertTrue(self.audit(self.destination)['passed'])
        body=b'fixture bookkeeping'
        (self.destination/'STATUS.md').write_bytes(body)
        path=self.destination/'.ironclad-install.json';receipt=json.loads(path.read_text())
        receipt['files']['STATUS.md']=hashlib.sha256(body).hexdigest();path.write_text(json.dumps(receipt))
        result=self.audit(self.destination)
        self.assertFalse(result['passed'])
        self.assertFalse(result['receipt_allowlist_matches'])
        self.assertEqual(result['extra_files'],['STATUS.md'])

    def test_modified_and_missing_payload_are_reported(self):
        (self.destination/'README.md').write_text('changed fixture')
        (self.destination/'LICENSE').unlink()
        result=self.audit(self.destination)
        self.assertFalse(result['passed'])
        self.assertEqual(result['missing_files'],['LICENSE'])
        self.assertIn('README.md',result['changed_files'])
        self.assertIn('README.md',result['source_mismatch'])


if __name__=='__main__':
    unittest.main()
