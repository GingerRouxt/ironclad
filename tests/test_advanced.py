from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ironclad import advanced
from ironclad.model import validate_scan
from test_engine import sample


class AdvancedTests(unittest.TestCase):
    def test_scope_is_explicit_and_no_source_read(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'pyproject.toml').write_text('token=synthetic-must-not-read')
            c=advanced.workspace(p)
            self.assertIn('pyproject.toml',c.evidence[0].value); self.assertNotIn('synthetic-must-not-read',c.evidence[0].value)
    def test_scope_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'link'; p.symlink_to(d,target_is_directory=True)
            with self.assertRaises(ValueError): advanced.workspace(p)
    def test_partial_kernel_values(self):
        with patch('ironclad.advanced.read',side_effect=PermissionError()):
            self.assertEqual(advanced.kernel_posture().status,'unavailable')
    def test_no_false_disabled_lsm(self):
        with patch('ironclad.advanced.read',side_effect=PermissionError()):
            self.assertEqual(advanced.lsm().status,'unavailable')
    def test_malformed_cached_contract(self):
        for bad in (None,{}, {'schema_version':'1.0'}, {**sample(),'checks':[{'check_id':'test.bad'}]}):
            with self.assertRaises(ValueError): validate_scan(bad)
    def test_url_scheme_rejected(self):
        s=sample(); s['checks'][0]['documentation_url']='javascript:evil()'
        with self.assertRaises(ValueError): validate_scan(s)
    def test_numeric_summary_rejected(self):
        s=sample(); s['checks'][0]['summary']=123
        with self.assertRaises(ValueError): validate_scan(s)
    def test_huge_evidence_rejected(self):
        s=sample(); s['checks'][0]['evidence'][0]['value']='x'*2049
        with self.assertRaises(ValueError): validate_scan(s)
    def test_nan_duration_rejected(self):
        s=sample(); s['checks'][0]['elapsed_ms']=float('nan')
        with self.assertRaises(ValueError): validate_scan(s)
    def test_unknown_smart_not_hardware_failure(self):
        c=advanced.firmware_support(); self.assertNotIn('failure',c.summary)

    def test_stable_id_when_probe_fails(self):
        from ironclad import collectors
        with patch('ironclad.collectors.os_check',side_effect=PermissionError()):
            result=collectors.scan('quick')
        self.assertEqual(result['checks'][0]['check_id'],'system.os')
        self.assertEqual(result['checks'][0]['status'],'unavailable')
    def test_budget_preserves_check_coverage(self):
        from ironclad import collectors
        with patch('ironclad.collectors.time.monotonic',side_effect=[0]+[20]*200):
            result=collectors.scan('full')
        self.assertEqual(len(result['checks']),180)
        self.assertTrue(all(c['status']=='unavailable' for c in result['checks']))
