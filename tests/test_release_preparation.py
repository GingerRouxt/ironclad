import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_preparation',ROOT/'tools/prepare_release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)


class ReleasePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.output=Path(self.temp.name)/'candidate'
        self.addCleanup(patch.stopall)
        patch.object(release,'git',side_effect=lambda *args:' M README.md' if args[0]=='status' else 'a'*40).start()

    def test_candidate_is_reproducible_honest_and_checksum_bound(self):
        first=release.prepare(self.output)
        second=release.prepare(self.output)
        self.assertEqual(first,second);self.assertTrue(first['source_dirty']);self.assertFalse(first['publication_performed'])
        archive=first['archive'];self.assertEqual(hashlib.sha256((self.output/archive['name']).read_bytes()).hexdigest(),archive['sha256'])
        saved=json.loads((self.output/'release-manifest.json').read_text());self.assertEqual(saved,first)
        self.assertIn('ui0237/Overview.qml',saved['payload_sha256'])
        self.assertEqual(saved['sensor']['rule_count'],8)
        self.assertFalse(any('.local-evidence' in name or 'MASTER_SPEC' in name for name in saved['payload_sha256']))

    def test_clean_gate_and_tag_mismatch_refuse_before_output(self):
        with self.assertRaises(ValueError):release.prepare(self.output,require_clean=True)
        with self.assertRaises(ValueError):release.prepare(self.output,tag='v0.0.0')
        self.assertFalse(self.output.exists())

    def test_conflicting_and_linked_assets_preserved(self):
        first=release.prepare(self.output);archive=self.output/first['archive']['name'];archive.write_bytes(b'preserve')
        with self.assertRaises(ValueError):release.prepare(self.output)
        self.assertEqual(archive.read_bytes(),b'preserve')
        archive.unlink();target=Path(self.temp.name)/'outside';target.write_bytes(b'private');archive.symlink_to(target)
        with self.assertRaises(ValueError):release.prepare(self.output)
        self.assertEqual(target.read_bytes(),b'private')
