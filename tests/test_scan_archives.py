import gzip
import json
import os
from pathlib import Path
import tempfile
import unittest
from ironclad.scan_archives import archive
from test_engine import sample

class ScanArchiveTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.state=Path(self.temp.name)/'state'
 def test_previous_scan_and_ai_are_preserved_private_and_idempotent(self):
  scan=sample();key=scan['checks'][0]['check_id'];explanations={key:{'check_id':key,'meaning':'Synthetic finding','action':'Review','verification':'Repeat'}}
  result=archive(self.state,scan,explanations);path=self.state/'scan-archives'/result['file']
  body=json.loads(gzip.decompress(path.read_bytes()))
  self.assertEqual(body['scan'],scan);self.assertEqual(body['explanations'],explanations)
  self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertEqual(path.parent.stat().st_mode&0o777,0o700)
  self.assertEqual(archive(self.state,scan,explanations),result)
  self.assertEqual(len(list(path.parent.glob('*.gz'))),1)
 def test_changed_same_id_creates_another_archive_without_overwrite(self):
  scan=sample();first=archive(self.state,scan);scan['checks'][0]['summary']='Changed result'
  second=archive(self.state,scan);self.assertNotEqual(first['file'],second['file'])
  self.assertEqual(len(list((self.state/'scan-archives').glob('*.gz'))),2)
 def test_symlink_directory_refused(self):
  self.state.mkdir(mode=0o700);target=Path(self.temp.name)/'other';target.mkdir()
  (self.state/'scan-archives').symlink_to(target,target_is_directory=True)
  with self.assertRaises(OSError):archive(self.state,sample())
  self.assertEqual(list(target.iterdir()),[])
 def test_conflicting_archive_not_overwritten(self):
  scan=sample();first=archive(self.state,scan);path=self.state/'scan-archives'/first['file'];path.write_bytes(b'preserve this conflict')
  with self.assertRaises((OSError,ValueError)):archive(self.state,scan)
  self.assertEqual(path.read_bytes(),b'preserve this conflict')
 def test_linked_archive_not_accepted(self):
  scan=sample();first=archive(self.state,scan);path=self.state/'scan-archives'/first['file'];os.link(path,path.with_suffix('.linked'))
  with self.assertRaises(ValueError):archive(self.state,scan)
 def test_foreign_and_oversized_ai_rows_rejected(self):
  scan=sample();key=scan['checks'][0]['check_id']
  for rows in ({'other':{'check_id':'other'}},{key:{'check_id':key,'meaning':'x'*601,'action':'Review','verification':'Repeat'}}):
   with self.assertRaises(ValueError):archive(self.state,scan,rows)
 def test_invalid_scan_does_not_create_archive_storage(self):
  scan=sample();scan['scan_id']='../../unsafe'
  with self.assertRaises(ValueError):archive(self.state,scan)
  self.assertFalse(self.state.exists())

if __name__=='__main__':unittest.main()
