#!/usr/bin/env python3
"""Explicit synthetic-only native automatic/one-off malware acceptance.
No service mutation, user document scan, private contents, deletion or quarantine.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from ironclad import onaccess,malware,sensor
EICAR=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--output',type=Path,default=ROOT/'.local-evidence/onaccess-native-acceptance.json');a=p.parse_args()
 if not a.run:p.error('--run required to approve synthetic fixtures')
 state=Path.home()/'.local/state/ironclad';initial=onaccess.status(state)
 if not initial['active']:raise ValueError('automatic scanner must already be verified')
 guard=[]
 for name in ('codex','quickshell'):
  r=subprocess.run(['pgrep','-x',name],capture_output=True,text=True);guard.extend(int(v) for v in r.stdout.split())
 if not guard:raise ValueError('process guard missing')
 with tempfile.TemporaryDirectory(prefix='ironclad-automatic-test-',dir=Path.home()/'Downloads') as tmp, tempfile.TemporaryDirectory(prefix='outside-scope-',dir=ROOT/'.local-evidence') as outside:
  base=Path(tmp);good=base/'harmless-control.txt';flag=base/('eicar-'+str(time.time_ns())+'.txt');control=Path(outside)/'outside-eicar.txt'
  # Allow native recursive watch registration before file creation.
  time.sleep(2)
  good.write_text('Harmless Ironclad automatic-scanner acceptance fixture.\n');good.chmod(0o600)
  control.write_bytes(EICAR);control.chmod(0o600)
  flag.write_bytes(EICAR);flag.chmod(0o600)
  assert good.read_text().startswith('Harmless') and control.read_bytes()==EICAR
  blocked=False
  try:assert flag.read_bytes()==EICAR
  except PermissionError:blocked=True
  deadline=time.monotonic()+45;automatic=None
  while time.monotonic()<deadline:
   automatic=onaccess.status(state)
   if any(e['name']==flag.name for e in automatic['events']):break
   if not all(Path('/proc',str(pid)).exists() for pid in guard):raise RuntimeError('original process guard failed')
   time.sleep(1)
  found=any(e['name']==flag.name and 'Eicar' in e['detection'] for e in automatic['events'])
  benign_flagged=any(e['name']==good.name for e in automatic['events'])
  outside_flagged=any(e['name']==control.name for e in automatic['events'])
  if initial['mode']=='notify':
   review=malware.plan(state,str(flag));oneoff=malware.scan(state,review,review['digest'])
   clean_review=malware.plan(state,str(good));clean=malware.scan(state,clean_review,clean_review['digest'])
   oneoff_detected=oneoff['outcome']=='detected';oneoff_clean=clean['outcome']=='no_detection'
   unchanged=flag.read_bytes()==EICAR and good.read_text().startswith('Harmless')
  else:
   oneoff_detected=None;oneoff_clean=None;unchanged=flag.exists() and good.exists()
  final=onaccess.status(state);falco=sensor.status(state)
  result={'mode':initial['mode'],'automatic_detection_without_manual_scan':found,'detected_file_access_blocked':blocked,'benign_control_flagged':benign_flagged,'outside_scope_control_flagged':outside_flagged,'oneoff_eicar_detected':oneoff_detected,'oneoff_benign_no_detection':oneoff_clean,'original_fixture_files_preserved':unchanged,'automatic_active_after':final['active'],'scanner_errors':final['errors'],'falco_state':falco['state'],'original_codex_and_shell_alive':all(Path('/proc',str(pid)).exists() for pid in guard)}
  result['passed']=found and not benign_flagged and not outside_flagged and unchanged and final['active'] and not final['errors'] and result['original_codex_and_shell_alive'] and falco['monitoring'] and (blocked if initial['mode']=='prevent' else not blocked and oneoff_detected and oneoff_clean)
  # Acknowledging only these exact test events preserves unrelated detections.
  for e in final['events']:
   if e['name']==flag.name:onaccess.acknowledge(state,e['id'])
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
  return 0 if result['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
