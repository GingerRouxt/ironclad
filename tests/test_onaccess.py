import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from ironclad import onaccess, onaccess_package, onaccess_policy as policy, onaccess_service as helper

class OnAccessTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.state=Path(self.tmp.name)
  self.feed={'schema':1,'version':policy.VERSION,'owner_uid':os.getuid(),'mode':'notify','scope':'Downloads','boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'heartbeat_ns':str(time.monotonic_ns()),'daemon_ready':True,'watcher_ready':True,'stopped':False,'events':[],'scanned':4,'errors':0,'signatures_age_hours':1.5,'database_current':True}
  self.owner={'schema':1,'uid':os.getuid(),'mode':'notify'}
  fake=type('Meta',(),{'st_mode':0o100755,'st_uid':0})()
  self.addCleanup(patch.stopall)
  patch('ironclad.onaccess.os.stat',return_value=fake).start()
  patch('ironclad.onaccess.service',return_value='active').start()
  patch('ironclad.onaccess.root_record',side_effect=lambda p:self.owner if p.name=='owner.json' else self.feed).start()
 def test_acknowledging_multiple_events_and_repeats_persists(self):
  patch.stopall()
  ids=['a'*24,'b'*24]
  data={'events':[{'id':i} for i in ids]}
  with patch('ironclad.onaccess.status',return_value=data):
   for identifier in [*ids,ids[0]]:onaccess.acknowledge(self.state,identifier)
  self.assertEqual(onaccess.review_state(self.state),ids)
  self.assertEqual((self.state/'antimalware-reviewed.json').stat().st_mode & 0o777,0o600)
 def test_ready_is_not_based_on_process_presence_only(self):
  self.assertTrue(onaccess.status()['active'])
  for key in ('daemon_ready','watcher_ready','database_current'):
   self.feed[key]=False;self.assertFalse(onaccess.status()['active']);self.feed[key]=True
  self.feed['heartbeat_ns']='0';self.assertFalse(onaccess.status()['active'])
 def test_wrong_boot_or_stopped_is_degraded(self):
  for key,value in [('boot_id','wrong'),('stopped',True),('errors',1),('signatures_age_hours',169),('signatures_age_hours',None),('signatures_age_hours',float('nan'))]:
   old=self.feed[key];self.feed[key]=value;self.assertFalse(onaccess.status()['active'],key);self.feed[key]=old
 def test_prevention_and_notify_are_distinguished(self):
  self.assertEqual(onaccess.status()['state'],'scanning')
  self.owner['mode']='prevent';self.feed['mode']='prevent'
  v=onaccess.status();self.assertTrue(v['active']);self.assertEqual(v['state'],'protecting');self.assertIn('fail open',v['message'])
 def test_cross_user_and_malformed_event_rejected(self):
  self.owner['uid']=-1;self.assertFalse(onaccess.status()['active']);self.owner['uid']=os.getuid()
  self.feed['events']=[{'id':'a'*24,'name':'x\nforged','detection':'Eicar','time':'today'}];self.assertFalse(onaccess.status()['active'])
  self.feed['events']=[{'id':'a'*24,'name':'x','detection':'Eicar','time':'today','path':'/private'}];self.assertFalse(onaccess.status()['active'])
 def test_stopped_never_inherits_fresh_feed(self):
  with patch('ironclad.onaccess.service',return_value='inactive'):
   self.assertEqual(onaccess.status()['state'],'stopped');self.assertFalse(onaccess.status()['active'])
 def test_plan_is_bound_to_mode_package_and_user(self):
  with patch('ironclad.malware.status',return_value={'ready':True}),patch('ironclad.onaccess_package.build',return_value={'sha256':'a'*64,'path':'/fixture/pkg'}):
   p=onaccess.plan(self.state,'notify');self.assertEqual(p['uid'],os.getuid());self.assertEqual(p['scope'],'Downloads')
   changed=copy.deepcopy(p);changed['action']='prevent'
   with self.assertRaises(ValueError):onaccess.apply(self.state,changed,p['digest'])
   p['created']=0;p['digest']=onaccess.digest(p)
   with self.assertRaises(ValueError):onaccess.apply(self.state,p,p['digest'])
 def test_no_scan_ready_no_service_plan(self):
  with patch('ironclad.malware.status',return_value={'ready':False}),self.assertRaises(ValueError):onaccess.plan(self.state,'notify')
 def test_failed_or_timed_out_auth_does_not_claim_success(self):
  with patch('ironclad.malware.status',return_value={'ready':True}),patch('ironclad.onaccess_package.build',return_value={'path':'/fixture/pkg'}):
   p=onaccess.plan(self.state,'notify')
   for code in (None,1,126):
    with patch('ironclad.sensor.run_privileged',return_value=code) as run,self.assertRaises(ValueError):onaccess.apply(self.state,p,p['digest'])
    self.assertEqual(run.call_count,1)
 def test_package_has_only_namespaced_services(self):
  files=onaccess_package.payload();manifest=json.loads(files['usr/share/ironclad-antimalware/manifest.json'])
  for n,h in manifest['files'].items():self.assertEqual(hashlib.sha256(files[n]).hexdigest(),h)
  self.assertNotIn('usr/lib/systemd/system/clamav-daemon.service',files)
  self.assertIn('PrivateNetwork=true',policy.ENGINE);self.assertIn('ProtectHome=true',policy.ENGINE)
  self.assertIn('User=clamav',policy.ENGINE);self.assertIn('MemoryMax=1536M',policy.ENGINE)
  self.assertNotIn('--move',policy.WATCH);self.assertNotIn('--remove',policy.WATCH)
  self.assertIn('ProtectHome=tmpfs',policy.WATCH)
 def test_event_parser_discards_paths_and_untrusted_lines(self):
  e=helper.event('/home/example/Downloads/fixture.txt: Eicar-Test-Signature FOUND')
  self.assertEqual(e['name'],'fixture.txt');self.assertNotIn('/home',json.dumps(e));self.assertEqual(e['detection'],'Eicar-Test-Signature')
  for s in ('anything', 'x: y ERROR','x: <script> FOUND','x'*9000):self.assertIsNone(helper.event(s))
 def test_config_no_tcp_no_delete_and_root_scanner_excluded(self):
  with patch('ironclad.onaccess_service.pwd.getpwnam',return_value=type('User',(),{'pw_uid':64})()):
   for mode in ('notify','prevent'):
    c=helper.configuration(Path('/home/example/Downloads'),mode)
    self.assertIn('LocalSocketMode 600',c);self.assertNotIn('TCPSocket',c)
    self.assertIn('OnAccessExcludeRootUID yes',c);self.assertIn('OnAccessExcludeUID 64',c)
    self.assertIn('OnAccessDenyOnError no',c);self.assertNotIn('VirusEvent',c)
    self.assertIn('OnAccessPrevention '+('yes' if mode=='prevent' else 'no'),c)
 def test_helper_cli_does_not_accept_other_paths_or_user_code(self):
  for arg in ['enable','/home/foo','run /bin/sh','remove','--help']:
   with patch('sys.argv',['helper',arg]):self.assertEqual(helper.main(),2)

if __name__=='__main__':unittest.main()
