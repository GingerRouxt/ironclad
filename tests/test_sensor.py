"""Sensor trust and health checks use synthetic feeds; never enable host services."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import unittest
import urllib.request
from unittest.mock import patch
from ironclad import sensor, sensor_policy as policy, sensor_service as service, sensor_package as package


class SensorTests(unittest.TestCase):
    def test_calibration_socket_keeps_network_and_resource_restrictions(self):
        self.assertIn('RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n',policy.SERVICE)
        self.assertIn('IPAddressDeny=any\n',policy.SERVICE)
        self.assertIn('MemoryMax=512M\n',policy.SERVICE)
        self.assertIn('CPUQuota=25%\n',policy.SERVICE)
        self.assertIn('TasksMax=64\n',policy.SERVICE)

    def test_download_redirect_only_allows_exact_official_cdn_hop(self):
        handler=package.SensorRedirect()
        request=urllib.request.Request(policy.ARCHIVE_URL)
        cdn=policy.ARCHIVE_URL.replace('https://download.falco.org/', 'https://d20hasrqv82i0q.cloudfront.net/')
        self.assertEqual(handler.redirect_request(request,None,307,'',{},cdn).full_url,cdn)
        for destination in ('http://'+cdn[8:],cdn+'?extra=1',cdn.replace('cloudfront.net','example.org'),cdn+'/other'):
            with self.assertRaises(ValueError):handler.redirect_request(request,None,307,'',{},destination)
        with self.assertRaises(ValueError):handler.redirect_request(urllib.request.Request(cdn),None,307,'',{},cdn)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name)/'state'
        self.addCleanup(patch.stopall)
        patch.object(sensor,'installed',return_value=True).start()
        patch.object(sensor,'service_state',return_value='active').start()
        patch.object(sensor,'compatibility',return_value={'supported':True}).start()
        self.feed={'schema':1,'policy_version':policy.VERSION,'owner_uid':os.getuid(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   'heartbeat_ns':str(time.monotonic_ns()),'metric_ns':str(time.monotonic_ns()),'stopped':False,
                   'events':[],'metrics':{'events':'200','kernel_drops':'0','output_drops':'0','async_reader':'1','async_events':'3','async_errors':'0','async_emitted':'3','async_pending':'0'}}
        patch.object(sensor,'read_root',side_effect=lambda path,*args:{'uid':os.getuid()} if path.name=='owner.json' else self.feed).start()
    def test_installed_component_mismatch_offers_bundled_update(self):
        import hashlib
        component={'version':policy.VERSION,'engine_version':policy.FALCO_VERSION,'engine_sha256':policy.ENGINE_SHA,'krsi_sha256':policy.KRSI_SHA,'rules_sha256':hashlib.sha256(policy.RULES_YAML.encode()).hexdigest()}
        sensor.read_root.side_effect=lambda path,*args: component if path.name=='policy.json' else {'uid':os.getuid()} if path.name=='owner.json' else self.feed
        self.assertFalse(sensor.status(self.state)['update_available'])
        component['version']='old'
        result=sensor.status(self.state)
        self.assertTrue(result['update_available']);self.assertEqual(result['installed_policy_version'],'old')
        self.assertTrue(result['monitoring'])

    def event(self):
        return service.sanitize_event({'rule':'ZDS Runtime preload changed','source':'syscall','time':'2026-10-22T12:00:00Z',
          'output':'SECRET command','output_fields':{'proc.name':'demo','evt.type':'openat','proc.cmdline':'SECRET','fd.name':'/private/secret'}},policy.RULES,'a'*16+':1')
    def test_bridge_retains_only_allowlisted_fields(self):
        row=self.event();self.assertEqual(set(row),{'id','rule_id','severity','time','app','event'})
        self.assertNotIn('SECRET',json.dumps(row));self.assertNotIn('/private',json.dumps(row))
        unknown=service.sanitize_event({'rule':'ZDS User startup changed','time':'2026-10-22T12:00:00Z','output_fields':{'proc.name':None,'evt.type':'krsi_open'}},policy.RULES,'a'*16+':2')
        self.assertEqual(unknown['app'],'unidentified application')
        self.assertEqual(unknown['event'],'krsi_open')
        for data in (None,{}, {'rule':'unknown'}, {'rule':'ZDS Runtime preload changed','time':'invalid'}):self.assertIsNone(service.sanitize_event(data,policy.RULES,'a'*16+':1'))
    def test_metrics_require_real_engine_and_all_counter_types(self):
        row={'rule':'Falco internal: metrics snapshot','output_fields':{'scap.engine_name':'modern_ebpf','scap.n_evts':1,'scap.n_drops':0,'falco.outputs_queue_num_drops':0,'plugins.krsi.ironclad_async_reader_alive':1,'plugins.krsi.ironclad_async_events':3,'plugins.krsi.ironclad_async_errors':0,'plugins.krsi.ironclad_async_emitted':3,'plugins.krsi.ironclad_async_pending':0,'host.ip':'SECRET'}}
        self.assertEqual(service.metrics(row),{'events':'1','kernel_drops':'0','output_drops':'0','async_reader':'1','async_events':'3','async_errors':'0','async_emitted':'3','async_pending':'0'})
        row['output_fields']['scap.n_drops']=True;self.assertIsNone(service.metrics(row))
        row['output_fields']['scap.n_drops']=0;row['output_fields']['scap.engine_name']='replay';self.assertIsNone(service.metrics(row))
    def test_verified_health_then_stale_dropped_and_stopped(self):
        self.assertTrue(sensor.status(self.state)['monitoring'])
        self.feed['metric_ns']='0';self.assertFalse(sensor.status(self.state)['monitoring'])
        self.feed['metric_ns']=str(time.monotonic_ns());self.feed['metrics']['kernel_drops']='2'
        self.assertEqual(sensor.status(self.state)['state'],'degraded')
        with patch.object(sensor,'service_state',return_value='inactive'):
            result=sensor.status(self.state);self.assertFalse(result['monitoring']);self.assertEqual(result['state'],'stopped')
    def test_async_reader_failure_and_processing_errors_never_show_healthy(self):
        for key,value in [('async_reader','0'),('async_errors','1'),('async_pending','1'),('async_emitted','2')]:
            original=copy.deepcopy(self.feed);self.feed['metrics'][key]=value
            self.assertEqual(sensor.status(self.state)['state'],'degraded');self.feed=original
        for value in (None,True,'2'):
            self.feed['metrics']['async_reader']=value
            self.assertFalse(sensor.status(self.state)['monitoring'])
        self.feed['metrics'].pop('async_reader')
        self.assertFalse(sensor.status(self.state)['monitoring'])

    def test_bundled_async_component_rejects_archive_and_library_tampering(self):
        import hashlib
        self.assertIn('usr/lib/ironclad/libkrsi.so',package.krsi_payload())
        with patch.object(policy,'KRSI_ARCHIVE_SHA','0'*64):
            with self.assertRaises(ValueError):package.krsi_payload()
        with patch.object(policy,'KRSI_SHA','0'*64):
            with self.assertRaises(ValueError):package.krsi_payload()
        bodies={service.ENGINE:b'engine',service.KRSI:b'plugin',service.CONFIG:b'config',service.ASSETS/'rules.yaml':b'rules'}
        metadata={key:hashlib.sha256(body).hexdigest() for key,body in [('engine_sha256',b'engine'),('krsi_sha256',b'plugin'),('config_sha256',b'config'),('rules_sha256',b'rules')]}
        with patch.object(service,'root_dir',side_effect=lambda _:os.open('/',os.O_RDONLY)),patch.object(service,'policy',return_value=metadata),patch.object(service,'trusted_file',side_effect=lambda path,*_:bodies[path]):
            self.assertEqual(service.verify_install(),metadata)
            bodies[service.KRSI]=b'changed'
            with self.assertRaisesRegex(ValueError,'async sensor component changed'):service.verify_install()

    def test_boot_policy_and_ownership_must_match(self):
        for key,value in [('boot_id','previous'),('policy_version','old'),('stopped',True),('owner_uid',-1)]:
            original=copy.deepcopy(self.feed);self.feed[key]=value
            self.assertFalse(sensor.status(self.state)['monitoring']);self.feed=original
    def test_alert_review_is_local_acknowledgement_not_remediation(self):
        self.feed['events']=[self.event()]
        result=sensor.status(self.state);self.assertEqual(result['unreviewed'],1);self.assertEqual(result['alerts'][0]['rule_id'],'runtime.preload')
        result=sensor.acknowledge(self.state,self.event()['id']);self.assertEqual(result['unreviewed'],0)
        self.assertTrue(result['alerts'][0]['reviewed']);self.assertNotIn('resolved',result['alerts'][0])
        self.assertEqual((self.state/'sensor-reviewed.json').stat().st_mode&0o777,0o600)
        with self.assertRaises(ValueError):sensor.acknowledge(self.state,'b'*16+':2')
    def test_malformed_and_duplicate_alerts_never_show_green(self):
        self.feed['events']=[self.event(),self.event()];self.assertFalse(sensor.status(self.state)['monitoring'])
        self.feed['events']=[dict(self.event(),time='unparseable')];self.assertFalse(sensor.status(self.state)['monitoring'])
    def test_review_binding_expiry_mutation_and_fixed_commands(self):
        component={'path':'/fixture/component','sha256':'a'*64}
        with patch.object(package,'build',return_value=component),patch.object(sensor,'run_privileged',return_value=0) as privileged:
            plan=sensor.plan(self.state,'enable',True)
            for changed in (dict(plan,created=0),dict(plan,action='shell'),dict(plan,uid='0')):
                with self.assertRaises(ValueError):sensor.apply(self.state,changed,plan['digest'])
            privileged.assert_not_called()
            result=sensor.apply(self.state,plan,plan['digest']);self.assertTrue(result['verified'])
            self.assertEqual(privileged.call_args_list[0].args[0],['/usr/bin/pacman','-U','--noconfirm','--','/fixture/component'])
            self.assertEqual(privileged.call_args_list[1].args[0],[policy.HELPER,'enable'])
    def test_failed_authorization_never_claims_success(self):
        with patch.object(package,'build',return_value={'path':'/fixture/component'}),patch.object(sensor,'run_privileged',return_value=126):
            plan=sensor.plan(self.state,'enable',True);self.assertFalse(sensor.apply(self.state,plan,plan['digest'])['verified'])
    def test_successful_control_process_cannot_hide_async_backlog(self):
        with patch.object(package,'build',return_value={'path':'/fixture/component'}),patch.object(sensor,'run_privileged',return_value=0):
            plan=sensor.plan(self.state,'enable',True)
            self.feed['metrics']['async_pending']='1'
            self.assertFalse(sensor.apply(self.state,plan,plan['digest'])['verified'])

    def test_root_helper_rejects_unsafe_paths_and_commands(self):
        with self.assertRaises(ValueError):service.root_dir(self.temp.name)
        with self.assertRaises(ValueError):service.command(['/bin/sh','-c','false'])
        with patch.dict(os.environ,{'PKEXEC_UID':'0'}):
            with self.assertRaises(ValueError):service.caller()
        with patch.object(service,'ROOT_UID',os.getuid()):
            path=Path(self.temp.name)/'file';path.write_text('fixture');path.chmod(0o600)
            self.assertEqual(service.trusted_file(path),b'fixture');path.chmod(0o622)
            with self.assertRaises(ValueError):service.trusted_file(path)
    def test_unenabled_component_can_be_stopped_for_removal(self):
        with patch.object(service,'caller',return_value=1000),patch.object(service,'owner',side_effect=FileNotFoundError),patch.object(service,'command',side_effect=[(0,''),(3,'inactive'),(1,'disabled')]) as command:
            self.assertTrue(service.manage('disable')['verified'])
            self.assertEqual(command.call_args_list[0].args[0],['/usr/bin/systemctl','disable','--now',policy.UNIT])
    def test_private_package_cache_refuses_links_and_wrong_hash(self):
        path=package.directory(self.state)/policy.ARCHIVE_URL.rsplit('/',1)[1];path.write_bytes(b'wrong');path.chmod(0o600)
        with self.assertRaises(ValueError):package.archive(self.state,False)
        link=path.parent/'linked';link.symlink_to(path)
        with self.assertRaises(OSError):package.read_private(link)
    def test_package_rebuild_detects_tampering(self):
        files={'usr/lib/ironclad/falco':b'fixture','usr/lib/ironclad/sensor-helper':b'fixture'}
        with patch.object(package,'archive',return_value=b'fixture'),patch.object(package,'payload',return_value=files):
            first=package.build(self.state);self.assertEqual(first,package.build(self.state))
            path=Path(first['path'])
            body=subprocess.check_output(['/usr/bin/zstd','-q','-d','-c',str(path)])
            with tarfile.open(fileobj=io.BytesIO(body)) as archive:
                self.assertTrue(all(m.uid==0 and m.gid==0 and not m.issym() for m in archive.getmembers()))
                self.assertIn(b'pkgname = ironclad-sensor',archive.extractfile('.PKGINFO').read())
            path.write_bytes(b'tampered')
            with self.assertRaises(ValueError):package.build(self.state)


class EmbeddedScannerTests(unittest.TestCase):
    def test_install_uses_os_authentication_and_verifies_readiness(self):
        from ironclad import malware
        with patch('ironclad.maintenance.trusted',side_effect=lambda v:v),patch.object(malware.subprocess,'Popen') as process,patch.object(malware,'status',return_value={'installed':True,'ready':False}):
            process.return_value.wait.return_value=0
            self.assertFalse(malware.install_scanner('/fixture')['ready'])
            self.assertEqual(process.call_args.args[0],['/usr/bin/pkexec','/usr/bin/pacman','-S','--needed','--noconfirm','--','clamav','bubblewrap'])
            self.assertEqual(process.call_args.kwargs['stdout'],subprocess.DEVNULL)
            process.return_value.wait.return_value=126
            with self.assertRaises(ValueError):malware.install_scanner('/fixture')

class SupervisorTests(unittest.TestCase):
    def test_real_fixture_engine_is_stopped_and_private_output_is_filtered(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);engine=base/'engine';snapshot=base/'snapshot.json'
            engine.write_text("#!/usr/bin/python3\nimport json,time\n"+
              "print(json.dumps("+repr({'rule':'ZDS Runtime preload changed','time':'2026-10-22T12:00:00Z','output_fields':{'proc.name':'demo','evt.type':'openat','proc.cmdline':'SECRET'}})+"),flush=True)\n"+
              "print(json.dumps("+repr({'rule':'Falco internal: metrics snapshot','output_fields':{'scap.engine_name':'modern_ebpf','scap.n_evts':20,'scap.n_drops':0,'falco.outputs_queue_num_drops':0,'plugins.krsi.ironclad_async_reader_alive':1,'plugins.krsi.ironclad_async_events':3,'plugins.krsi.ironclad_async_errors':0,'plugins.krsi.ironclad_async_emitted':3,'plugins.krsi.ironclad_async_pending':0}})+"),flush=True)\ntime.sleep(30)\n")
            engine.chmod(0o700)
            runner=base/'run.py';runner.write_text("from pathlib import Path\nimport json,os,sys\nsys.path.insert(0,"+repr(str(Path(__file__).resolve().parents[1]))+")\nfrom ironclad import sensor_service as s,sensor_policy as p\ns.BASE=Path("+repr(str(base))+ ")\ns.ENGINE=Path("+repr(str(engine))+")\ns.verify_install=lambda:dict(version=p.VERSION,rules=p.RULES)\ns.owner=lambda:os.getuid()\ns.prepare_owner=lambda uid:None\ndef atomic(name,data,uid=None):\n path=Path("+repr(str(snapshot))+")\n temporary=path.with_suffix('.tmp');temporary.write_text(json.dumps(data));temporary.chmod(0o600);temporary.replace(path)\ns.atomic=atomic\nraise SystemExit(s.run())\n")
            child=subprocess.Popen(['/usr/bin/python3','-I','-B',str(runner)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                deadline=time.monotonic()+6;data={}
                while time.monotonic()<deadline:
                    if snapshot.exists():
                        data=json.loads(snapshot.read_text())
                        if data.get('metrics') and data.get('events'):break
                    time.sleep(.05)
                self.assertEqual(data['metrics']['events'],'20');self.assertEqual(len(data['events']),1)
                self.assertNotIn('SECRET',snapshot.read_text());self.assertEqual(data['policy_version'],policy.VERSION)
                child.terminate();self.assertEqual(child.wait(timeout=5),0)
                self.assertTrue(json.loads(snapshot.read_text())['stopped'])
            finally:
                if child.poll() is None:child.kill();child.wait()
