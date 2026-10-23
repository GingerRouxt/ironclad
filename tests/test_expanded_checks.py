import copy
import gzip
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from ironclad import check_catalog as catalog,collectors,expanded_checks as probes
from ironclad.model import validate_scan
from ironclad.runner import Result

class ExpandedChecksTests(unittest.TestCase):
 def rule(self,kind,target):return next(r for r in catalog.RULES if r.kind==kind and r.target==target)
 def test_catalog_has_distinct_controls_and_nested_profiles(self):
  self.assertEqual(len({r.id for r in catalog.RULES}),386)
  self.assertEqual(len({(r.kind,r.target) for r in catalog.RULES}),386)
  q={r.id for r in catalog.selected('quick')};f={r.id for r in catalog.selected('full')};s={r.id for r in catalog.selected('super')}
  self.assertLess(q,f);self.assertLess(f,s)
  self.assertEqual([len(q)+20,len(f)+34,len(s)+34],[90,180,420])
  for r in catalog.RULES:
   self.assertGreater(len(r.reason),30);self.assertTrue(r.doc.startswith('https://'));self.assertLess(len(r.id),101)
 def test_runtime_cpu_reports_distinguish_partial_and_unknown(self):
  r=self.rule('cpu_mitigation','spectre_v2')
  for raw,status in [('Not affected','pass'),('Mitigation: Retpolines','pass'),('Mitigation: Retpolines; SMT vulnerable','attention'),('Vulnerable: no mitigation','attention'),('unexpected future format','unavailable')]:
   with patch('ironclad.expanded_checks.read',return_value=raw):self.assertEqual(probes.evaluate(r,probes.Context()).status,status)
 def test_numeric_policy_boundaries(self):
  for policy,good,bad in [('eq:1',1,0),('ge:2',2,1),('le:0',0,1),('mask:176',176,255)]:
   self.assertTrue(probes.predicate(policy,good));self.assertFalse(probes.predicate(policy,bad))
  with self.assertRaises(ValueError):probes.predicate('eq:1','1')
 def test_sysctl_evidence_reflects_real_predicate(self):
  rule=self.rule('sysctl','kernel/kptr_restrict')
  for value,state in [('2','pass'),('0','attention')]:
   with patch('ironclad.expanded_checks.read',return_value=value):
    c=probes.evaluate(rule,probes.Context());self.assertEqual(c.status,state);self.assertIn('value='+value,c.evidence[0].value)
  with patch('ironclad.expanded_checks.read',return_value='$(execute)'):
   with self.assertRaises(ValueError):probes.evaluate(rule,probes.Context())
 def test_readonly_observation_never_becomes_a_policy_pass(self):
  r=self.rule('sysctl','vm/swappiness')
  with patch('ironclad.expanded_checks.read',return_value='60'):
   self.assertEqual(probes.evaluate(r,probes.Context()).status,'observed')
 def test_kernel_build_never_implies_active_enforcement(self):
  r=self.rule('kconfig','SECURITY_APPARMOR');context=probes.Context()
  for value in ['y','m','n']:
   with patch.object(context,'config',return_value={r.target:value}):
    c=probes.evaluate(r,context);self.assertEqual(c.status,'observed');self.assertIn('not_established',c.evidence[0].value)
  with patch.object(context,'config',return_value={}):self.assertEqual(probes.evaluate(r,context).status,'not_applicable')
  with patch.object(context,'config',return_value=None):self.assertEqual(probes.evaluate(r,context).status,'unavailable')
 def test_supported_core_kernel_build_controls_flag_disabled_support(self):
  r=self.rule('kconfig','FORTIFY_SOURCE');context=probes.Context()
  for value,status in [('y','pass'),('n','attention')]:
   with patch.object(context,'config',return_value={r.target:value}):self.assertEqual(probes.evaluate(r,context).status,status)
 def test_kernel_config_loader_bounded_and_filters_string_values(self):
  compressed=gzip.compress(b'CONFIG_FORTIFY_SOURCE=y\n# CONFIG_SECURITY_APPARMOR is not set\nCONFIG_CMDLINE="private must not enter evidence"\n')
  # Exercise the actual compressed-data parser through a synthetic fd.
  with tempfile.TemporaryFile() as f:
   f.write(compressed);f.flush();f.seek(0)
   fd=os.dup(f.fileno())
   meta=type('Meta',(),{'st_uid':0,'st_mode':0o100444})()
   with patch('ironclad.expanded_checks.os.open',return_value=fd),patch('ironclad.expanded_checks.os.fstat',return_value=meta):
    c=probes.Context();self.assertEqual(c.config(),{'FORTIFY_SOURCE':'y','SECURITY_APPARMOR':'n'});self.assertIs(c.config(),c.cache['config'])
 def test_service_absent_inactive_and_unknown_are_not_passes(self):
  r=self.rule('service','sshd.service/NoNewPrivileges');context=probes.Context()
  for values,status in [({'LoadState':'not-found'},'not_applicable'),({'LoadState':'loaded','ActiveState':'inactive'},'not_applicable'),({'LoadState':'loaded','ActiveState':'active'},'unavailable'),(None,'unavailable')]:
   with patch.object(context,'service',return_value=values):self.assertEqual(probes.evaluate(r,context).status,status)
 def test_service_exact_property_and_no_private_list_leak(self):
  context=probes.Context();values={'LoadState':'loaded','ActiveState':'active','NoNewPrivileges':'yes','SystemCallFilter':'~@danger /home/secret/argument'}
  with patch.object(context,'service',return_value=values):
   self.assertEqual(probes.evaluate(self.rule('service','sshd.service/NoNewPrivileges'),context).status,'pass')
   c=probes.evaluate(self.rule('service','sshd.service/SystemCallFilter'),context)
   self.assertEqual(c.status,'observed');self.assertNotIn('secret',json.dumps(c.dict()))
   values['NoNewPrivileges']='no';self.assertEqual(probes.evaluate(self.rule('service','sshd.service/NoNewPrivileges'),context).status,'attention')
   values['NoNewPrivileges']='unknown'
   with self.assertRaises(ValueError):probes.evaluate(self.rule('service','sshd.service/NoNewPrivileges'),context)
 def test_service_queried_once_and_untrusted_fields_not_exported(self):
  with patch('ironclad.expanded_checks.run',return_value=Result('available','LoadState=loaded\nActiveState=active\nNoNewPrivileges=yes\n')) as run:
   context=probes.Context();context.service('sshd.service');context.service('sshd.service');self.assertEqual(run.call_count,1)
 def test_mount_uses_most_specific_and_last_overmount(self):
  context=probes.Context();r=self.rule('mount','/tmp/noexec')
  with patch.object(context,'mounts',return_value=[('/',{'noexec'}),('/tmp',set()),('/tmp',{'noexec'})]):self.assertEqual(probes.evaluate(r,context).status,'pass')
  with patch.object(context,'mounts',return_value=[('/',{'noexec'}),('/tmp',set())]):self.assertEqual(probes.evaluate(r,context).status,'attention')
 def test_port_exposure_is_protocol_specific_and_omits_addresses(self):
  context=probes.Context();rows=[('tcp',22,True),('udp',22,False),('tcp',445,False)]
  with patch.object(context,'listeners',return_value=rows):
   self.assertEqual(probes.evaluate(self.rule('listener','tcp/22'),context).status,'pass')
   c=probes.evaluate(self.rule('listener','tcp/445'),context);self.assertEqual(c.status,'attention');self.assertIn('reachability',c.recommendation)
 def test_loopback_and_specific_address_parser(self):
  sample='tcp LISTEN 0 10 127.0.0.1:22 0.0.0.0:*\ntcp LISTEN 0 10 [::1]:53 [::]:*\nudp UNCONN 0 0 10.2.3.4:53 0.0.0.0:*\n'
  with patch('ironclad.expanded_checks.run',return_value=Result('available',sample)):
   self.assertEqual(probes.Context().listeners(),[('tcp',22,True),('tcp',53,True),('udp',53,False)])
 def test_sensitive_metadata_reads_no_contents(self):
  meta=type('Meta',(),{'st_uid':0,'st_mode':0o100644})()
  r=self.rule('metadata','/etc/shadow')
  with patch('ironclad.expanded_checks.os.stat',return_value=meta),patch('builtins.open',side_effect=AssertionError('no contents')):
   self.assertEqual(probes.evaluate(r,probes.Context()).status,'attention')
 def test_profile_rejects_unknown_and_keeps_missing_data_unknown(self):
  with self.assertRaises(ValueError):collectors.scan('anything')
  with patch('ironclad.expanded_checks.read',side_effect=PermissionError()):
   q=collectors.scan('quick')
  self.assertEqual(len(q['checks']),90)
  self.assertTrue(all(c['status']=='unavailable' for c in q['checks'] if c['check_id'].startswith('sysctl.')))
 def test_protection_health_is_bounded_and_cached_without_elevation(self):
  value={'continuous_monitoring':True,'sensor':{'state':'monitoring'},'automatic_malware':{'active':True,'state':'scanning','mode':'notify'},'scanner':{'ready':True,'signatures_age_hours':1},'updates':{'automatic':True,'issues':[]}}
  with tempfile.TemporaryDirectory() as state,patch('ironclad.maintenance.capture',return_value=json.dumps(value)) as capture:
   context=probes.Context(state)
   for rule in catalog.RULES:
    if rule.kind=='protection':self.assertEqual(probes.evaluate(rule,context).status,'pass')
   self.assertEqual(capture.call_count,1);self.assertEqual(capture.call_args.kwargs['timeout'],2)
   self.assertNotIn('pkexec',capture.call_args.args[0]);self.assertNotIn('sudo',capture.call_args.args[0])
  with patch('ironclad.maintenance.capture',side_effect=ValueError('timeout')):
   self.assertEqual(probes.evaluate(self.rule('protection','falco'),probes.Context()).status,'unavailable')
 def test_large_scan_ai_includes_every_check_in_risk_order(self):
  from ironclad import advisor
  snapshot={'collected_at':'2026-10-23T00:00:00Z','checks':[{'check_id':f'test.control{i}','status':'observed','severity':'info','summary':'A recorded configuration fact','remediation_steps':['Review this exact control.'],'verification':'Repeat the check.'} for i in range(420)]}
  snapshot['checks'][-1].update(status='critical',severity='high',summary='Synthetic risk at end of list')
  self.assertEqual(len(advisor.ordered_checks(snapshot)),420)
  self.assertEqual(advisor.ordered_checks(snapshot)[0]['check_id'],'test.control419')
  text=advisor.brief(snapshot,{'items':[],'limits':[],'fresh':False},'What matters?')
  self.assertIn('All 420 checks',text);self.assertIn('Synthetic risk at end',text);self.assertLess(len(text),524288)
 def test_super_contract_serializes_reports_without_overflow(self):
  with tempfile.TemporaryDirectory() as state:
   result=collectors.scan('super',state=state)
  self.assertEqual(len(result['checks']),420);self.assertLess(result['elapsed_ms'],11000);validate_scan(result)
  self.assertEqual({c['check_id'] for c in result['checks']},{r['id'] for r in catalog.inventory()['checks']})
  from ironclad.reports import render
  for fmt in ('json','html','markdown'):self.assertGreater(len(render(result,fmt)),10000)
  bad=copy.deepcopy(result);bad['checks']=bad['checks']*2
  with self.assertRaises(ValueError):validate_scan(bad)

if __name__=='__main__':unittest.main()
