"""Rule consent, filtering and transactional activation; no host service changes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ironclad import falco_rules as rules, rule_service as service, rule_updates, sensor_service, sensor

SOURCE=b'''- required_engine_version: 0.57.0
- macro: in_container
  condition: container.id != host
- macro: indirect
  condition: in_container and proc.name=bash
- rule: Host fixture
  desc: host fixture
  condition: evt.type=execve and proc.name=bash
  output: private %proc.cmdline %fd.name
  priority: WARNING
- rule: Container fixture
  condition: indirect
  output: private %proc.cmdline
  priority: WARNING
- rule: Disabled fixture
  condition: evt.type=execve
  output: private
  priority: WARNING
  enabled: false
'''


def candidate():
    body,catalog,skipped=rules.prepare(SOURCE)
    return body,dict(schema=1,channel='falco-rules:5',catalog=catalog,excluded_count=len(skipped),
                     rules_sha256=hashlib.sha256(body).hexdigest(),source_sha256=hashlib.sha256(SOURCE).hexdigest())


class RuleTests(unittest.TestCase):
    def test_only_supported_host_rules_with_minimal_output(self):
        body,catalog,skipped=rules.prepare(SOURCE)
        self.assertEqual(list(catalog),['Host fixture'])
        self.assertEqual(len(skipped),2)
        for forbidden in (b'cmdline',b'fd.name',b'container.',b'indirect',b'private'):
            self.assertNotIn(forbidden,body)
        self.assertIn(b'%proc.name',body)

    def test_unsafe_yaml_and_directives_fail_closed(self):
        for body in (b'!!python/object/apply:os.system [true]',b'- &a [*a]',b'{}',
                     SOURCE.replace(b'  enabled: false',b'  append: true'),SOURCE.replace(b'Host fixture',b'<script>')):
            with self.subTest(body=body[:60]),self.assertRaises((ValueError,__import__('yaml').YAMLError)):
                rules.prepare(body)

    def test_unknown_rule_source_does_not_gain_host_coverage(self):
        body=SOURCE.replace(b'  desc: host fixture',b'  source: cloudtrail')
        with self.assertRaises(ValueError):rules.prepare(body)

    def test_catalog_rejects_bad_identity_and_hashes(self):
        _,data=candidate();self.assertEqual(service.validate(data),data)
        for key,value in (('channel','latest'),('rules_sha256','../bad'),('excluded_count',True)):
            bad=copy.deepcopy(data);bad[key]=value
            with self.assertRaises(ValueError):service.validate(bad)
        bad=copy.deepcopy(data);bad['catalog']['Host fixture']['id']='runtime.startup'
        with self.assertRaises(ValueError):service.validate(bad)

    def test_upstream_alert_roundtrip_drops_sensitive_fields(self):
        _,data=candidate()
        raw={'rule':'Host fixture','source':'syscall','time':'2026-10-26T00:00:00Z',
             'output_fields':{'proc.name':'bash','evt.type':'execve','proc.cmdline':'SECRET','fd.name':'PRIVATE'}}
        event=sensor_service.sanitize_event(raw,data['catalog'],'a'*16+':1')
        parsed=sensor.parse_feed({'schema':1,'events':[event]})
        self.assertEqual(parsed[0]['title'],'Host fixture')
        self.assertNotIn('SECRET',json.dumps(parsed));self.assertNotIn('PRIVATE',json.dumps(parsed))
        event['title']='Other rule'
        with self.assertRaises(ValueError):sensor.parse_feed({'schema':1,'events':[event]})

    def test_separate_network_consent_required_before_privilege(self):
        with patch('ironclad.maintenance.trusted') as trusted,patch.object(rule_updates.subprocess,'run') as run:
            with self.assertRaises(ValueError):rule_updates.configure(True,False)
            trusted.assert_not_called();run.assert_not_called()

    def test_timer_does_not_enable_itself_and_worker_is_constrained(self):
        self.assertNotIn('WantedBy',rule_updates.SERVICE)
        args=service.sandbox(Path('/fixture'))
        for value in ('--unshare-all','--cap-drop','--clearenv','--unshare-user','--uid','65534'):self.assertIn(value,args)
        self.assertNotIn('/home',args);self.assertNotIn('--no-verify',Path(rules.__file__).read_text())
        self.assertIn('ignore-tlog: false',rules.INDEX)
        self.assertIn('^https://github[.]com/falcosecurity/rules/',rules.INDEX)

    def test_unconsented_update_does_not_download_or_restart(self):
        with patch.object(service,'RELEASE_READY',True),patch.object(service,'read',return_value=b'{"enabled":false}'),patch.object(service,'sandbox') as sandbox,patch.object(service,'control') as control:
            with self.assertRaises(ValueError):service.update()
            sandbox.assert_not_called();control.assert_not_called()

    def test_unreleased_updater_cannot_be_enabled_even_with_network_consent(self):
        self.assertFalse(service.RELEASE_READY)
        with patch('ironclad.maintenance.trusted') as trusted:
            with self.assertRaises(ValueError):rule_updates.configure(True,True)
            with self.assertRaises(ValueError):service.update()
            trusted.assert_not_called()
        status=rule_updates.status()
        self.assertFalse(status['available']);self.assertFalse(status['enabled'])

    def test_symlink_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'data').write_text('{}');(root/'link').symlink_to(root/'data')
            with self.assertRaises(OSError):service.read(root/'link',uid=os.getuid())

    def transaction(self,failed):
        body,data=candidate()
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);(base/'consent.json').write_text('{"enabled":true}')
            original=service.read
            def read(path,limit=65536,uid=0):return original(path,limit,os.getuid())
            def stage(work):
                (work/'result.json').write_text(json.dumps(data));(work/'host-rules.yaml').write_bytes(body)
                return ['fixture']
            with patch.object(service,'RELEASE_READY',True),patch.object(service,'BASE',base),patch.object(service,'directory'),patch.object(service,'read',side_effect=read),patch.object(service.os,'chown'),patch.object(service,'running',return_value=True),patch.object(service,'sandbox',side_effect=stage),patch.object(service.subprocess,'run') as run,patch.object(service,'control') as control,patch.object(service,'health') as health:
                run.return_value.returncode=0
                if failed:health.side_effect=[ValueError('bad health'),None]
                if failed:
                    with self.assertRaises(ValueError):service.update()
                else:service.update()
                self.assertFalse((base/'pending.json').exists())
                active=json.loads((base/'active.json').read_text())
                self.assertEqual(active,None if failed else data)
                self.assertEqual(control.call_count,2 if failed else 1)
                record=json.loads((base/'status.json').read_text())
                self.assertEqual(record['state'],'failed' if failed else 'ok')
                if failed:self.assertTrue(record['rollback_ok'])

    def test_activation_records_success_after_health(self):self.transaction(False)
    def test_failed_health_restores_previous_selection(self):self.transaction(True)


if __name__=='__main__':unittest.main()
