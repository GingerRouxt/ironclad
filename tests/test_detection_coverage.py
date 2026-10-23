"""Behavior matrix over shipped conditions; real Falco compilation is a separate gate."""
import fnmatch
import json
from unittest.mock import patch
import re
import unittest
from ironclad import sensor_policy as policy, sensor_service


class Condition:
    def __init__(self,text,macros):
        self.tokens=re.findall(r'>=|!=|[(),=]|[^\s(),=<>!]+',text);self.pos=0;self.macros=macros
    def take(self):
        value=self.tokens[self.pos];self.pos+=1;return value
    def accept(self,value):
        if self.pos<len(self.tokens) and self.tokens[self.pos]==value:self.pos+=1;return True
        return False
    def parse(self):
        result=self.either()
        if self.pos!=len(self.tokens):raise ValueError('unsupported condition syntax')
        return result
    def either(self):
        left=self.both()
        while self.accept('or'):left=('or',left,self.both())
        return left
    def both(self):
        left=self.atom()
        while self.accept('and'):left=('and',left,self.atom())
        return left
    def atom(self):
        if self.accept('('):
            value=self.either()
            if not self.accept(')'):raise ValueError('missing close')
            return value
        field=self.take()
        if field in self.macros:return self.macros[field]
        op=self.take()
        if op=='in':
            if not self.accept('('):raise ValueError('missing list')
            values=[self.take()]
            while self.accept(','):values.append(self.take())
            if not self.accept(')'):raise ValueError('missing list end')
            return ('in',field,values)
        if op not in ('=','>=','startswith','glob'):raise ValueError('unsupported operator')
        return (op,field,self.take())


def evaluate(node,event):
    op,left,right=node
    if op=='and':return evaluate(left,event) and evaluate(right,event)
    if op=='or':return evaluate(left,event) or evaluate(right,event)
    value=event.get(left)
    if value is None:return False
    if op=='>=':return int(value)>=int(right)
    if op=='in':return str(value) in right
    if op=='glob':return fnmatch.fnmatchcase(str(value),right)
    if op=='startswith':return str(value).startswith(right)
    return str(value).lower()==right.lower()


def compiled():
    macros={};rules={}
    for kind,name,condition in re.findall(r'- (macro|rule): ([^\n]+)\n(?:  desc: [^\n]+\n)?  condition: ([^\n]+)',policy.RULES_YAML):
        target=macros if kind=='macro' else rules
        target[name]=Condition(condition,macros).parse()
    if set(rules)!=set(policy.RULES):raise ValueError('rule not evaluated')
    return rules


class DetectionCoverageTests(unittest.TestCase):
    def test_standalone_helper_accepts_expanded_packaged_policy_and_rejects_bad_metadata(self):
        good={'version':policy.VERSION,'rules':policy.RULES}
        with patch.object(sensor_service,'trusted_file',return_value=json.dumps(good).encode()):
            self.assertEqual(len(sensor_service.policy()['rules']),8)
        for rules in ({},{'same'+str(i):next(iter(policy.RULES.values())) for i in range(33)},{'bad':{'id':'runtime.bad'}},dict(policy.RULES,duplicate=next(iter(policy.RULES.values())))):
            with patch.object(sensor_service,'trusted_file',return_value=json.dumps({'rules':rules}).encode()):
                with self.assertRaises(ValueError):sensor_service.policy()

    def test_behavior_and_legitimate_workload_matrix(self):
        rules=compiled()
        def matches(path,**extra):
            event={'evt.type':'openat','evt.is_open_write':True,'evt.rawres':3,'fd.name':path,**extra}
            return {policy.RULES[name]['id'] for name,node in rules.items() if evaluate(node,event)}
        positives=[('/etc/ld.so.preload','runtime.preload'),('/etc/systemd/system/demo.service','runtime.startup'),('/etc/cron.d/demo','runtime.startup'),('/etc/pam.d/demo','runtime.authentication'),('/etc/sudoers','runtime.authentication'),('/home/demo/.config/systemd/user/demo.service','runtime.user_startup'),('/home/demo/.config/autostart/demo.desktop','runtime.user_startup'),('/etc/audit/auditd.conf','runtime.audit_policy'),('/etc/audit/audit.rules','runtime.audit_policy'),('/etc/audit/rules.d/demo.rules','runtime.audit_policy'),('/etc/passwd','runtime.accounts'),('/etc/shadow','runtime.accounts'),('/etc/group','runtime.accounts'),('/etc/gshadow','runtime.accounts')]
        for path,expected in positives:
            with self.subTest(path=path):
                self.assertEqual(matches(path),{expected})
                self.assertEqual(matches('',**{'evt.type':'krsi_open','krsi.name':path,'krsi.write_open':1}),{expected})
                self.assertEqual(matches('',**{'evt.type':'krsi_open','krsi.name':path,'krsi.write_open':0}),set())
                self.assertEqual(matches(path,**{'evt.is_open_write':False}),set(),'Reading the same policy is not a write')
                self.assertEqual(matches(path,**{'evt.rawres':-1}),set(),'Failed opens do not establish a policy write')
        # Builds, downloads, normal settings and adjacent directory names must not trigger these rules.
        for path in ('/home/demo/Work/app/build/main.o','/home/demo/Downloads/file','/tmp/demo.service','/home/demo/.cache/python/module.pyc','/home/demo/.config/app/settings.json','/home/demo/.config/autostart/readme.txt','/etc/systemd/systematic/demo','/etc/audit/rules.d.backup/demo','/var/log/audit/audit.log','/tmp/shadow','/etc/ssh/ssh_config'):
            with self.subTest(legitimate=path):self.assertEqual(matches(path),set())
        self.assertEqual(matches('',**{'evt.type':'execve','proc.is_exe_from_memfd':True}),{'runtime.memory_execution'})
        self.assertEqual(matches('',**{'evt.type':'execve','proc.is_exe_from_memfd':False}),set())
        self.assertEqual(matches('',**{'evt.type':'init_module','evt.rawres':0}),{'runtime.kernel_module'})
        self.assertEqual(matches('',**{'evt.type':'init_module','evt.rawres':-1}),set())

    def test_all_categories_survive_private_bridge_without_raw_paths_or_arguments(self):
        for name,rule in policy.RULES.items():
            event={'rule':name,'time':'2026-10-22T12:00:00Z','output_fields':{'proc.name':'fixture','evt.type':'openat','proc.cmdline':'PRIVATE-ARGS','fd.name':'PRIVATE-PATH'}}
            data=sensor_service.sanitize_event(event,policy.RULES,'a'*16+':1')
            self.assertEqual(data['rule_id'],rule['id'])
            self.assertNotIn('PRIVATE',str(data))
        self.assertEqual(len(policy.RULES),8)
        self.assertNotIn('%proc.cmdline',policy.RULES_YAML)
        self.assertNotIn('%fd.name',policy.RULES_YAML)

    def test_new_policy_changes_are_review_signals_not_malware_verdicts(self):
        for key in ('ZDS User startup changed','ZDS Audit policy changed','ZDS Account database changed'):
            text=' '.join(policy.RULES[key][field] for field in ('meaning','action'))
            self.assertRegex(text,'normal|legitimate|administrator')
