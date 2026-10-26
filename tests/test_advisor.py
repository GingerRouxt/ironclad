from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from ironclad import advisor, maintenance


class AdvisorTests(unittest.TestCase):
    def snapshot(self):
        return {'collected_at': '2026-10-21T00:00:00Z', 'checks': [{'check_id': 'performance.memory', 'status': 'attention', 'summary': 'Memory pressure', 'remediation_steps': ['Close an unused app.'], 'verification': 'Rescan.'}]}

    def software(self):
        return {'items': [{'name': 'node', 'installed': '24', 'available': '24.1', 'status': 'update available', 'advisories': []}], 'fresh': False, 'limits': ['Interpreter CVEs are not covered.']}

    def test_software_priority_brief_includes_exploitation_evidence_and_coverage(self):
        data=self.software()
        data['items'][0]['advisories']=[{'id':'CVE-2026-12345','known_exploited':True,'summary':'Example advisory.'}]
        data.update(advisory_status='available',kev_status='unavailable',advisory_details_status='partial')
        text=advisor.brief(self.snapshot(),data,'Which software risk first?')
        self.assertIn('CVE-2026-12345 [known exploited]',text)
        self.assertIn('CISA catalog: unavailable',text)
        self.assertIn('advisory details: partial',text)
        self.assertIn('cannot execute or approve changes',text)

    def test_reference_sources_and_exact_rules_reach_question_brief(self):
        from ironclad.protection_reference import SOURCES, REVIEWED
        from ironclad import sensor_policy
        text=advisor.brief(self.snapshot(),self.software(),'Can you draft a Falco rule for startup changes?')
        for url in SOURCES.values():self.assertIn(url,text)
        self.assertIn(REVIEWED,text);self.assertIn('not a live web lookup',text)
        self.assertIn(sensor_policy.RULES_YAML,text)
        self.assertIn('no custom-rule editor',text)
        self.assertIn('false positives',text)
        self.assertIn('not supplied',text)
        self.assertLess(len(text),60000)

    def test_references_are_offline_and_match_visible_links(self):
        from ironclad.protection_reference import context, SOURCES
        with patch('urllib.request.build_opener',side_effect=AssertionError('no network')):
            text=context('Explain malware signatures')
        self.assertNotIn('BUNDLED POLICY YAML',text)
        for filename,keys in [('Protection.qml',('clamav_docs','clamav_signatures')),('Monitoring.qml',('falco_docs','falco_help'))]:
            source=(Path(__file__).resolve().parents[1]/'ui0237'/filename).read_text()
            for key in keys:self.assertIn(SOURCES[key],source)

    def test_local_protection_context_excludes_file_and_alert_details(self):
        from ironclad.protection_reference import local_status
        data={'scanner':{'installed':True,'ready':True,'signatures_age_hours':2},'updates':{'automatic':False,'last_success':None,'issues':['Refresh needed'],'engines':[],'policy_version':'fixture','plugin_managed':False},'sensor':{'state':'stopped'},'continuous_monitoring':False,'last_scan':{'name':'PRIVATE-FILE'},'alerts':[{'app':'PRIVATE-APP'}]}
        with patch('ironclad.protection.status',return_value=data):text=local_status('/fixture')
        self.assertNotIn('PRIVATE',text);self.assertIn('"automatic_updates": false',text)
        prompt=advisor.brief(self.snapshot(),self.software(),'Am I protected?',text)
        self.assertIn(text,prompt)
        with patch('ironclad.protection.status',side_effect=ValueError):self.assertIn('unavailable',local_status('/fixture'))

    def test_brief_has_steps_coverage_and_no_action_authority(self):
        text = advisor.brief(self.snapshot(), self.software(), 'Explain token=abc123')
        self.assertIn('Close an unused app.', text)
        self.assertIn('Verify: Rescan.', text)
        self.assertIn('Interpreter CVEs are not covered.', text)
        self.assertIn('not fresh', text)
        self.assertIn('cannot execute or approve', text)
        self.assertNotIn('abc123', text)

    def test_provider_command_disables_tools_and_extensions_without_bare_auth_mode(self):
        args = advisor.command('claude', '/usr/bin/claude', '/fixture/answer')
        self.assertIn('--safe-mode', args)
        self.assertIn('--restricted', args)
        self.assertEqual(args[args.index('--tools')+1], '')
        self.assertIn('--strict-mcp-config', args)
        self.assertEqual(args[args.index('--mcp-config')+1], '{"mcpServers":{}}')
        self.assertIn('--no-session-persistence', args)
        self.assertNotIn('--bare', args)  # Bare mode would break subscription OAuth.
        self.assertFalse(any('skip-permissions' in a for a in args))

    def test_declined_send_never_starts_agent(self):
        with patch('ironclad.maintenance.scan_snapshot', return_value=self.snapshot()), patch('ironclad.maintenance.software_snapshot', return_value=self.software()), patch('ironclad.maintenance.confirm', side_effect=ValueError()), patch('ironclad.advisor.ask') as ask, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(maintenance.main(['ask']), 2)
            ask.assert_not_called()

    def test_question_brief_uses_selected_scan_and_its_evidence_not_a_new_quick_scan(self):
        from test_engine import sample
        snapshot=sample();snapshot['checks'][0]['evidence'][0]['value']='synthetic selected super-scan evidence'
        output=StringIO()
        with patch('sys.stdin',StringIO(json.dumps({'question':'Explain this check','scan':snapshot})+'\n')),patch('ironclad.maintenance.scan_snapshot') as fresh,patch('ironclad.maintenance.software_snapshot',return_value=self.software()),patch('ironclad.protection_reference.local_status',return_value='fixture protection'),redirect_stdout(output):
            self.assertEqual(maintenance.main(['brief','--json','--input-question']),0)
        fresh.assert_not_called();self.assertIn('synthetic selected super-scan evidence',json.loads(output.getvalue())['brief'])

    def test_preparing_brief_is_offline_and_never_starts_agent(self):
        output = StringIO()
        with patch('ironclad.maintenance.scan_snapshot', return_value=self.snapshot()), patch('ironclad.maintenance.software_snapshot', return_value=self.software()), patch('ironclad.advisor.ask') as ask, redirect_stdout(output):
            self.assertEqual(maintenance.main(['brief', '--json']), 0)
            self.assertIn('Question:', json.loads(output.getvalue())['brief'])
            ask.assert_not_called()

    def test_exact_reviewed_brief_sent_not_a_second_scan(self):
        prompt = advisor.brief(self.snapshot(), self.software(), 'Explain')
        output = StringIO()
        with patch('sys.stdin', StringIO(json.dumps({'brief': prompt})+'\n')), patch('ironclad.advisor.ask', return_value={'answer': 'Advice', 'provider': 'Codex'}) as ask, patch('ironclad.maintenance.scan_snapshot') as scan, redirect_stdout(output):
            self.assertEqual(maintenance.main(['ask', '--send', '--json', '--input-brief']), 0)
            ask.assert_called_once_with(prompt)
            scan.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['answer'], 'Advice')

    def test_malformed_reviewed_brief_is_refused(self):
        for value in [[], {'brief': 'Run a shell script'}, {'brief': advisor.SYSTEM+'x'*524289}]:
            with patch('sys.stdin', StringIO(json.dumps(value)+'\n')), patch('ironclad.advisor.ask') as ask, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(maintenance.main(['ask', '--send', '--input-brief']), 2)
                ask.assert_not_called()

    def test_question_can_arrive_on_stdin_without_process_arguments(self):
        output = StringIO()
        with patch('sys.stdin', StringIO('{"question":"What needs attention?"}\n')), patch('ironclad.maintenance.scan_snapshot', return_value=self.snapshot()), patch('ironclad.maintenance.software_snapshot', return_value=self.software()), redirect_stdout(output):
            self.assertEqual(maintenance.main(['brief', '--json', '--input-question']), 0)
            self.assertIn('What needs attention?', json.loads(output.getvalue())['brief'])

    def test_output_strips_escape_sequences_and_control_bytes(self):
        self.assertEqual(advisor.clean_answer('\x1b[31mAdvice\x1b[0m\x07\x7f'), 'Advice')
        self.assertEqual(advisor.clean_answer('\x1b]0;evil title\x07Advice'), 'Advice')

    def test_real_fixture_child_receives_stdin_and_returns_bounded_answer(self):
        fixture = [sys.executable, '-c', 'import sys; s=sys.stdin.read(); print("Received " + str(len(s)))']
        with patch('ironclad.advisor.detect_agent', return_value=('claude', '/fixture')), patch('ironclad.advisor.command', return_value=fixture):
            self.assertEqual(advisor.ask('hello')['answer'].strip(), 'Received 5')

    def test_fixture_child_failure_timeout_and_excess_output(self):
        for code in ['raise SystemExit(1)', 'import time; time.sleep(10)', 'print("x"*140000)']:
            with patch('ironclad.advisor.detect_agent', return_value=('claude', '/fixture')), patch('ironclad.advisor.command', return_value=[sys.executable, '-c', code]):
                with self.assertRaises(ValueError):
                    advisor.ask('hello', timeout=.1)

    def test_unprotected_executable_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'claude'
            path.write_text('not executed')
            path.chmod(0o777)
            with self.assertRaises(ValueError):
                advisor.safe_executable(path)

    def test_codex_command_uses_existing_auth_with_restricted_advice_settings(self):
        args = advisor.command('codex', '/usr/bin/codex', '/fixture/answer')
        self.assertIn('--ignore-user-config', args)
        self.assertIn('--ignore-rules', args)
        self.assertEqual(args[args.index('--sandbox')+1], 'read-only')
        self.assertIn('--ephemeral', args)
        self.assertIn('shell_tool', args)
        self.assertIn('hooks', args)
        self.assertIn('apps', args)
        self.assertIn('plugins', args)
        self.assertIn('web_search="disabled"', args)
        self.assertEqual(args[-3:], ['--output-last-message', '/fixture/answer', '-'])
        self.assertFalse(any('dangerously' in a for a in args))

    def test_detect_uses_signed_in_agent_and_skips_unsigned_or_missing_clients(self):
        with patch('ironclad.advisor.agent_executable', side_effect=lambda n: '/fixture/'+n), patch('ironclad.advisor.signed_in', side_effect=[False, True]):
            self.assertEqual(advisor.detect_agent(), ('claude', '/fixture/claude'))
        with patch('ironclad.advisor.agent_executable', return_value='/fixture/codex'), patch('ironclad.advisor.signed_in', return_value=True) as status:
            self.assertEqual(advisor.detect_agent()[0], 'codex')
            self.assertEqual(status.call_count, 1)
        with patch('ironclad.advisor.agent_executable', side_effect=OSError()):
            with self.assertRaises(ValueError):
                advisor.detect_agent()

    def test_agent_status_exposes_name_not_account_or_credentials(self):
        output = StringIO()
        with patch('ironclad.advisor.detect_agent', return_value=('codex', '/private/executable')), redirect_stdout(output):
            self.assertEqual(maintenance.main(['agent-status', '--json']), 0)
        self.assertEqual(json.loads(output.getvalue()), {'available': True, 'agent': 'Codex'})

    def test_codex_fixture_returns_only_final_answer(self):
        def fixture(name, path, answer_path):
            return [sys.executable, '-c', 'import pathlib,sys; sys.stdin.read(); print("Diagnostic noise"); pathlib.Path(sys.argv[1]).write_text("Final advice")', str(answer_path)]
        with patch('ironclad.advisor.detect_agent', return_value=('codex', '/fixture')), patch('ironclad.advisor.command', side_effect=fixture):
            self.assertEqual(advisor.ask('hello'), {'answer': 'Final advice', 'provider': 'Codex'})

    def explanation_snapshot(self):
        snapshot = self.snapshot()
        snapshot['scan_id'] = 'fixture-scan'
        snapshot['checks'][0]['evidence'] = [{'source':'pressure','value':'Some memory stalls'}]
        return snapshot

    def test_fresh_plain_explanation_generated_on_every_request(self):
        row = {'check_id':'performance.memory','meaning':'Apps are waiting for memory.','action':'You can close unused apps after saving.','verification':'Scan again and compare memory pressure.'}
        answer = {'provider':'Fixture agent','answer':json.dumps({'explanations':[row]})}
        with patch('ironclad.advisor.ask',return_value=answer) as ask:
            first = advisor.explain_findings(self.explanation_snapshot())
            second = advisor.explain_findings(self.explanation_snapshot())
        self.assertEqual(ask.call_count,2)
        self.assertEqual(first['explanations'][0],row)
        self.assertEqual(second['scan_id'],'fixture-scan')
        prompt = ask.call_args.args[0]
        self.assertIn('Some memory stalls',prompt)
        self.assertIn('https://falco.org/docs/',prompt)
        self.assertIn('https://docs.clamav.net/manual/Usage.html',prompt)
        self.assertIn('cannot execute or approve',prompt)

    def test_every_check_is_explained_with_verified_stream_progress(self):
        snapshot=self.explanation_snapshot()
        row=snapshot['checks'][0]
        snapshot['checks']=[dict(row,check_id='test.control'+str(i)) for i in range(420)]
        def answer(prompt,**kwargs):
            payload=json.loads(prompt.rsplit('OBSERVATIONS:\n',1)[1])
            return {'provider':'Fixture','answer':json.dumps({'explanations':[{'check_id':c['check_id'],'meaning':'Observed control.','action':'Review in context.','verification':'Repeat this exact check.'} for c in payload['observations']]})}
        with patch('ironclad.advisor.ask',side_effect=answer):
            chunks=list(advisor.explanation_batches(snapshot))
        self.assertEqual(chunks[-1]['completed'],420);self.assertTrue(chunks[-1]['done'])
        self.assertTrue(all(c['total']==420 for c in chunks))
        self.assertEqual({r['check_id'] for c in chunks for r in c['explanations']},{r['check_id'] for r in snapshot['checks']})
        self.assertEqual(sum(len(c['explanations']) for c in chunks),420)

    def test_stream_failure_keeps_completed_chunks_without_claiming_completion(self):
        snapshot=self.explanation_snapshot();row=snapshot['checks'][0]
        snapshot['checks']=[dict(row,check_id='test.control'+str(i)) for i in range(90)]
        calls=[]
        def answer(prompt,**kwargs):
            if calls:raise ValueError('provider unavailable')
            calls.append(True);payload=json.loads(prompt.rsplit('OBSERVATIONS:\n',1)[1])
            return {'provider':'Fixture','answer':json.dumps({'explanations':[{'check_id':c['check_id'],'meaning':'Fact','action':'Review','verification':'Repeat'} for c in payload['observations']]})}
        with patch('ironclad.advisor.ask',side_effect=answer):
            chunks=advisor.explanation_batches(snapshot);first=next(chunks)
            self.assertFalse(first['done']);self.assertLess(first['completed'],90)
            with self.assertRaises(ValueError):next(chunks)

    def test_explanations_reject_missing_unknown_duplicate_or_oversized_answers(self):
        row = {'check_id':'performance.memory','meaning':'Meaning','action':'Optional action','verification':'Verify'}
        for rows in ([],[dict(row,check_id='invented.check')],[row,row],[dict(row,action='x'*601)]):
            with patch('ironclad.advisor.ask',return_value={'provider':'Fixture','answer':json.dumps({'explanations':rows})}):
                with self.assertRaises(ValueError):advisor.explain_findings(self.explanation_snapshot())

    def test_explanation_cli_requires_send_before_agent_can_run(self):
        with patch('ironclad.advisor.ask') as ask, redirect_stderr(StringIO()):
            self.assertEqual(maintenance.main(['explain-findings','--json']),2)
        ask.assert_not_called()

    def test_retained_version_and_fixed_release_reach_ai_without_claiming_global_outdated(self):
        data=self.software()
        item=data['items'][0]
        item.update(name='go',installed='1.27.2',available=None,active=False,status='security review',version_scope='retained version',configured_versions=['1.26.10'],security_fixed_versions=['1.27.3'],advisories=[dict(id='GO-2026-6809',summary='Certificate advisory',issues=['GO-2026-6809'],severity='unknown')])
        text=advisor.brief(self.snapshot(),data,'What do I need to fix?')
        self.assertIn('retained version',text)
        self.assertIn('configured global: 1.26.10',text)
        self.assertIn('publisher fixes: 1.27.3',text)
