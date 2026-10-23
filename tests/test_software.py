from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from ironclad import software, maintenance
from ironclad.runner import Result

MISE = json.dumps({'node': [{'version': '24.1.0', 'requested_version': '24', 'installed': True, 'active': True}]})

class SoftwareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root/'state'
        self.intel=patch('ironclad.threatintel.enrich',side_effect=lambda records,previous:(records,{'kev_status':'unavailable','kev_checked_at':None,'advisory_details_status':'partial'}))
        self.intel.start();self.addCleanup(self.intel.stop)
        self.commands = patch('ironclad.software.run', side_effect=lambda command: Result('available', MISE) if command == 'user_mise' else Result('missing'))
        self.command_mock = self.commands.start()

    def test_new_coverage_requires_new_advisory_query_even_when_updates_fresh(self):
        cache=self.snapshot();software.write_cache(self.state,cache)
        data=software.inventory(self.state,self.root)
        self.assertTrue(data['fresh']);self.assertEqual(data['advisory_status'],'not checked')
        cache.update(advisory_query_version=2,advisory_inventory_hash=cache['inventory_hash'])
        software.write_cache(self.state,cache)
        self.assertEqual(software.inventory(self.state,self.root)['advisory_status'],'available')
        cache['advisory_inventory_hash']='0'*64;software.write_cache(self.state,cache)
        self.assertEqual(software.inventory(self.state,self.root)['advisory_status'],'not checked')

    def test_failed_advisory_refresh_keeps_previously_matched_records(self):
        cache=self.snapshot();record={'source':'uv tool','package':'demo','affected':'1.0','id':'CVE-2026-12345','issues':['CVE-2026-12345'],'severity':'unknown','known_exploited':True}
        cache['advisories']=[record];software.write_cache(self.state,cache)
        data=software.inventory(self.state,self.root)
        with patch('ironclad.maintenance.inventory',return_value=data),patch('ironclad.maintenance.check_updates',return_value={}),patch('ironclad.maintenance.fetch_advisories',side_effect=OSError()):
            maintenance.refresh(self.state)
        saved=software.read_cache(self.state)
        self.assertEqual(saved['advisories'],[record]);self.assertEqual(saved['advisory_status'],'unavailable')

    def tearDown(self):
        self.commands.stop()
        self.temp.cleanup()

    def snapshot(self):
        data = software.inventory(self.state, self.root)
        return {'schema': 2, 'checked_at': datetime.now(timezone.utc).isoformat(), 'inventory_hash': data['inventory_hash'], 'updates': {'node': {'installed': '24.1.0', 'available': '24.2.0', 'requested': '24', 'source': 'mise'}}, 'channels': {'mise': 'available'}, 'advisories': [], 'advisory_status': 'available'}

    def test_inventory_readonly_and_user_scope(self):
        data = software.inventory(self.state, self.root)
        self.assertFalse(self.state.exists())
        self.assertFalse(data['fresh'])
        self.assertEqual([i['source'] for i in data['items']], ['mise'])
        self.assertEqual(data['items'][0]['status'], 'check for updates')
        self.assertTrue(all(c.args[0].startswith('user_') for c in self.command_mock.mock_calls if c.args))

    def test_cache_freshness_and_request_invalidation(self):
        data = self.snapshot()
        software.write_cache(self.state, data)
        self.assertEqual(software.inventory(self.state, self.root)['update_count'], 1)
        data['checked_at'] = (datetime.now(timezone.utc)-timedelta(days=2)).isoformat()
        software.write_cache(self.state, data)
        self.assertEqual(software.inventory(self.state, self.root)['update_count'], 0)
        data = self.snapshot()
        data['inventory_hash'] = 'a'*64
        software.write_cache(self.state, data)
        self.assertFalse(software.inventory(self.state, self.root)['fresh'])

    def test_advisory_exact_source_version(self):
        data = self.snapshot()
        data['advisories'] = [{'package': 'node', 'source': 'mise', 'affected': '24.1.0', 'id': 'GHSA-example', 'severity': 'unknown', 'issues': ['GHSA-example']}]
        software.write_cache(self.state, data)
        self.assertEqual(software.inventory(self.state, self.root)['security_count'], 1)
        data['advisories'][0]['affected'] = '24.0.0'
        software.write_cache(self.state, data)
        self.assertEqual(software.inventory(self.state, self.root)['security_count'], 0)

    def test_cache_private_and_symlink_safe(self):
        self.state.mkdir(mode=0o700)
        target = self.root/'target'
        target.write_text('preserve')
        path = self.state/'applications.json'
        data = self.snapshot()
        path.symlink_to(target)
        with self.assertRaises(OSError):
            software.read_cache(self.state)
        software.write_cache(self.state, data)
        self.assertEqual(target.read_text(), 'preserve')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            software.read_cache(self.state)

    def test_manager_parsers_and_injection(self):
        self.assertEqual(software.parse_uv_tools('ruff v0.17.0\n- ruff\n')[0]['name'], 'ruff')
        self.assertEqual(software.parse_flatpak('org.example.App\t1.2')[0]['source'], 'Flatpak user')
        updates = software.parse_mise_outdated(json.dumps({'node': {'current': '24.1.0', 'latest': '24.2.0', 'requested': '24'}}))
        self.assertEqual(updates['node']['available'], '24.2.0')
        for body in ['ruff;curl v1', '$(cmd) v1']:
            with self.assertRaises(ValueError):
                software.parse_uv_tools(body)
        with self.assertRaises(ValueError):
            software.parse_mise_outdated('{"--evil":{"current":"1","latest":"2","requested":"1"}}')

    def test_local_launcher_is_metadata_only(self):
        path = self.root/'.local/bin'
        path.mkdir(parents=True)
        launcher = path/'unknown-app'
        launcher.write_text('must never execute')
        launcher.chmod(0o700)
        (path/'linked').symlink_to(launcher)
        items = software.local_launchers(self.root, set())
        self.assertEqual([i['name'] for i in items], ['unknown-app'])
        self.assertEqual(items[0]['status'], 'identify installer')
        self.assertEqual(maintenance.update_candidates({'items': items}), [])

    def test_targeted_plan_and_stale_refusal(self):
        with patch('ironclad.maintenance.inventory', return_value=software.inventory(self.state, self.root)):
            with self.assertRaises(ValueError):
                maintenance.patch_plan(self.state, 'mise:node')
        software.write_cache(self.state, self.snapshot())
        data = software.inventory(self.state, self.root)
        with patch('ironclad.maintenance.inventory', return_value=data), patch('ironclad.maintenance.trusted', side_effect=str):
            plan = maintenance.patch_plan(self.state, 'mise:node')
            self.assertEqual(plan['command'], ['/usr/bin/mise', '--yes', 'upgrade', '--global', '--no-prune', '--jobs', '1', 'node@24.2.0'])
            for target in [None, 'pacman:linux', 'mise:--evil']:
                with self.assertRaises(ValueError):
                    maintenance.patch_plan(self.state, target)
        for source, name, expected in [('uv tool', 'ruff', ['/usr/bin/uv', 'tool', 'upgrade', 'ruff']), ('Flatpak user', 'org.example.App', ['/usr/bin/flatpak', 'update', '--user', '--app', '--assumeyes', '--noninteractive', 'org.example.App'])]:
            data['items'] = [{'source': source, 'name': name, 'installed': '1', 'available': None}]
            with patch('ironclad.maintenance.inventory', return_value=data), patch('ironclad.maintenance.trusted', side_effect=str):
                self.assertEqual(maintenance.patch_plan(self.state, source+':'+name)['command'], expected)

    def test_receipts_and_version_verification(self):
        software.write_cache(self.state, self.snapshot())
        data = software.inventory(self.state, self.root)
        with patch('ironclad.maintenance.inventory', return_value=data), patch('ironclad.maintenance.trusted', side_effect=str):
            plan = maintenance.patch_plan(self.state, 'mise:node')
        for code, version, verified in [(0, '24.2.0', True), (0, '24.1.0', False), (1, '24.2.0', False)]:
            after = {'items': [{'source': 'mise', 'name': 'node', 'installed': version, 'active': True}]}
            with patch('ironclad.maintenance.patch_plan', return_value=plan), patch('ironclad.maintenance.inventory', side_effect=[data, after]), patch('ironclad.maintenance.run_update', return_value={'returncode': code, 'reason': None if code == 0 else 'manager_failed'}) as run:
                self.assertEqual(maintenance.apply_patch_plan(self.state, plan)['verified'], verified)
                self.assertEqual(run.call_args.args[0][-1], 'node@24.2.0')
        self.assertEqual(len(list((self.state/'maintenance').glob('*-finished.json'))), 3)
        with patch('ironclad.maintenance.patch_plan', return_value={}), patch('ironclad.maintenance.subprocess.run') as run:
            with self.assertRaises(ValueError):
                maintenance.apply_patch_plan(self.state, plan)
            run.assert_not_called()

    def test_refused_refresh_never_contacts_network(self):
        with patch('ironclad.maintenance.confirm', side_effect=ValueError('declined')), patch('ironclad.maintenance.refresh') as refresh, patch('sys.stdout', StringIO()), patch('sys.stderr', StringIO()):
            self.assertEqual(maintenance.main(['--state', str(self.state), 'refresh']), 2)
            refresh.assert_not_called()

    def test_refresh_partial_failure_is_visible(self):
        data = software.inventory(self.state, self.root)
        with patch('ironclad.maintenance.inventory', return_value=data), patch('ironclad.maintenance.check_updates', side_effect=ValueError()), patch('ironclad.maintenance.fetch_advisories', side_effect=OSError()):
            maintenance.refresh(self.state)
        saved = software.read_cache(self.state)
        self.assertEqual(saved['channels']['mise'], 'unavailable')
        self.assertEqual(saved['advisory_status'], 'unavailable')

    def test_osv_queries_only_supported_ecosystems(self):
        items = [{'source': 'uv tool', 'name': 'ruff', 'installed': '1'}, {'source': 'mise', 'name': 'npm:typescript', 'installed': '5'}, {'source': 'mise', 'name': 'node', 'installed': '24'}]
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"results":[{"vulns":[{"id":"GHSA-example"}]},{}]}'
        opener = Mock()
        opener.open.return_value = response
        with patch('ironclad.maintenance.urllib.request.build_opener', return_value=opener):
            result = maintenance.fetch_advisories(items)
        request = opener.open.call_args.args[0]
        queries = json.loads(request.data)['queries']
        self.assertEqual([q['package']['ecosystem'] for q in queries], ['PyPI', 'npm'])
        self.assertEqual(result[0]['severity'], 'unknown')
        self.assertEqual(result[0]['package'], 'ruff')

    def test_all_findings_have_specific_steps_and_verification(self):
        from ironclad.collectors import scan
        from ironclad.guidance import GUIDANCE
        from ironclad.reports import render
        result = scan('full')
        for check in result['checks']:
            self.assertIn(check['check_id'], GUIDANCE)
            self.assertTrue(check['remediation_steps'])
            self.assertTrue(check['verification'])
        self.assertIn('Verify', render(result, 'html'))
        self.assertIn('Verify', render(result, 'markdown'))

    def test_user_writable_executable_refused(self):
        path = self.root/'updater'
        path.write_text('#!/bin/sh\nexit 0')
        path.chmod(0o755)
        with self.assertRaises(ValueError):
            maintenance.trusted(path)


    def test_explicit_refresh_returns_inventory_json_without_terminal(self):
        data = {'schema': 2, 'update_count': 5, 'security_count': 0, 'advisory_status': 'available'}
        output = StringIO()
        with patch('ironclad.maintenance.refresh', return_value=data), patch('ironclad.maintenance.confirm') as confirm, patch('sys.stdout', output):
            self.assertEqual(maintenance.main(['refresh', '--allow-network', '--json']), 0)
            confirm.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), data)

    def test_network_flag_cannot_approve_installation(self):
        with patch('ironclad.maintenance.confirm', side_effect=ValueError('declined')) as confirm, patch('ironclad.maintenance.apply_patch_plan') as apply, patch('sys.stdout', StringIO()), patch('sys.stderr', StringIO()):
            self.assertEqual(maintenance.main(['update', '--allow-network']), 2)
            confirm.assert_called_once_with('REVIEW APP')
            apply.assert_not_called()

    def test_apply_requires_explicit_approval_of_the_exact_reviewed_digest(self):
        for payload, approval in [({}, None), ({'plan': {'digest': 'a'*64}}, None), ({'plan': {'digest': 'a'*64}}, 'b'*64)]:
            with patch('ironclad.maintenance.apply_patch_plan') as apply:
                with self.assertRaises(ValueError):
                    maintenance.apply_reviewed(self.state, payload, approval)
                apply.assert_not_called()
        plan = {'digest': 'a'*64}
        with patch('ironclad.maintenance.apply_patch_plan', return_value={'verified': True}) as apply:
            self.assertTrue(maintenance.apply_reviewed(self.state, {'plan': plan}, 'a'*64)['verified'])
            apply.assert_called_once_with(self.state, plan)

    def test_apply_cli_rejects_network_approval_without_review_digest(self):
        with patch('sys.stdin', StringIO(json.dumps({'plan': {'digest': 'a'*64}}))), patch('ironclad.maintenance.apply_patch_plan') as apply, patch('sys.stdout', StringIO()), patch('sys.stderr', StringIO()):
            self.assertEqual(maintenance.main(['apply-update', '--json', '--allow-network']), 2)
            apply.assert_not_called()

    def test_verified_update_preserves_unaffected_candidates_without_freshening_timestamp(self):
        entries = {'node': [{'version': '24.1.0', 'requested_version': '24', 'installed': True, 'active': True}], 'gh': [{'version': '2.0', 'requested_version': 'latest', 'installed': True, 'active': True}]}
        self.command_mock.side_effect = lambda command: Result('available', json.dumps(entries)) if command == 'user_mise' else Result('missing')
        cache = self.snapshot()
        cache['updates']['gh'] = {'installed': '2.0', 'available': '2.1', 'requested': 'latest', 'source': 'mise'}
        software.write_cache(self.state, cache)
        before = software.inventory(self.state, self.root)
        plan = {'target': 'mise:node', 'inventory_hash': before['inventory_hash']}
        entries['node'][0]['active'] = False
        entries['node'].append({'version': '24.2.0', 'requested_version': '24', 'installed': True, 'active': True})
        after = software.inventory(self.state, self.root)
        self.assertTrue(maintenance.retain_unaffected_metadata(self.state, before, after, plan))
        current = software.inventory(self.state, self.root)
        self.assertTrue(current['fresh'])
        self.assertEqual(current['update_count'], 1)
        self.assertEqual(software.read_cache(self.state)['checked_at'], cache['checked_at'])
        # An unrelated application changing must invalidate remaining metadata instead.
        software.write_cache(self.state, cache)
        entries['gh'][0]['version'] = '2.0.1'
        self.assertFalse(maintenance.retain_unaffected_metadata(self.state, before, software.inventory(self.state, self.root), plan))
        self.assertFalse(software.inventory(self.state, self.root)['fresh'])

    def test_machine_plan_is_a_single_line_for_quickshell_transport(self):
        output = StringIO()
        with patch('ironclad.maintenance.patch_plan', return_value={'name': 'demo', 'command': ['/usr/bin/mise', 'demo']}), patch('sys.stdout', output):
            self.assertEqual(maintenance.main(['plan', '--target', 'mise:demo', '--json']), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())['name'], 'demo')

    def test_selected_plan_rejects_empty_duplicate_or_excessive_targets(self):
        for targets in ([], ['mise:demo', 'mise:demo'], ['mise:t'+str(n) for n in range(33)], 'mise:demo', [None]):
            with self.assertRaises(ValueError):
                maintenance.selected_plan(self.state, targets)

    def test_selected_plan_requires_consistent_inventory(self):
        with patch('ironclad.maintenance.patch_plan', side_effect=[{'inventory_hash':'a'}, {'inventory_hash':'b'}]):
            with self.assertRaises(ValueError):
                maintenance.selected_plan(self.state, ['mise:one','mise:two'])

    def test_batch_approval_and_plan_tampering_never_run_manager(self):
        batch = {'plans':[{'target':'mise:demo','inventory_hash':'original'}], 'digest':'a'*64}
        with patch('ironclad.maintenance.selected_plan', return_value=batch), patch('ironclad.maintenance.apply_patch_plan') as apply:
            with self.assertRaises(ValueError):
                maintenance.apply_selected(self.state, batch, 'b'*64)
            altered = dict(batch, operation='tampered')
            with self.assertRaises(ValueError):
                maintenance.apply_selected(self.state, altered, 'a'*64)
            apply.assert_not_called()

    def test_batch_inventory_change_stops_before_execution(self):
        batch = {'plans':[{'target':'mise:demo','inventory_hash':'original'}], 'digest':'a'*64}
        with patch('ironclad.maintenance.selected_plan', return_value=batch), patch('ironclad.maintenance.inventory', return_value={'inventory_hash':'changed'}), patch('ironclad.maintenance.apply_patch_plan') as apply:
            result = maintenance.apply_selected(self.state,batch,'a'*64)
        self.assertFalse(result['verified'])
        self.assertEqual(result['results'][0]['reason'],'plan_changed_or_unavailable')
        apply.assert_not_called()

    def test_patched_global_go_does_not_hide_vulnerable_retained_versions(self):
        listing=json.dumps({'go':[
            {'installed':True,'version':'1.26.10','requested_version':'1.26','active':True},
            {'installed':True,'version':'1.26.9','requested_version':'','active':False},
            {'installed':True,'version':'1.27.2','requested_version':'','active':False}]})
        self.command_mock.side_effect=lambda command: Result('available',listing) if command=='user_mise' else Result('missing')
        cache=self.snapshot();cache['updates']={};cache['advisories']=[{'source':'mise','package':'go','affected':v,'id':'GO-2026-6809','issues':['GO-2026-6809'],'severity':'unknown','fixed_versions':['1.26.10','1.27.3']} for v in ('1.26.9','1.27.2')]
        software.write_cache(self.state,cache)
        result=software.inventory(self.state,self.root)
        self.assertEqual(result['update_count'],0)
        self.assertEqual(result['security_count'],2)
        rows={i['installed']:i for i in result['items']}
        self.assertEqual(rows['1.26.10']['version_scope'],'configured global')
        self.assertFalse(rows['1.26.10']['advisories'])
        for old,fixed in [('1.26.9','1.26.10'),('1.27.2','1.27.3')]:
            self.assertEqual(rows[old]['version_scope'],'retained version')
            self.assertEqual(rows[old]['configured_versions'],['1.26.10'])
            self.assertEqual(rows[old]['security_fixed_versions'],[fixed])
            self.assertIn('projects can still select it',rows[old]['next_step'])
            self.assertIsNone(rows[old]['available'])
        cache['advisories'][0]['fixed_versions']=['1.26.10; bad']
        with self.assertRaises(ValueError):software.write_cache(self.state,cache)
