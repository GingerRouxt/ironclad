"""User-invoked metadata refresh, updater handoff and AI advice. No arbitrary commands."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import tempfile
import time
import urllib.request
from .cli import confirm
from .model import now
from .software import inventory, parse_mise_outdated, write_cache, read_cache, NAME
from .storage import export, private_dir


def trusted(path):
    path = Path(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            meta = os.fstat(fd)
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                raise ValueError('untrusted command parent')
        # Packaged symlinks may only resolve into another protected system path.
        target = path.resolve(strict=True)
        if target != path:
            return trusted(target)
        meta = path.stat()
        if meta.st_uid != 0 or meta.st_mode & 0o022 or not stat.S_ISREG(meta.st_mode) or not meta.st_mode & 0o111:
            raise ValueError('untrusted system command')
        return str(path)
    finally:
        os.close(fd)


def environment():
    home = pwd.getpwuid(os.getuid()).pw_dir
    result = {'PATH': '/usr/bin', 'HOME': home, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'XDG_RUNTIME_DIR': f'/run/user/{os.getuid()}'}
    for key in ('DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS', 'TERM', 'COLORTERM'):
        if key in os.environ:
            result[key] = os.environ[key]
    return result


def capture(command, timeout=45):
    command = [trusted(command[0]), *command[1:]]
    with tempfile.TemporaryFile() as output:
        p = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, env=environment(), cwd=pwd.getpwuid(os.getuid()).pw_dir, start_new_session=True)
        start = time.monotonic()
        try:
            while p.poll() is None:
                if time.monotonic()-start > timeout or os.fstat(output.fileno()).st_size > 262144:
                    raise ValueError('manager query timed out or exceeded output limit')
                time.sleep(.05)
            output.seek(0)
            body = output.read(262145)
            if p.returncode != 0 or len(body) > 262144:
                raise ValueError('application manager query failed')
            return body.decode('utf-8', errors='strict')
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()


def check_updates():
    return parse_mise_outdated(capture(['/usr/bin/mise', 'outdated', '--global', '--json']))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('unexpected advisory redirect')


def fetch_advisories(items):
    from .threatintel import query_for
    supported = [(item, query_for(item)) for item in items if query_for(item)]
    if not supported:
        return []
    if len(supported) > 128:
        raise ValueError('advisory query limit')
    request = urllib.request.Request('https://api.osv.dev/v1/querybatch', data=json.dumps({'queries': [q for _, q in supported]}).encode(), headers={'User-Agent': 'Ironclad/0.2 user-software check', 'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        body = response.read(1048577)
    if len(body) > 1048576:
        raise ValueError('advisory response limit')
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get('results'), list) or len(data['results']) != len(supported):
        raise ValueError('invalid advisory response')
    result = []
    for (item, _), row in zip(supported, data['results']):
        if not isinstance(row, dict):
            raise ValueError('invalid advisory result')
        if row.get('next_page_token'): raise ValueError('advisory response is paginated; coverage incomplete')
        vulns = row.get('vulns', [])
        if not isinstance(vulns, list) or len(vulns) > 64:
            raise ValueError('invalid advisory list')
        for vuln in vulns:
            if not isinstance(vuln, dict):
                raise ValueError('invalid advisory entry')
            identifier = vuln.get('id')
            if not isinstance(identifier, str) or not __import__('re').fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{1,119}', identifier):
                raise ValueError('invalid advisory identifier')
            result.append({'package': item['name'], 'source': item['source'], 'affected': item['installed'], 'id': identifier, 'severity': 'unknown', 'issues': [identifier]})
            if len(result) > 256:
                raise ValueError('too many advisory matches')
    return result


def refresh(state):
    before = inventory(state)
    updates = {}
    channels = {'mise': 'unavailable'}
    if before['channels'].get('mise') == 'available':
        try:
            updates = check_updates()
            channels['mise'] = 'available'
        except (OSError, ValueError):
            pass
    previous = read_cache(state)
    try:
        advisories = fetch_advisories(before['items'])
        advisory_status = 'available'
    except (OSError, ValueError, KeyError, TypeError):
        advisories, advisory_status = (previous['advisories'] if previous else []), 'unavailable'
    from .threatintel import enrich
    advisories, intelligence = enrich(advisories, previous)
    after = inventory(state)
    if after['inventory_hash'] != before['inventory_hash']:
        raise ValueError('installed software changed during refresh; retry')
    data = {'schema': 2, 'checked_at': now(), 'inventory_hash': before['inventory_hash'], 'updates': updates, 'channels': channels, 'advisories': advisories, 'advisory_status': advisory_status, 'advisory_query_version':2, 'advisory_inventory_hash':before['inventory_hash'], **intelligence}
    write_cache(state, data)
    return inventory(state)


def update_candidates(data):
    return [i for i in data['items'] if (i['source'] == 'mise' and i.get('active') and i['available']) or i['source'] in ('uv tool', 'Flatpak user')]


def patch_plan(state, target=None):
    data = inventory(state)
    if not target:
        raise ValueError('choose one application or tool to update')
    items = [i for i in update_candidates(data) if i['source']+':'+i['name'] == target]
    if len(items) != 1:
        raise ValueError('selected application is not eligible for managed updating')
    item = items[0]
    name = item['name']
    if not NAME.fullmatch(name):
        raise ValueError('invalid application name')
    if item['source'] == 'mise':
        if not data['fresh']:
            raise ValueError('refresh tool update metadata before approving')
        command = [trusted('/usr/bin/mise'), '--yes', 'upgrade', '--global', '--no-prune', '--jobs', '1', name+'@'+item['available']]
        scope = 'Only this configured global mise tool, within its existing requested range. Old versions are retained; no project config or project pins are changed.'
    elif item['source'] == 'uv tool':
        if not __import__('re').fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', name):
            raise ValueError('invalid uv tool name')
        command = [trusted('/usr/bin/uv'), 'tool', 'upgrade', name]
        scope = 'Only this user-installed uv tool and its isolated dependencies. uv resolves its configured source/constraints; availability is checked by the manager during this review.'
    else:
        if not __import__('re').fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,159}', name):
            raise ValueError('invalid Flatpak application')
        command = [trusted('/usr/bin/flatpak'), 'update', '--user', '--app', '--assumeyes', '--noninteractive', name]
        scope = 'Only this user Flatpak application, with related user runtimes/extensions. Flatpak may also remove unused end-of-life user runtimes. No system-wide installation is targeted.'
    plan = {'schema': 2, 'operation': 'user-application-update', 'target': target, 'source': item['source'], 'name': name, 'installed': item['installed'], 'available': item['available'], 'requested': item.get('requested'), 'command': command, 'inventory_hash': data['inventory_hash'], 'checked_at': data['checked_at'], 'scope': scope, 'impact': 'Save work and close the affected app before updating. The manager may download and run publisher installation steps. No OS packages, kernel, Omarchy migrations or system updater are invoked.', 'recovery': 'Restart the affected application and verify its version and normal workflow. Retained mise versions can be selected again; other manager rollback is not guaranteed.'}
    plan['digest'] = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    return plan


def run_update(command, timeout=900):
    with tempfile.TemporaryFile() as output:
        p = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                             env=environment(), cwd=pwd.getpwuid(os.getuid()).pw_dir,
                             start_new_session=True)
        started = time.monotonic()
        reason = None
        try:
            while p.poll() is None:
                if time.monotonic()-started > timeout:
                    reason = 'timeout'
                    break
                if os.fstat(output.fileno()).st_size > 1048576:
                    reason = 'output_limit'
                    break
                time.sleep(.05)
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        if os.fstat(output.fileno()).st_size > 1048576:
            reason = reason or 'output_limit'
        return {'returncode': p.returncode, 'reason': reason or ('manager_failed' if p.returncode else None)}


def retain_unaffected_metadata(state, before, after, plan):
    try:
        cache = read_cache(state)
        if not cache or cache['inventory_hash'] != plan['inventory_hash'] or not after.get('inventory_hash'):
            return False
        def others(data):
            return sorted((i['source'], i['name'], i['installed'], i.get('requested', ''), i.get('active', False))
                          for i in data['items'] if i['source']+':'+i['name'] != plan['target'])
        if others(before) != others(after):
            return False
        updates = {}
        for item in after['items']:
            row = cache['updates'].get(item['name'])
            if item['source'] == 'mise' and item.get('active') and item['source']+':'+item['name'] != plan['target'] and row and row['installed'] == item['installed'] and row['requested'] == item.get('requested'):
                updates[item['name']] = row
        cache.update(inventory_hash=after['inventory_hash'], updates=updates)
        # Retain the original checked_at: a local update is not a new upstream check.
        write_cache(state, cache)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def apply_patch_plan(state, plan):
    if patch_plan(state, plan.get('target')) != plan:
        raise ValueError('application plan changed; review again')
    before = inventory(state)
    if before.get('inventory_hash') != plan['inventory_hash']:
        raise ValueError('application plan changed; review again')
    receipt_dir = Path(state)/'maintenance'
    fd = private_dir(receipt_dir)
    os.close(fd)
    receipt_id = str(time.time_ns())
    export(receipt_dir/(receipt_id+'-started.json'), json.dumps({'started_at': now(), 'plan': plan}))
    try:
        process = run_update(plan['command'])
        after = inventory(state)
        versions = [i['installed'] for i in after['items'] if i['source'] == plan['source'] and i['name'] == plan['name'] and (plan['source'] != 'mise' or i.get('active'))]
        expected = plan['available']
        verified = process['returncode'] == 0 and process['reason'] is None and bool(versions) and (not expected or expected in versions)
        reason = process['reason'] or (None if verified else 'version_not_verified')
        metadata_retained = retain_unaffected_metadata(state, before, after, plan) if verified else False
        result = {'finished_at': now(), 'operation': plan['operation'], 'target': plan['target'],
                  'updater_exit_code': process['returncode'], 'observed_versions': versions,
                  'version_changed': any(v != plan['installed'] for v in versions), 'reason': reason, 'metadata_retained': metadata_retained,
                  'restart_status': 'Restart this application, then verify its reported version and normal workflow.',
                  'verified': verified, 'verification_scope': 'Manager completed and target version observed where specified; project compatibility and absence of vulnerabilities are not certified.'}
    except BaseException:
        export(receipt_dir/(receipt_id+'-finished.json'), json.dumps({'finished_at': now(), 'target': plan['target'], 'verified': False, 'reason': 'interrupted_or_unavailable'}))
        raise
    export(receipt_dir/(receipt_id+'-finished.json'), json.dumps(result))
    return result


def apply_reviewed(state, payload, approval):
    if not isinstance(payload, dict) or not isinstance(payload.get('plan'), dict):
        raise ValueError('invalid reviewed update plan')
    plan = payload['plan']
    digest = plan.get('digest')
    if not isinstance(digest, str) or not __import__('re').fullmatch('[0-9a-f]{64}', digest) or approval != digest:
        raise ValueError('explicit update approval required')
    return apply_patch_plan(state, plan)


def selected_plan(state, targets):
    if not isinstance(targets, list) or not 1 <= len(targets) <= 32 or any(not isinstance(t, str) for t in targets) or len(set(targets)) != len(targets):
        raise ValueError('select between one and 32 distinct applications')
    plans = [patch_plan(state, target) for target in targets]
    if len({plan['inventory_hash'] for plan in plans}) != 1:
        raise ValueError('inventory changed during review')
    result = {'operation': 'selected-application-updates', 'plans': plans}
    result['digest'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def apply_selected(state, batch, approval, progress=lambda value: None):
    if not isinstance(batch, dict) or not isinstance(batch.get('plans'), list):
        raise ValueError('invalid selection')
    if not approval or approval != batch.get('digest') or selected_plan(state, [p['target'] for p in batch['plans']]) != batch:
        raise ValueError('selection changed; review again')
    expected_hash = batch['plans'][0]['inventory_hash']
    results = []
    for index, reviewed in enumerate(batch['plans']):
        try:
            before = inventory(state)
            if before['inventory_hash'] != expected_hash:
                raise ValueError('inventory changed')
            current = patch_plan(state, reviewed['target'])
            stable = lambda plan: {k: v for k, v in plan.items() if k not in ('digest', 'inventory_hash', 'checked_at')}
            if stable(current) != stable(reviewed):
                raise ValueError('reviewed command or version changed')
            progress({'progress': index + 1, 'total': len(batch['plans']), 'target': current['target']})
            result = apply_patch_plan(state, current)
            results.append(result)
            if not result['verified']:
                break
            after = inventory(state)
            others = lambda data: sorted((i['source'], i['name'], i['installed'], i.get('requested', ''), i.get('active', False)) for i in data['items'] if i['source']+':'+i['name'] != current['target'])
            if others(before) != others(after):
                break
            expected_hash = after['inventory_hash']
        except (OSError, ValueError, KeyError, TypeError):
            results.append({'target': reviewed['target'], 'verified': False, 'reason': 'plan_changed_or_unavailable'})
            break
    return {'batch_result': True, 'verified': len(results) == len(batch['plans']) and all(r['verified'] for r in results), 'results': results, 'skipped': [p['target'] for p in batch['plans'][len(results):]]}


def scan_snapshot():
    from .model import validate_scan
    script = Path(__file__).resolve().parents[1]/'engine.py'
    result = subprocess.run([trusted('/usr/bin/python3'), '-I', '-B', str(script), 'check', '--profile', 'quick'], stdin=subprocess.DEVNULL, capture_output=True, env=environment(), cwd='/', timeout=15, check=False)
    if result.returncode or len(result.stdout) > 262144:
        raise ValueError('fresh offline scan unavailable')
    return validate_scan(json.loads(result.stdout))


def software_snapshot(state):
    script = Path(__file__).resolve().parents[1]/'engine.py'
    result = subprocess.run([trusted('/usr/bin/python3'), '-I', '-B', str(script), '--state', str(Path(state).absolute()), 'software'], stdin=subprocess.DEVNULL, capture_output=True, env=environment(), cwd='/', timeout=15, check=False)
    if result.returncode or len(result.stdout) > 1048576:
        raise ValueError('offline software inventory unavailable')
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or data.get('schema') != 2 or not isinstance(data.get('items'), list) or len(data['items']) > 2304:
        raise ValueError('invalid software snapshot')
    return data


def main(argv=None):
    p = argparse.ArgumentParser(description='Ironclad interactive companion')
    p.add_argument('--state', type=Path, default=Path(os.environ.get('XDG_STATE_HOME', Path.home()/'.local/state'))/'ironclad')
    p.add_argument('operation', choices=('refresh', 'plan', 'update', 'ask', 'brief', 'agent-status', 'apply-update', 'plan-selected', 'apply-selected', 'explain-findings', 'scan-archive', 'fix-options', 'fix-queue', 'fix-run', 'fix-result', 'protection-status', 'automatic-malware-plan', 'automatic-malware-apply', 'automatic-malware-review', 'malware-plan', 'malware-scan', 'scanner-install', 'scanner-signatures', 'monitor-status', 'monitor-plan', 'monitor-apply', 'monitor-review', 'finding-preferences', 'protection-maintain', 'protection-updates-enable', 'protection-updates-disable'))
    p.add_argument('--ticket', help='private reviewed repair ticket')
    p.add_argument('--approve', help='exact digest of a reviewed application plan; only applies to apply-update')
    p.add_argument('--allow-network', action='store_true', help='explicitly approve update/advisory metadata requests; never authorizes installing updates')
    p.add_argument('--question', default='What should I address first?', help='question about the current observations')
    p.add_argument('--input-question', action='store_true', help='read a JSON question from stdin')
    p.add_argument('--input-brief', action='store_true', help='read a previously reviewed JSON brief from stdin')
    p.add_argument('--send', action='store_true', help='explicitly send a redacted brief through your already signed-in coding agent')
    p.add_argument('--json', action='store_true', help='machine-readable AI result')
    p.add_argument('--target', help='one source:name from the application inventory')
    p.add_argument('--hold', action='store_true', help='keep review terminal open until Enter')
    args = p.parse_args(argv)
    try:
        if args.operation == 'agent-status':
            from .advisor import detect_agent
            try:
                name, _ = detect_agent()
                result = {'available': True, 'agent': 'Codex' if name == 'codex' else 'Claude Code'}
            except (OSError, ValueError):
                result = {'available': False, 'agent': None}
            print(json.dumps(result))
            return 0
        if os.geteuid() == 0:
            raise ValueError('run Ironclad as your normal user')
        if args.operation in ('protection-maintain','protection-updates-enable','protection-updates-disable'):
            from . import protection_updates
            try:
                if args.operation!='protection-updates-disable' and not args.allow_network:raise ValueError('network approval required')
                if args.operation=='protection-maintain':
                    result=protection_updates.maintain(args.state,args.allow_network)
                    print(json.dumps({'scanner':__import__('ironclad.malware',fromlist=['status']).status(args.state),'message':'Protection maintenance finished.' if result['outcome']=='ok' else 'Protection maintenance needs attention. Review update health.'}))
                    return 0 if result['outcome']=='ok' else 2
                protection_updates.configure(args.operation=='protection-updates-enable')
                print(json.dumps({'scanner':__import__('ironclad.malware',fromlist=['status']).status(args.state),'message':'Automatic protection updates enabled.' if args.operation=='protection-updates-enable' else 'Automatic protection updates disabled. Existing signatures are retained.'}))
                return 0
            except (OSError,ValueError):
                print(json.dumps({'error':'Protection maintenance could not complete. Check update health, connection and user timer configuration; existing files are retained.'}));return 2
        if args.operation == 'scan-archive':
            from .scan_archives import archive
            line=__import__('sys').stdin.readline(4194305)
            if len(line)>4194304:raise ValueError('archive request size bound')
            data=json.loads(line)
            if not isinstance(data,dict) or set(data)-{'scan','explanations'}:raise ValueError('invalid archive request')
            print(json.dumps(archive(args.state,data['scan'],data.get('explanations'))),flush=True)
            return 0
        if args.operation == 'finding-preferences':
            from .finding_preferences import apply
            try:
                line=__import__('sys').stdin.readline(2097153)
                if len(line)>2097152:raise ValueError('preference request too large')
                result=apply(args.state,json.loads(line))
                print(json.dumps(result));return 0
            except (OSError,ValueError,TypeError,KeyError):
                print(json.dumps({'error':'Could not save or read ignored findings. No system settings were changed.'}));return 2
        if args.operation.startswith('monitor-'):
            from . import sensor
            try:
                if args.operation=='monitor-status':result=sensor.status(args.state)
                elif args.operation=='monitor-plan':result=sensor.plan(args.state,args.target,args.allow_network)
                else:
                    line=__import__('sys').stdin.readline(65537)
                    if len(line)>65536:raise ValueError('monitoring request too large')
                    request=json.loads(line)
                    result=sensor.apply(args.state,request.get('plan'),args.approve) if args.operation=='monitor-apply' else sensor.acknowledge(args.state,request.get('id'))
                print(json.dumps(result));return 0
            except (OSError,ValueError,TypeError,KeyError):
                print(json.dumps({'error':'Monitoring change could not be completed. Refresh its status, check your connection or OS authentication, and review again.'}));return 2
        if args.operation in ('automatic-malware-plan','automatic-malware-apply','automatic-malware-review'):
            from . import onaccess
            try:
                if args.operation=='automatic-malware-plan':result=onaccess.plan(args.state,args.target)
                else:
                    line=__import__('sys').stdin.readline(65537)
                    if len(line)>65536:raise ValueError('automatic protection request limit')
                    request=json.loads(line)
                    result=onaccess.apply(args.state,request.get('plan'),args.approve) if args.operation=='automatic-malware-apply' else onaccess.acknowledge(args.state,request.get('id'))
                print(json.dumps(result));return 0
            except (OSError,ValueError,KeyError,TypeError):
                print(json.dumps({'error':'Automatic malware protection did not verify. Refresh status, check OS authentication, and review again. No coverage is assumed.'}));return 2
        if args.operation == 'protection-status':
            from .protection import status
            print(json.dumps(status(args.state)))
            return 0
        if args.operation in ('malware-plan','malware-scan'):
            from . import malware
            line=__import__('sys').stdin.readline(65537)
            if len(line)>65536:raise ValueError('scan request too large')
            request=json.loads(line)
            try:
                result=malware.plan(args.state,request.get('path')) if args.operation=='malware-plan' else malware.scan(args.state,request.get('plan'),args.approve)
            except ValueError as error:
                print(json.dumps({'error':str(error)[:512]}))
                return 2
            except OSError:
                print(json.dumps({'error':'The file or scanner could not be opened safely. Check permissions and scanner setup, then review again.'}))
                return 2
            print(json.dumps(result))
            return 0
        if args.operation in ('scanner-install','scanner-signatures'):
            from . import malware
            # Invoked only after the app's explicit setup review.
            try:
                result=malware.install_scanner(args.state) if args.operation=='scanner-install' else malware.update_signatures(args.state,args.allow_network)
                print(json.dumps({'scanner':result,'message':'Scanner installed. Download signatures before scanning.' if args.operation=='scanner-install' else 'Signature update finished. Scanner readiness has been checked.'}))
                return 0
            except (OSError,ValueError):
                print(json.dumps({'error':'Scanner installation was cancelled or failed. Check package-manager availability, then retry.' if args.operation=='scanner-install' else 'Signature download did not complete. Check your connection and try again; existing signatures are retained.'}))
                return 2
        if args.operation.startswith('fix-'):
            from . import remediation
            if args.operation == 'fix-options':
                print(json.dumps(remediation.options(args.target)))
            elif args.operation == 'fix-queue':
                line = __import__('sys').stdin.readline(65537)
                if len(line) > 65536:
                    raise ValueError('repair plan too large')
                print(json.dumps(remediation.queue(args.state, json.loads(line)['plan'], args.approve)))
            elif args.operation == 'fix-run':
                result = remediation.run_ticket(args.state,args.ticket,args.approve)
                print(json.dumps(result))
                return 0 if result['verified'] else 2
            else:
                print(json.dumps(remediation.result(args.state,args.ticket)))
            return 0
        if args.operation == 'explain-findings':
            if not args.send:
                raise ValueError('sending findings requires explicit approval')
            line = __import__('sys').stdin.readline(2097153)
            if len(line) > 2097152:
                raise ValueError('scan too large')
            from .model import validate_scan
            from .advisor import explanation_batches
            snapshot = validate_scan(json.loads(line)['scan'])
            for result in explanation_batches(snapshot):print(json.dumps(result),flush=True)
            return 0
        if args.operation in ('plan-selected', 'apply-selected'):
            line = __import__('sys').stdin.readline(65537)
            if len(line) > 65536:
                raise ValueError('selection too large')
            payload = json.loads(line)
            if args.operation == 'plan-selected':
                print(json.dumps(selected_plan(args.state, payload['targets'])))
                return 0
            result = apply_selected(args.state, payload['batch'], args.approve, lambda value: print(json.dumps(value), flush=True))
            print(json.dumps(result))
            return 0 if result['verified'] else 2
        if args.operation == 'apply-update':
            line = __import__('sys').stdin.readline(65537)
            if len(line) > 65536:
                raise ValueError('invalid reviewed update plan')
            result = apply_reviewed(args.state, json.loads(line), args.approve)
            print(json.dumps(result))
            return 0 if result['verified'] else 2
        if args.operation == 'plan':
            print(json.dumps(patch_plan(args.state, args.target), indent=None if args.json else 2))
            return 0
        if args.operation == 'refresh':
            if not args.allow_network:
                print('Check compatible global mise tool updates through their configured upstream sources. Also send supported Python-tool/npm/Go standard-library package names and versions to api.osv.dev for advisory matching/details, and download the public exploited-vulnerability catalog from raw.githubusercontent.com/cisagov/kev-data. No software is installed and no OS updater is called.')
                confirm('REFRESH')
            data = refresh(args.state)
            if args.json:
                print(json.dumps(data))
            else:
                print(f"Checked: {data['update_count']} compatible tool updates; {data['security_count']} exact advisory matches. Advisory source: {data['advisory_status']}.")
        elif args.operation == 'update':
            if not args.target:
                confirm('REVIEW APP')
                candidates = update_candidates(inventory(args.state))
                if not candidates:
                    raise ValueError('no eligible application updates; check online first')
                for index, item in enumerate(candidates):
                    print(f"{index+1}. {item['name']} · {item['source']} · {item['installed']}" + (f" -> {item['available']}" if item['available'] else ' · manager will check'))
                selected = input('Application number: ').strip()
                if not selected.isdigit() or not 1 <= int(selected) <= len(candidates):
                    raise ValueError('invalid application selection')
                item = candidates[int(selected)-1]
                args.target = item['source']+':'+item['name']
            plan = patch_plan(args.state, args.target)
            print(json.dumps(plan, indent=2))
            confirm('UPDATE '+plan['digest'][:12])
            result = apply_patch_plan(args.state, plan)
            print(json.dumps(result, indent=2))
            return 0 if result['verified'] else 2
        else:
            from .advisor import brief, ask, SYSTEM
            supplied_snapshot = None
            if args.input_question:
                line = __import__('sys').stdin.readline(2097153)
                payload = json.loads(line)
                if len(line) > 2097152 or not isinstance(payload, dict) or not isinstance(payload.get('question'), str):
                    raise ValueError('invalid question')
                args.question = payload['question'][:1000]
                if payload.get('scan') is not None:
                    from .model import validate_scan
                    supplied_snapshot = validate_scan(payload['scan'])
            if args.input_brief:
                line = __import__('sys').stdin.readline(2097153)
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError('invalid reviewed brief')
                prompt = payload.get('brief')
                if len(line) > 2097152 or not isinstance(prompt, str) or len(prompt) > 524288 or not prompt.startswith(SYSTEM):
                    raise ValueError('invalid reviewed brief')
            else:
                from .protection_reference import local_status
                prompt = brief(supplied_snapshot if supplied_snapshot is not None else scan_snapshot(), software_snapshot(args.state), args.question, local_status(args.state))
            if args.operation == 'brief':
                print(json.dumps({'brief': prompt}) if args.json else prompt)
            else:
                if not args.send:
                    print('Send the redacted findings and your question through your already signed-in coding agent. Its provider processes this data; account limits or charges apply. Advice only, with no update authority. No local model required.')
                    confirm('ASK AGENT')
                result = ask(prompt)
                print(json.dumps(result) if args.json else result['answer'])
        return 0
    except (OSError, ValueError, KeyError, TypeError, EOFError, KeyboardInterrupt):
        if args.json and (args.operation.startswith('fix-') or args.operation in ('plan', 'apply-update', 'plan-selected', 'apply-selected')):
            print(json.dumps({'error': 'Update review or execution failed. The plan may have changed or its metadata expired. Check for updates and review again.'}))
            return 2
        print('Ironclad: operation declined, failed or unavailable. Existing results are retained. Check the documented source, permissions and local service requirements.', file=__import__('sys').stderr)
        return 2
    finally:
        if args.hold and __import__('sys').stdin.isatty():
            try:
                input('\nPress Enter to close…')
            except EOFError:
                pass
