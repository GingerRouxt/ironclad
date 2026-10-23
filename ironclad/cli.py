"""Explicit local workflows. No remote access or privileged action surface."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
from . import __version__
from .collectors import scan
from .model import SEVERITIES, validate_scan
from .reports import render
from .storage import Store, compare, export, scan_lock


def parser():
    p = argparse.ArgumentParser(description='ZDS Ironclad — offline system intelligence')
    p.add_argument('--version', action='version', version=__version__)
    p.add_argument('--state', type=Path, default=Path(os.environ.get('XDG_STATE_HOME', Path.home()/'.local/state'))/'ironclad')
    commands = p.add_subparsers(dest='command', required=True)
    for name in ('doctor', 'self-test'): commands.add_parser(name)
    c = commands.add_parser('check'); c.add_argument('--profile', choices=['quick', 'full', 'super'], default='quick'); c.add_argument('--format', choices=['json', 'markdown', 'html'], default='json'); c.add_argument('--save', action='store_true'); c.add_argument('--scope', type=Path)
    c = commands.add_parser('catalog'); c.add_argument('--profile', choices=['quick','full','super'], default='super')
    c = commands.add_parser('findings'); c.add_argument('--severity', choices=sorted(SEVERITIES), default='info')
    c = commands.add_parser('report'); c.add_argument('--format', choices=['html', 'json', 'markdown'], default='html'); c.add_argument('--output', type=Path, required=True); c.add_argument('--fresh', action='store_true')
    c = commands.add_parser('baseline'); c.add_argument('operation', choices=['save'])
    commands.add_parser('compare')
    commands.add_parser('history')
    commands.add_parser('ai-packet')
    commands.add_parser('software')
    c = commands.add_parser('action'); c.add_argument('operation', choices=['preview', 'apply', 'rollback']); c.add_argument('action_id', choices=['baseline.replace', 'home.remove_world_write']); c.add_argument('--receipt')
    c = commands.add_parser('schedule'); c.add_argument('operation', choices=['status', 'preview', 'enable', 'disable'])
    return p


def confirm(phrase):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('interactive terminal required; approval cannot be piped')
    if input(f'Type {phrase!r} to approve this exact local operation: ') != phrase:
        raise ValueError('approval declined')


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise ValueError('run as an unprivileged user')
        if args.command == 'catalog':
            from .check_catalog import inventory
            print(json.dumps(inventory(args.profile),indent=2));return 0
        if args.command == 'software':
            from .software import inventory
            print(json.dumps(inventory(args.state), separators=(',', ':')))
            return 0
        if args.command in ('doctor', 'self-test'):
            from .runner import COMMANDS
            print(json.dumps({'version': __version__, 'python': list(sys.version_info[:3]), 'offline': True, 'network_guard': __import__('ironclad.offline', fromlist=['active']).active, 'privileged_helper': False,
                              'commands_present': {k: (Path('/usr/bin')/v[0]).exists() for k, v in COMMANDS.items()},
                              'runtime': Path(os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')).is_dir()}))
            return 0
        if args.command == 'schedule':
            from . import scheduling
            if args.operation == 'status':
                print(json.dumps(scheduling.status()))
            elif args.operation == 'preview':
                print(json.dumps(scheduling.plan('enable'), indent=2))
            else:
                plan = scheduling.plan(args.operation)
                print(json.dumps(plan, indent=2))
                confirm('SCHEDULE '+args.operation.upper()+' '+plan['digest'][:12])
                if args.operation == 'enable': scheduling.enable(plan['digest'])
                else: scheduling.disable(plan['digest'])
                print('Approved schedule operation completed; history retained.')
            return 0
        if args.command == 'check':
            with scan_lock():
                result = scan(args.profile, scope=args.scope, state=args.state)
                if args.save:
                    with Store(args.state) as store: store.save(result)
            print(render(result, args.format))
            return 0
        if args.command == 'report' and args.fresh:
            with scan_lock():
                result = scan('quick')
            export(args.output, render(result, args.format))
            print(json.dumps({'operation':'report','message':'Redacted report exported with owner-only permissions.'}))
            return 0
        with Store(args.state) as store:
            if args.command == 'action' and args.action_id == 'home.remove_world_write':
                from . import actions
                if args.operation == 'preview':
                    print(json.dumps(actions.preview(args.action_id).public()))
                elif args.operation == 'apply':
                    plan = actions.preview(args.action_id)
                    print(json.dumps(plan.public(), indent=2))
                    confirm('APPLY '+plan.digest()[:12])
                    receipt = actions.apply(store, plan, plan.digest())
                    print(json.dumps({'applied':True, 'receipt':receipt, 'postcheck':'home other-write permission removed'}))
                else:
                    if not args.receipt: raise ValueError('receipt required')
                    print('Undo restores previous home permissions and may restore world-write.')
                    confirm('ROLLBACK '+args.receipt)
                    actions.rollback(store,args.receipt)
                    print('Approved rollback applied.')
                return 0
            if args.command == 'history':
                rows=store.db.execute('SELECT body FROM scans ORDER BY id DESC LIMIT 32').fetchall()
                scans=[validate_scan(json.loads(row[0])) for row in rows]
                from .actions import journal
                from .activity import history
                print(json.dumps({'operation':'history','scans':[{'scan_id':s['scan_id'],'collected_at':s['collected_at'],'checks':len(s['checks'])} for s in scans], 'actions':journal(store), 'activity':history(args.state)}))
            elif args.command == 'ai-packet':
                from .ai import explanation_packet
                print(json.dumps(explanation_packet(store.latest())))
            elif args.command == 'findings':

                levels = ['info', 'low', 'medium', 'high', 'critical']
                result = [c for c in store.latest()['checks'] if levels.index(c['severity']) >= levels.index(args.severity)]
                print(json.dumps(result))
            elif args.command == 'report':
                export(args.output, render(store.latest(), args.format))
                print('Report created with mode 0600; existing paths are never overwritten.')
            elif args.command == 'compare':
                print(json.dumps(compare(store.baseline(), store.latest())))
            elif args.command in ('baseline', 'action'):
                operation = 'apply' if args.command == 'baseline' else args.operation
                if operation == 'preview':
                    print(json.dumps({'action_id': 'baseline.replace', 'scan_id': store.latest()['scan_id'], 'scope': 'Ironclad local baseline only', 'impact': 'Replace one baseline, retain previous for rollback; no system changes', 'reversible': True, 'approval': 'interactive exact scan ID', 'root': False}))
                elif operation == 'apply':
                    result = store.latest()
                    print('Replace Ironclad baseline with saved scan '+result['scan_id']+'; old baseline retained for rollback.')
                    confirm('baseline '+result['scan_id'])
                    receipt = store.replace_baseline(result)
                    if store.baseline()['scan_id'] != result['scan_id']:
                        raise ValueError('baseline postcondition failed')
                    print(json.dumps({'applied': True, 'receipt': receipt, 'scan_id': result['scan_id']}))
                else:
                    if args.receipt is None: raise ValueError('rollback receipt required')
                    confirm('rollback '+str(args.receipt))
                    store.rollback(int(args.receipt))
                    print('Rollback applied; receipt consumed.')
        return 0
    except (OSError, ValueError, sqlite3.Error, EOFError, UnicodeError):
        # No raw exceptions or potentially sensitive command output in logs.
        print('Ironclad: operation failed or unavailable. Check permissions, state, dependencies, approval and documented limits.', file=sys.stderr)
        return 2


def entrypoint():
    """Supported installed console entrypoint always applies the offline policy."""
    from .offline import restrict
    try:
        restrict()
    except (OSError, ValueError, AttributeError):
        print('Ironclad: trusted system libseccomp and supported Linux architecture required; refusing to run.', file=sys.stderr)
        return 2
    return main()
