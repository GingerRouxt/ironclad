"""Read bounded local action receipts; never execute a recovery instruction."""
from datetime import datetime, timezone
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat
from .storage import open_dir


NAMES = {'repairs': re.compile(r'[a-f0-9]{32}\.(?:request|result)\.json'),
         'maintenance': re.compile(r'[0-9]{1,24}-(?:started|finished)\.json')}


def text(value, limit=700):
    if not isinstance(value, str): return ''
    return ''.join(c for c in value if c in '\n\t' or ord(c) >= 32)[:limit]


def timestamp(value):
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        if not isinstance(value, str): return ''
        date = datetime.fromisoformat(value)
        if date.tzinfo is None: return ''
        return date.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return ''


def receipts(state, folder, limits):
    """No directory creation; refuse links, special files and shared receipts."""
    try:
        fd = open_dir(Path(state)/folder)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        limits.append(folder + ' history could not be safely opened.')
        return {}
    rows = {}
    try:
        meta = os.fstat(fd)
        if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o700:
            raise ValueError('unsafe receipt directory')
        with os.scandir(fd) as entries:
            names = [e.name for e in islice(entries, 513)]
        if len(names) > 512:
            limits.append(folder + ' history exceeds the 512-file read limit; some records are omitted.')
        for name in names[:512]:
            if not NAMES[folder].fullmatch(name): continue
            try:
                item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(item, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536:
                        raise ValueError('unsafe receipt')
                    body = json.loads(stream.read(65537))
                if not isinstance(body, dict): raise ValueError('invalid receipt')
                rows[name] = body
            except (OSError, ValueError, UnicodeError):
                if 'Some local receipts could not be read safely.' not in limits:
                    limits.append('Some local receipts could not be read safely.')
    except (OSError, ValueError):
        limits.append(folder + ' history could not be safely read.')
    finally:
        os.close(fd)
    return rows


def history(state):
    limits = []
    entries = []
    for folder, kind in [('repairs', 'repair'), ('maintenance', 'update')]:
        rows = receipts(state, folder, limits)
        ids = {name.split('.')[0] if kind == 'repair' else name.split('-')[0] for name in rows}
        for identifier in ids:
            start = rows.get(identifier + ('.request.json' if kind == 'repair' else '-started.json'), {})
            end = rows.get(identifier + ('.result.json' if kind == 'repair' else '-finished.json'))
            plan = start.get('plan', {})
            if not isinstance(plan, dict): plan = {}
            # A completion record proves only the recorded action's postcondition.
            outcome = 'incomplete' if end is None else 'verified' if end.get('verified') is True else 'unverified'
            result = end or {}
            target = text(plan.get('target') or result.get('target'), 256)
            title = text(plan.get('title'), 256) if kind == 'repair' else 'Update ' + text(plan.get('name') or target, 160)
            detail = text(result.get('message')) if kind == 'repair' else text(result.get('verification_scope'))
            if outcome == 'incomplete':
                detail = 'No completion record. This action may be running or interrupted; check the current state before retrying.'
            elif not detail:
                detail = 'The recorded result did not verify completion. Check the current state before retrying.' if outcome != 'verified' else 'The recorded action passed its verification. This does not certify the entire machine.'
            if outcome == 'unverified': detail = 'Completion was not verified. ' + detail
            versions = result.get('observed_versions', [])
            if not isinstance(versions, list): versions = []
            observed = ', '.join(text(v, 120) for v in versions[:8] if isinstance(v, str))
            version_detail = ('Before: ' + text(plan.get('installed'), 120) + ' · Observed after: ' + (observed or 'not recorded')) if kind == 'update' else ''
            if kind == 'update' and outcome != 'verified' and result.get('reason'):
                detail += ' Reason: ' + text(result['reason'], 120)
            entries.append({'id':kind+':'+identifier, 'kind':kind, 'at':timestamp(result.get('finished_at')) or timestamp(start.get('started_at')) or timestamp(plan.get('created')), 'title':title or 'Reviewed repair', 'target':target or 'Target not recorded', 'check_id':text(plan.get('check_id') or result.get('check_id'), 128), 'outcome':outcome, 'detail':detail, 'recovery':text(plan.get('undo') or plan.get('recovery') or result.get('undo')), 'versions':version_detail})
    entries.sort(key=lambda row: (row['at'], row['id']), reverse=True)
    if len(entries) > 64: limits.append('Showing the newest 64 recorded actions; older receipts remain on this machine.')
    return {'entries':entries[:64], 'limits':limits[:8]}
