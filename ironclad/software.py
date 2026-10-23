"""Offline software metadata. Never executes user-installed tools or reads projects."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from datetime import datetime, timezone
from .model import now
from .runner import run
from .storage import open_dir, private_dir

LIMIT = 2048
MAX_BYTES = 524288
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9@+_.:/~-]{0,159}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.:~/-]{0,119}\Z')


def fingerprint(packages):
    return hashlib.sha256(json.dumps(packages, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read_cache(state):
    """No file/directory creation during read-only inventory."""
    try:
        fd = open_dir(state)
    except FileNotFoundError:
        return None
    try:
        meta = os.fstat(fd)
        if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o700:
            raise ValueError('unsafe cache directory')
        try:
            f = os.open('applications.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return None
        with os.fdopen(f, 'rb') as stream:
            meta = os.fstat(stream.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) != 0o600:
                raise ValueError('unsafe cache file')
            body = stream.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError('cache limit')
            data = json.loads(body)
        try:
            validate_cache(data)
        except (KeyError, TypeError, AttributeError, OverflowError) as error:
            raise ValueError('invalid cached metadata') from error
        return data
    finally:
        os.close(fd)


def validate_cache(data):
    if not isinstance(data, dict) or data.get('schema') != 2:
        raise ValueError('invalid cache schema')
    timestamp = datetime.fromisoformat(data['checked_at'])
    if timestamp.tzinfo is None or timestamp > datetime.now(timezone.utc):
        raise ValueError('invalid cache time')
    if not re.fullmatch(r'[0-9a-f]{64}', data['inventory_hash']):
        raise ValueError('invalid inventory hash')
    if not isinstance(data['updates'], dict) or len(data['updates']) > LIMIT:
        raise ValueError('invalid updates')
    for name, item in data['updates'].items():
        if not NAME.fullmatch(name) or not isinstance(item, dict) or any(not isinstance(item.get(k), str) or not VERSION.fullmatch(item[k]) for k in ('installed', 'available')):
            raise ValueError('invalid cached update')
    if not isinstance(data.get('channels'), dict) or set(data['channels']) - {'mise'} or any(v not in ('available', 'unavailable') for v in data['channels'].values()):
        raise ValueError('invalid update channels')
    for name, item in data['updates'].items():
        if item.get('source') != 'mise' or not isinstance(item.get('requested'), str) or not VERSION.fullmatch(item['requested']):
            raise ValueError('invalid managed-tool request')
    if data.get('advisory_status') not in ('available', 'unavailable') or not isinstance(data.get('advisories'), list) or len(data['advisories']) > 256:
        raise ValueError('invalid advisory snapshot')
    for item in data['advisories']:
        if not isinstance(item, dict) or not NAME.fullmatch(item.get('package', '')) or item.get('source') not in ('mise', 'uv tool') or not VERSION.fullmatch(item.get('affected', '')):
            raise ValueError('invalid application advisory')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{1,119}', item.get('id', '')) or item.get('severity') not in ('unknown','low','medium','high','critical') or not isinstance(item.get('issues'), list) or len(item['issues']) > 64:
            raise ValueError('invalid advisory identifier')
        if any(not isinstance(c, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{1,119}', c) for c in item['issues']):
            raise ValueError('invalid advisory references')

    if data.get('advisory_query_version',1) not in (1,2):raise ValueError('unsupported advisory query version')
    if data.get('advisory_inventory_hash') is not None and (not isinstance(data['advisory_inventory_hash'],str) or not re.fullmatch(r'[0-9a-f]{64}',data['advisory_inventory_hash'])):raise ValueError('invalid advisory inventory identity')
    if data.get('advisory_details_status','not checked') not in ('not checked','available','partial'):raise ValueError('invalid detail status')
    if data.get('kev_status', 'not checked') not in ('not checked', 'available', 'unavailable'):
        raise ValueError('invalid exploit-feed status')
    for item in data['advisories']:
        if 'known_exploited' in item and not isinstance(item['known_exploited'],bool): raise ValueError('invalid exploit evidence')
        if 'fixed_versions' in item and (not isinstance(item['fixed_versions'],list) or len(item['fixed_versions'])>32 or any(not isinstance(v,str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,79}',v) for v in item['fixed_versions'])):raise ValueError('invalid fixed releases')
        if 'summary' in item and (not isinstance(item['summary'],str) or len(item['summary'])>400): raise ValueError('invalid advisory summary')
        for key in ('exploit_checked_at',):
            if item.get(key) is not None and (not isinstance(item[key],str) or datetime.fromisoformat(item[key]).tzinfo is None):raise ValueError('invalid exploit time')
    if data.get('kev_checked_at') is not None and (not isinstance(data['kev_checked_at'],str) or datetime.fromisoformat(data['kev_checked_at']).tzinfo is None):raise ValueError('invalid intelligence time')


def write_cache(state, data):
    import secrets
    validate_cache(data)
    body = json.dumps(data, separators=(',', ':')).encode()
    if len(body) > MAX_BYTES:
        raise ValueError('cache limit')
    fd = private_dir(state)
    name = '.software-' + secrets.token_hex(8)
    try:
        f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(f, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, 'applications.json', src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def managed_tools(home):
    """Bounded metadata listing; no tool invocation, symlink traversal or config reads."""
    items = []
    root = Path(home) / '.local/share/mise/installs'
    try:
        fd = open_dir(root)
    except FileNotFoundError:
        return items, False
    try:
        with os.scandir(fd) as tools:
            for index, tool in enumerate(tools):
                if index >= 128:
                    return items, True
                if not NAME.fullmatch(tool.name) or not tool.is_dir(follow_symlinks=False):
                    continue
                child = os.open(tool.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    with os.scandir(child) as versions:
                        for number, version in enumerate(versions):
                            if number >= 64 or len(items) >= 256:
                                return items, True
                            if VERSION.fullmatch(version.name) and version.is_dir(follow_symlinks=False):
                                items.append({'name': tool.name, 'installed': version.name, 'available': None, 'source': 'mise', 'status': 'version only', 'advisories': []})
                finally:
                    os.close(child)
    finally:
        os.close(fd)
    return items, False


def parse_mise_list(body):
    data = json.loads(body)
    if not isinstance(data, dict) or len(data) > 256:
        raise ValueError('mise inventory limit')
    result = []
    for name, versions in data.items():
        if not NAME.fullmatch(name) or not isinstance(versions, list) or len(versions) > 64:
            raise ValueError('invalid mise metadata')
        for entry in versions:
            if not isinstance(entry, dict) or not entry.get('installed'):
                continue
            version = entry.get('version')
            requested = entry.get('requested_version', '')
            if not isinstance(version, str) or not VERSION.fullmatch(version) or not isinstance(requested, str) or (requested and not VERSION.fullmatch(requested)):
                raise ValueError('invalid tool version')
            result.append({'name': name, 'installed': version, 'available': None, 'source': 'mise', 'requested': requested, 'active': bool(entry.get('active')), 'status': 'check for updates', 'advisories': []})
    if len(result) > 256:
        raise ValueError('mise inventory limit')
    return result


def parse_mise_outdated(body):
    data = json.loads(body)
    if not isinstance(data, dict) or len(data) > 256:
        raise ValueError('mise update limit')
    result = {}
    for name, row in data.items():
        if not NAME.fullmatch(name) or not isinstance(row, dict):
            raise ValueError('invalid mise update')
        current, latest, requested = row.get('current'), row.get('latest'), row.get('requested')
        if not all(isinstance(x, str) and VERSION.fullmatch(x) for x in (current, latest, requested)):
            raise ValueError('invalid mise update versions')
        if current != latest:
            result[name] = {'source': 'mise', 'installed': current, 'available': latest, 'requested': requested}
    return result


def parse_uv_tools(body):
    items = []
    for line in body.splitlines():
        if not line or line.startswith(('-', ' ')):
            continue
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*) v([A-Za-z0-9][A-Za-z0-9+_.-]*)(?: \(.*\))?', line)
        if not match:
            raise ValueError('unsupported uv tool metadata')
        items.append({'name': match[1], 'installed': match[2], 'available': None, 'source': 'uv tool', 'status': 'manager review', 'advisories': []})
        if len(items) > 128:
            raise ValueError('uv inventory limit')
    return items


def parse_flatpak(body):
    items = []
    for line in body.splitlines():
        fields = line.split('\t')
        if len(fields) != 2 or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,159}', fields[0]):
            raise ValueError('unsupported user Flatpak metadata')
        version = fields[1].strip() or 'unknown'
        if not VERSION.fullmatch(version):
            version = 'unknown'
        items.append({'name': fields[0], 'installed': version, 'available': None, 'source': 'Flatpak user', 'status': 'manager review', 'advisories': []})
        if len(items) > 256:
            raise ValueError('Flatpak inventory limit')
    return items


def local_launchers(home, managed_names):
    result = []
    root = Path(home)/'.local/bin'
    try:
        fd = open_dir(root)
    except FileNotFoundError:
        return result
    try:
        with os.scandir(fd) as entries:
            for index, entry in enumerate(entries):
                if index >= 256:
                    break
                if not NAME.fullmatch(entry.name) or entry.name in managed_names:
                    continue
                # Metadata only. A launcher is not proof the application is installed.
                meta = entry.stat(follow_symlinks=False)
                if stat.S_ISREG(meta.st_mode) and meta.st_mode & 0o111:
                    result.append({'name': entry.name, 'installed': 'unknown', 'available': None, 'source': 'local launcher', 'status': 'identify installer', 'advisories': []})
    finally:
        os.close(fd)
    return result


def inventory(state, home=None):
    home = home or Path.home()
    channels = {}
    items = []
    for command, channel, parser in [('user_mise', 'mise', parse_mise_list), ('user_uv', 'uv tool', parse_uv_tools), ('user_flatpak', 'Flatpak user', parse_flatpak)]:
        result = run(command)
        channels[channel] = 'available' if result.state in ('available', 'empty') else 'unavailable'
        if result.state == 'available':
            items.extend(parser(result.output))
    tools, truncated = managed_tools(home)
    known = {(re.sub(r'[^A-Za-z0-9_-]', '-', i['name']), i['installed']) for i in items if i['source'] == 'mise'}
    for tool in tools:
        if (tool['name'], tool['installed']) not in known:
            tool.update(status='installed version', active=False, requested='')
            items.append(tool)
    items.extend(local_launchers(home, {i['name'] for i in items}))
    identity = {i['source']+':'+i['name']+':'+i['installed']: i.get('requested', '') for i in items}
    cache = read_cache(state)
    same_inventory = bool(cache and cache['inventory_hash'] == fingerprint(identity))
    age = (datetime.now(timezone.utc)-datetime.fromisoformat(cache['checked_at'])).total_seconds() if cache else None
    fresh = same_inventory and age is not None and age <= 86400
    updates = cache['updates'] if fresh else {}
    from .threatintel import query_for
    for item in items:
        item['advisory_coverage'] = 'supported' if query_for(item) else 'not evaluated'
        update = updates.get(item['name']) if item['source'] == 'mise' else None
        if update and item['installed'] == update['installed'] and item.get('active') and item.get('requested') == update['requested']:
            item.update(available=update['available'], status='update available')
        elif item['source'] == 'mise' and item.get('active'):
            item['status'] = 'no listed update' if fresh and cache['channels'].get('mise') == 'available' else 'check for updates'
        item['advisories'] = [a for a in (cache['advisories'] if cache else []) if a['source'] == item['source'] and a['package'] == item['name'] and a['affected'] == item['installed']]
        if item['advisories']:
            item['status'] = 'security review'
        item['version_scope']='configured global' if item['source']=='mise' and item.get('active') else 'retained version' if item['source']=='mise' else 'installed tool'
        globals_for_tool=[i['installed'] for i in items if i['source']==item['source'] and i['name']==item['name'] and i.get('active')]
        item['configured_versions']=globals_for_tool
        fixed=list(dict.fromkeys(v for a in item['advisories'] for v in a.get('fixed_versions',[])))
        # Guidance is publisher metadata, never an automatically executable version plan.
        if item['source']=='mise' and item['name']=='go':
            same_branch=[v for v in fixed if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',v) and v.split('.')[:2]==item['installed'].split('.')[:2]]
            if same_branch:fixed=same_branch
        item['security_fixed_versions']=fixed
        source = item['source']
        if source == 'mise':
            item['next_step'] = 'Review a compatible update for this configured global tool. Project pins and other installed versions are kept.' if item['available'] else 'Check online for compatible versions. An older installed version may still be required by a project.'
            if item['advisories']:
                location='This version is configured globally.' if item.get('active') else 'This is a retained version; projects can still select it. Configured global version: '+(', '.join(globals_for_tool) or 'not verified')+'.'
                fix=' Publisher fixed releases: '+', '.join(fixed)+'.' if fixed else ' No fixed release was verified; refresh advisory details and read the publisher notice.'
                item['next_step']=location+fix+' Review project pins and rebuild affected programs before retiring an old toolchain. Retained versions are not automatically changed or removed.'
        elif source == 'uv tool':
            item['next_step'] = 'Review an update for this named tool through uv. uv resolves its configured source and dependencies; no project environment is changed.'
        elif source == 'Flatpak user':
            item['next_step'] = 'Review this application in your user Flatpak manager; it may also update its user-scoped runtime dependencies.'
        else:
            item['next_step'] = 'Identify the original installer or publisher first. This is a launcher, not a verified installed application; Ironclad will not run it or guess an update command.'
    return {'schema': 2, 'observed_at': now(), 'checked_at': cache['checked_at'] if cache else None, 'fresh': fresh, 'inventory_hash': fingerprint(identity), 'channels': channels, 'update_channels': cache['channels'] if cache else {}, 'items': sorted(items, key=lambda x: (x['name'], x['source'], x['installed'])), 'update_count': sum(bool(i['available']) for i in items), 'security_count': sum(bool(i['advisories']) for i in items), 'advisory_status': cache['advisory_status'] if cache and cache.get('advisory_query_version')==2 and cache.get('advisory_inventory_hash')==fingerprint(identity) else 'not checked', 'kev_status':cache.get('kev_status','not checked') if cache else 'not checked', 'kev_checked_at':cache.get('kev_checked_at') if cache else None, 'advisory_details_status':cache.get('advisory_details_status','not checked') if cache else 'not checked', 'limits': ['User apps, language runtimes and developer tools only; no OS packages or core Omarchy updater.', 'Compatible update availability is checked for configured global mise tools. uv/Flatpak offer manager review; local launchers need installer identification.', 'OSV matching covers uv Python tools, identified mise npm packages and the mise Go standard library. Other interpreter/SDK advisories, project dependencies, transitive tool dependencies and standalone binaries are not evaluated.'] + (['mise directory inventory truncated.'] if truncated else [])}
