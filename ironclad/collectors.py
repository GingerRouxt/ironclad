"""Small platform probes. Never crawl personal files or collect command lines."""
import json
import os
from pathlib import Path
import platform
import stat
import time
from uuid import uuid4
from .model import Check, Evidence, now, validate_scan
from .runner import run


def read(path, limit=32768):
    with open(path, 'r', encoding='utf-8', errors='replace') as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("probe size limit")
    return value.strip()


def finding(id, summary, value, source, status="pass", severity="info", confidence="high", recommendation=None):
    c = Check(id, status, severity, summary, [Evidence(source, str(value))], confidence)
    if recommendation:
        c.recommendation = recommendation
    return c


def command_check(id, key, summary, parser=None, empty_ok=False):
    result = run(key)
    if result.state != "available" and not (empty_ok and result.state == "empty"):
        c = finding(id, "Probe unavailable; no conclusion", result.state, key, "unavailable", confidence="low")
        c.dependency_status = result.state
        return c
    return parser(result.output) if parser else finding(id, summary, result.output or "No entries reported", key)


def os_check():
    fields = dict(line.split('=', 1) for line in read('/etc/os-release').splitlines() if '=' in line)
    return finding('system.os', 'Operating system and kernel inventory',
                   json.dumps({"os": fields.get('ID', '').strip('"'), "version": fields.get('VERSION_ID', '').strip('"'),
                               "kernel": platform.release(), "architecture": platform.machine()}), '/etc/os-release + uname')


def cpu():
    load = os.getloadavg()
    count = os.cpu_count() or 1
    busy = load[0] > count * 1.5
    return finding('performance.cpu.load', 'Sustained work may exceed CPU capacity' if busy else 'CPU load within advisory threshold',
                   f'logical_cpus={count}, load_1_5_15={load}', '/proc/loadavg', 'attention' if busy else 'pass', 'medium' if busy else 'info',
                   recommendation='Compare sustained load and pressure before changing workloads or scheduler settings.')


def memory():
    values = dict(line.split(':', 1) for line in read('/proc/meminfo').splitlines())
    total = int(values['MemTotal'].split()[0]); available = int(values['MemAvailable'].split()[0])
    ratio = available / total
    return finding('performance.memory', 'Available memory is low' if ratio < .1 else 'Memory headroom available',
                   f'total_kib={total}, available_kib={available}, swap_total={values.get("SwapTotal", "unknown").strip()}',
                   '/proc/meminfo', 'attention' if ratio < .1 else 'pass', 'medium' if ratio < .1 else 'info')


def disk():
    data = os.statvfs('/')
    ratio = data.f_bavail / max(data.f_blocks, 1)
    inode = data.f_favail / max(data.f_files, 1) if data.f_files else None
    state = 'critical' if ratio < .03 else 'attention' if ratio < .1 or (inode is not None and inode < .05) else 'pass'
    return finding('system.disk.free_space', f'Root filesystem free: {ratio:.1%}',
                   f'available_bytes={data.f_bavail * data.f_frsize}; inode_free_ratio={inode}', 'statvfs(/)', state,
                   'high' if state == 'critical' else 'medium' if state == 'attention' else 'info',
                   recommendation='Review storage use manually; no cache or personal files are deleted by Ironclad.')


def permissions():
    mode = stat.S_IMODE(Path.home().stat().st_mode)
    result = finding('security.home.permissions', f'Home permission mode: {mode:04o}', f'mode={mode:04o}', 'home directory metadata',
                   'attention' if mode & 0o002 else 'pass', 'medium' if mode & 0o002 else 'info',
                   recommendation='World-writable home directories warrant review. ACLs and shared-home requirements need separate evaluation.')
    if mode & 0o002:
        result.remediation_action_ids = ['home.remove_world_write']
    return result


def sysctl():
    value = read('/proc/sys/kernel/randomize_va_space')
    return finding('security.kernel.aslr', 'ASLR enabled' if value == '2' else 'ASLR differs from full randomization', value,
                   '/proc/sys/kernel/randomize_va_space', 'pass' if value == '2' else 'attention', 'info' if value == '2' else 'medium')


def sockets(output):
    # Preserve protocol/port/bind scope, never IPs, PIDs or process arguments.
    listeners=[]; wildcard=0
    for line in output.splitlines():
        fields=line.split()
        if len(fields)<6 or fields[0] not in ('tcp','udp'): continue
        local=fields[4]
        scope='wildcard' if local.startswith(('0.0.0.0:','[::]:','*:')) else 'loopback' if local.startswith(('127.','[::1]:','::1:')) else 'specific-address'
        wildcard+=scope=='wildcard'
        port=local.rsplit(':',1)[-1]
        if port.isdecimal() and 0<int(port)<=65535:
            listeners.append({'protocol':fields[0],'port':int(port),'bind_scope':scope})
    result=finding('network.listeners', f'{len(output.splitlines())} listening sockets; {wildcard} wildcard binds',
                   f'listeners={len(output.splitlines())}; wildcard={wildcard}; addresses omitted', 'ss -H -lntu',
                   'attention' if wildcard else 'pass', 'low' if wildcard else 'info', 'medium',
                   'Review intentional listener ports and firewall rules. Wildcard binding does not prove internet reachability.')
    result.evidence.append(Evidence('ss protocol/port/scope; first 16 only',json.dumps(listeners[:16])))
    return result


def failed_units(output, id, key):
    count = len(output.splitlines())
    # Only known platform unit labels enter shareable evidence. Custom names,
    # descriptions and instance identifiers may contain personal information.
    known = {'systemd-pcrlogin@.service', 'systemd-pcrproduct.service',
             'systemd-tpm2-setup-early.service', 'systemd-tpm2-setup.service',
             'systemd-timesyncd.service', 'avahi-daemon.service',
             'NetworkManager.service', 'bluetooth.service', 'sshd.service',
             'cups.service', 'docker.service', 'podman.service'}
    names = []
    for line in output.splitlines()[:32]:
        fields = line.split()
        if not fields: continue
        unit = fields[0]
        if '@' in unit:
            unit = unit.split('@', 1)[0] + '@.service'
        if unit in known and unit not in names: names.append(unit)
    result = finding(id, f'{count} failed units', f'failed_units={count}', key,
                     'attention' if count else 'pass', 'medium' if count else 'info',
                     recommendation='Inspect failures with systemctl; retain essential desktop, network, security and backup services.')
    result.evidence.append(Evidence('Known failed platform services; instances omitted', ', '.join(names) or 'No recognized platform service names; inspect locally for exact targets.'))
    return result


def persistence():
    counts = {}
    for name, path in [('xdg_user', Path.home()/'.config/autostart'), ('user_units', Path.home()/'.config/systemd/user'), ('cron_system', Path('/etc/cron.d'))]:
        if not path.exists():
            counts[name] = 0
            continue
        with os.scandir(path) as entries:
            count = 0
            for _ in entries:
                count += 1
                if count > 1024:
                    raise ValueError('entry limit')
        counts[name] = count
    return finding('security.persistence.inventory', 'Persistence entry counts; contents not inspected', json.dumps(counts), 'directory metadata', confidence='medium')


def backups():
    found = [x for x in ('restic', 'borg', 'snapper', 'timeshift') if (Path('/usr/bin')/x).exists()]
    return finding('recovery.backup.discovery', 'Backup tooling detected; success and recoverability unverified' if found else 'Backup method unknown; custom backups may exist',
                   ', '.join(found) or 'No supported binary detected', '/usr/bin metadata', 'unavailable', confidence='low')


def secure_boot():
    directory = Path('/sys/firmware/efi/efivars')
    if not directory.exists():
        return finding('security.boot.secure_boot', 'EFI variables unavailable; boot mode unverified', 'unavailable', str(directory), 'unavailable', confidence='low')
    matches = list(directory.glob('SecureBoot-*'))[:2]
    if len(matches) != 1:
        return finding('security.boot.secure_boot', 'Secure Boot variable unavailable', 'unavailable', str(directory), 'unavailable', confidence='low')
    with matches[0].open('rb') as f:
        value = f.read(5)
    enabled = len(value) == 5 and value[4] == 1
    return finding('security.boot.secure_boot', 'Secure Boot enabled' if enabled else 'Secure Boot not observed enabled', str(enabled), 'EFI SecureBoot variable', 'pass' if enabled else 'attention', 'info' if enabled else 'low')


def disks(output):
    data = json.loads(output)
    def flatten(items, depth=0):
        if depth > 10: raise ValueError('device nesting limit')
        for item in items[:256]:
            yield item
            yield from flatten(item.get('children', []), depth+1)
    items = list(flatten(data['blockdevices']))[:512]
    fs = sorted({x.get('fstype') for x in items if isinstance(x.get('fstype'), str)})
    return finding('storage.filesystems', 'Filesystem types and encryption-container visibility',
                   f'filesystems={fs}; crypt_mapping_visible={any(x.get("type") == "crypt" for x in items)}; coverage not verified',
                   'lsblk TYPE,FSTYPE', confidence='medium')


def thermal():
    readings = []
    for path in sorted(Path('/sys/class/thermal').glob('thermal_zone*/temp'))[:32]:
        try:
            value = int(read(path, 64))/1000
            if -20 <= value <= 150:
                readings.append(value)
        except (OSError, ValueError):
            continue
    return finding('hardware.thermal', 'Reported thermal sensor temperatures; vendor thresholds unverified',
                   json.dumps(readings), 'sysfs thermal_zone*/temp', 'pass' if readings else 'unavailable', confidence='medium' if readings else 'low')


def package_count(id, key, label):
    return command_check(id, key, label,
                         lambda output: finding(id, f'{label}: {len(output.splitlines())}', f'count={len(output.splitlines())}', key,
                                                confidence='medium'), empty_ok=True)


def scan(profile='quick', scope=None, state=None):
    if profile not in ('quick','full','super'): raise ValueError('unsupported scan profile')
    started = time.monotonic()
    probes = [os_check, cpu, memory, disk, permissions, sysctl,
              lambda: finding('performance.pressure.memory', 'Memory pressure stall information', read('/proc/pressure/memory'), '/proc/pressure/memory'),
              lambda: finding('system.uptime', 'Uptime in seconds', read('/proc/uptime').split()[0], '/proc/uptime'),
              lambda: command_check('startup.units.user_failed', 'units', '', lambda o: failed_units(o, 'startup.units.user_failed', 'systemctl --user --failed')),
              lambda: command_check('startup.units.system_failed', 'system_units', '', lambda o: failed_units(o, 'startup.units.system_failed', 'systemctl --failed')),
              lambda: command_check('startup.boot', 'boot', 'Boot duration reported by systemd'),
              lambda: package_count('packages.installed', 'packages', 'Installed pacman packages'),
              lambda: package_count('packages.foreign', 'foreign', 'Packages absent from configured sync databases; not necessarily AUR'),
              lambda: package_count('packages.cached_updates', 'updates', 'Updates according to local database; freshness unknown'),
              lambda: command_check('network.listeners', 'sockets', '', sockets),
              lambda: command_check('storage.filesystems', 'disks', '', disks),
              backups, persistence, secure_boot, thermal,
              lambda: finding('security.firewall', 'Active firewall enforcement requires a separate permission-aware check', 'Not probed; no elevated calls', 'coverage declaration', 'unavailable', confidence='low'),
              lambda: finding('security.ssh.effective_policy', 'Effective SSH policy not evaluated; Includes and Match require authoritative evaluation', 'No configuration read', 'coverage declaration', 'unavailable', confidence='low'),
              lambda: finding('security.lock', 'Live lock enforcement not verified', 'No desktop state changes', 'coverage declaration', 'unavailable', confidence='low')]
    if profile in ('full','super'):
        from . import advanced
        probes.extend([advanced.kernel_posture, advanced.lsm, advanced.network_counters, advanced.resolver,
                       advanced.process_metadata, advanced.setuid_inventory, advanced.container_access,
                       advanced.firmware_support, advanced.battery, advanced.storage_candidates,
                       
            lambda: command_check('startup.units.enabled', 'enabled_units', 'Enabled user unit inventory count', lambda o: finding('startup.units.enabled', 'Enabled user unit count', len(o.splitlines()), 'systemctl --user list-unit-files')),
            lambda: command_check('startup.timers', 'timers', 'User timer inventory count', lambda o: finding('startup.timers', 'Timer inventory count', len(o.splitlines()), 'systemctl --user list-timers')),
            lambda: command_check('hardware.power.profile', 'power', 'Active power profile'),
            lambda: command_check('network.clock', 'clock', 'NTP synchronization report'),
            lambda: command_check('hardware.gpu', 'gpu', 'PCI display controller presence', lambda o: finding('hardware.gpu', 'Display-class device count; acceleration unverified', sum(1 for l in o.splitlines() if 'VGA' in l or '3D controller' in l or 'Display controller' in l), 'lspci class metadata', confidence='medium')),
        ])
    if scope is not None:
        from .advanced import workspace
        probes.append(lambda: workspace(scope))
    expected_ids = ['system.os','performance.cpu.load','performance.memory','system.disk.free_space','security.home.permissions',
                    'security.kernel.aslr','performance.pressure.memory','system.uptime','startup.units.user_failed','startup.units.system_failed',
                    'startup.boot','packages.installed','packages.foreign','packages.cached_updates','network.listeners','storage.filesystems',
                    'recovery.backup.discovery','security.persistence.inventory','security.boot.secure_boot','hardware.thermal','security.firewall',
                    'security.ssh.effective_policy','security.lock']
    if profile in ('full','super'):
        expected_ids += ['security.kernel.restrictions','security.lsm','network.counters','network.resolver','security.process.metadata',
                         'security.privileged_binaries','developer.container.access','hardware.firmware.support','hardware.battery',
                         'storage.package_cache','startup.units.enabled','startup.timers','hardware.power.profile','network.clock','hardware.gpu']
    if scope is not None:
        expected_ids.append('developer.workspace.metadata')
    if len(expected_ids) != len(probes): raise ValueError('collector registry mismatch')
    # Remove coverage declarations: an unimplemented probe is not a real check.
    # The composite kernel restriction probe is replaced by individual controls.
    omitted={'security.firewall','security.ssh.effective_policy','security.lock','security.kernel.restrictions'}
    pairs=[(identifier,probe) for identifier,probe in zip(expected_ids,probes) if identifier not in omitted]
    from .expanded_checks import Context,evaluate
    from .check_catalog import selected,PROFILE_COUNTS
    context=Context(state)
    pairs.extend((rule.id,lambda rule=rule:evaluate(rule,context)) for rule in selected(profile))
    expected_ids=[identifier for identifier,_ in pairs];probes=[probe for _,probe in pairs]
    if len(probes)!=PROFILE_COUNTS[profile]+(1 if scope is not None else 0) or len(set(expected_ids))!=len(expected_ids):
        raise ValueError('invalid diagnostic catalog')
    checks = []
    for index, probe in enumerate(probes):
        begin = time.monotonic()
        if begin - started > 9:
            checks.extend(finding(id, 'Probe skipped: scan deadline', '9 second scan budget', 'engine', 'unavailable', confidence='low').dict() for id in expected_ids[index:])
            break
        try:
            check = probe()
        except (OSError, ValueError, KeyError, TypeError):
            # Do not persist paths, command errors or raw tracebacks.
            check = finding(expected_ids[index], 'Probe unavailable; no conclusion', 'Permission, data or platform limitation', 'engine', 'unavailable', confidence='low')
        if check.status == 'unavailable' and check.dependency_status == 'available':
            check.dependency_status = 'unavailable'
        check.elapsed_ms = round((time.monotonic()-begin)*1000, 3)
        checks.append(check.dict())
    return validate_scan({'schema_version': '1.0', 'scan_id': str(uuid4()), 'collected_at': now(),
                          'host': {'platform': 'omarchy' if Path('/usr/bin/omarchy').exists() else platform.system().lower(),
                                   'kernel': platform.release(), 'redacted_id': 'local-only'},
                          'profile': profile, 'elapsed_ms': round((time.monotonic()-started)*1000, 3), 'checks': checks})
