"""Bounded metadata probes; no source, document, key or process argument reads."""
import grp
import json
import os
from pathlib import Path
import stat
import time
from .collectors import finding, read


def kernel_posture():
    expected = {'kernel/kptr_restrict':1, 'kernel/dmesg_restrict':1, 'fs/protected_hardlinks':1,
                'fs/protected_symlinks':1, 'kernel/yama/ptrace_scope':1}
    observed = {}; differences = 0
    for key, minimum in expected.items():
        try:
            value = int(read('/proc/sys/'+key,64)); observed[key]=value
            differences += value < minimum
        except (OSError, ValueError): observed[key]='unavailable'
    available = sum(isinstance(v,int) for v in observed.values())
    return finding('security.kernel.restrictions', f'{differences} kernel restrictions below advisory minima; {available}/{len(expected)} observed',
                   json.dumps(observed), '/proc/sys selected read-only nodes', 'attention' if differences else 'pass' if available else 'unavailable',
                   'low' if differences else 'info', 'medium',
                   'Review debugging and developer workflow needs before changing ptrace or kernel log access. No tuning applied.')


def lsm():
    path = Path('/sys/kernel/security/lsm')
    try: value = read(path,1024)
    except OSError:
        return finding('security.lsm', 'LSM state inaccessible; no disabled-protection conclusion', 'unavailable', str(path),'unavailable',confidence='low')
    return finding('security.lsm','Reported Linux security modules; policy enforcement unverified',value,str(path),confidence='medium')


def network_counters():
    received = sent = interfaces = 0
    for line in read('/proc/net/dev').splitlines()[2:]:
        if ':' not in line: continue
        values=line.split(':',1)[1].split()
        if len(values)<16: continue
        received+=int(values[0]); sent+=int(values[8]); interfaces+=1
    return finding('network.counters','Network byte totals since interface creation; no traffic inspection',
                   f'interfaces={interfaces}; received_bytes={received}; sent_bytes={sent}', '/proc/net/dev')


def resolver():
    # Resolver files contain nameservers/search domains, not Wi-Fi credentials.
    data=read('/etc/resolv.conf',8192)
    count=sum(l.strip().startswith('nameserver ') for l in data.splitlines())
    return finding('network.resolver',f'{count} resolver entries; DNS functionality and leaks not tested',
                   f'nameservers={count}; addresses and search domains omitted','/etc/resolv.conf',
                   'pass' if count else 'attention','info' if count else 'low', 'medium',
                   'Resolve configuration may be provided dynamically. External DNS and leak tests require explicit destination approval.')


def process_metadata():
    start=time.monotonic(); count=deleted=denied=world_writable=0; truncated=False
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdecimal(): continue
            if count>=2048 or time.monotonic()-start>.2:
                truncated=True; break
            count+=1
            try:
                target=os.readlink(entry.path+'/exe')
                deleted+=target.endswith(' (deleted)')
                mode=os.stat(entry.path+'/exe').st_mode
                world_writable+=bool(mode & stat.S_IWOTH)
            except OSError: denied+=1
    return finding('security.process.metadata','Process executable metadata; deleted binaries can follow legitimate upgrades',
                   f'observed={count}; deleted_executable={deleted}; world_writable={world_writable}; inaccessible_or_exited={denied}; truncated={truncated}',
                   '/proc/PID/exe metadata only','attention' if world_writable else 'pass','medium' if world_writable else 'info','medium',
                   'Corroborate executable changes against package updates. No process arguments, environment or memory collected.')


def setuid_inventory():
    count=checked=0; truncated=False; start=time.monotonic()
    with os.scandir('/usr/bin') as entries:
        for entry in entries:
            if checked>=4096 or time.monotonic()-start>.2:
                truncated=True; break
            checked+=1
            try: mode=entry.stat(follow_symlinks=False).st_mode
            except OSError: continue
            count+=bool(stat.S_ISREG(mode) and mode & (stat.S_ISUID|stat.S_ISGID))
    return finding('security.privileged_binaries','Setuid/setgid metadata inventory; presence alone is not suspicious',
                   f'count={count}; entries_checked={checked}; truncated={truncated}','/usr/bin metadata',confidence='medium')


def container_access():
    gids=set(os.getgroups())|{os.getgid()}; access=False
    try: access=grp.getgrnam('docker').gr_gid in gids
    except KeyError: pass
    socket=Path('/run/docker.sock')
    socket_present=socket.exists()
    return finding('developer.container.access','Docker group membership can confer host-level control' if access else 'No Docker group membership observed',
                   f'docker_group_member={access}; docker_socket_present={socket_present}; containers not queried',
                   'group membership and socket metadata','attention' if access else 'pass','medium' if access else 'info','high',
                   'Review Docker group access deliberately; prefer rootless containers where practical. Do not remove access automatically.')


def firmware_support():
    supported=Path('/usr/bin/fwupdmgr').is_file()
    return finding('hardware.firmware.support','Firmware update client detected; no online lookup or update performed' if supported else 'fwupd client not detected',
                   f'fwupdmgr_present={supported}; feed_freshness=unknown', '/usr/bin/fwupdmgr metadata', 'pass' if supported else 'unavailable',confidence='medium')


def battery():
    readings=[]
    for directory in sorted(Path('/sys/class/power_supply').glob('*'))[:16]:
        try:
            if read(directory/'type',64)!='Battery': continue
            value={'capacity_percent':read(directory/'capacity',64),'status':read(directory/'status',64)}
            readings.append(value)
        except OSError: continue
    return finding('hardware.battery','Battery capacity/status; design health unverified' if readings else 'No readable battery source',
                   json.dumps(readings),'sysfs power_supply','pass' if readings else 'not_applicable',confidence='medium')


def storage_candidates():
    # No recursive walk. Metadata/counts only in one conventional package cache.
    path=Path('/var/cache/pacman/pkg'); count=size=0; truncated=False; start=time.monotonic()
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if count>=4096 or time.monotonic()-start>.15:
                    truncated=True; break
                if not entry.name.endswith(('.pkg.tar.zst','.pkg.tar.xz')): continue
                meta=entry.stat(follow_symlinks=False)
                if stat.S_ISREG(meta.st_mode):
                    count+=1; size+=meta.st_size
    except OSError:
        return finding('storage.package_cache','Package cache unavailable','unavailable','cache metadata','unavailable',confidence='low')
    return finding('storage.package_cache','Package-cache candidates; retained rollback versions may be valuable',
                   f'packages={count}; apparent_bytes={size}; truncated={truncated}; reclaimable_bytes=unknown',str(path),confidence='medium',
                   recommendation='Review package rollback requirements and package-manager tooling. Nothing is classified as safe to delete automatically.')


def workspace(scope):
    scope=Path(scope)
    if not scope.is_absolute() or scope.is_symlink() or not scope.is_dir(): raise ValueError('explicit absolute real directory scope required')
    # Only allowlisted filename existence, no source/lock contents or recursive crawl.
    names=('uv.lock','Cargo.lock','package-lock.json','pnpm-lock.yaml','go.sum','pyproject.toml','Cargo.toml','package.json','go.mod')
    present=[name for name in names if (scope/name).is_file() and not (scope/name).is_symlink()]
    return finding('developer.workspace.metadata','Explicit workspace scope: toolchain manifest/lockfile presence only',
                   json.dumps({'recognized_files':present,'source_read':False,'recursive_scan':False}),'selected directory metadata',confidence='high')
