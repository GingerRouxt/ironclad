"""Explicitly enabled background protection maintenance; never installs code."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import urllib.request
from . import sensor_policy
from .model import now
from .storage import open_dir, private_dir, safe_file

NAME='protection-updates.json'
SERVICE_NAME='ironclad-protection-updates.service'
TIMER_NAME='ironclad-protection-updates.timer'
PLUGIN=Path.home()/'.config/omarchy/plugins/com.zerodaysecurity.ironclad'
SERVICE='''[Unit]
Description=Ironclad official malware signatures and engine release checks
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B %h/.config/omarchy/plugins/com.zerodaysecurity.ironclad/companion.py --state %h/.local/state/ironclad protection-maintain --allow-network --json
NoNewPrivileges=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryMax=1G
CPUQuota=20%
TasksMax=32
Nice=15
IOSchedulingClass=idle
TimeoutStartSec=12min
UMask=0077
StandardOutput=null
StandardError=null
'''
TIMER='''[Unit]
Description=Ironclad automatic protection updates
[Timer]
OnCalendar=*-*-* 00/4:00:00
OnActiveSec=5min
RandomizedDelaySec=15min
Persistent=true
[Install]
WantedBy=timers.target
'''
UNITS={SERVICE_NAME:SERVICE,TIMER_NAME:TIMER}


def read(state):
    try:directory=open_dir(state)
    except FileNotFoundError:return None
    try:
        meta=os.fstat(directory)
        if meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:raise ValueError('unsafe maintenance directory')
        try:fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        except FileNotFoundError:return None
        with os.fdopen(fd,'rb') as stream:
            meta=os.fstat(stream.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_size>16384:raise ValueError('unsafe maintenance record')
            data=json.loads(stream.read(16385))
        if not isinstance(data,dict) or data.get('schema')!=1 or data.get('outcome') not in ('running','ok','failed'):raise ValueError('invalid maintenance record')
        for key in ('attempted_at','signature_success_at','release_checked_at'):
            value=data.get(key)
            if value is not None and (not isinstance(value,str) or len(value)>64 or datetime.fromisoformat(value).tzinfo is None):raise ValueError('invalid maintenance time')
        versions=data.get('releases',{})
        if not isinstance(versions,dict) or set(versions)-{'clamav','falco'} or any(not isinstance(v,str) or not re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}',v) for v in versions.values()):raise ValueError('invalid releases')
        return data
    finally:os.close(directory)


def write(state,data):
    directory=private_dir(state);name='.updates-'+secrets.token_hex(8)
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(name,NAME,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
    finally:
        try:os.unlink(name,dir_fd=directory)
        except FileNotFoundError:pass
        os.close(directory)


@contextmanager
def signature_lock(state):
    directory=private_dir(state);lock=None
    try:
        lock=safe_file(directory,'signature-update.lock');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        if lock is not None:os.close(lock)
        os.close(directory)


def release_version(repository):
    from .maintenance import NoRedirect
    if repository not in ('Cisco-Talos/clamav','falcosecurity/falco'):raise ValueError('unapproved release source')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    request=urllib.request.Request('https://api.github.com/repos/'+repository+'/releases/latest',headers={'User-Agent':'Ironclad protection maintenance','Accept':'application/vnd.github+json'})
    with opener.open(request,timeout=15) as response:body=response.read(262145)
    if len(body)>262144:raise ValueError('release metadata limit')
    data=json.loads(body)
    if not isinstance(data,dict) or data.get('draft') is not False or data.get('prerelease') is not False:raise ValueError('release not stable')
    tag=data.get('tag_name','')
    if not isinstance(tag,str):raise ValueError('invalid release version')
    if repository=='Cisco-Talos/clamav':tag=tag.removeprefix('clamav-')
    if not re.fullmatch(r'v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}',tag):raise ValueError('invalid release version')
    return tag.removeprefix('v')


def age_hours(value):
    if not value:return None
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(value)).total_seconds()/3600
    return age if age>=0 else None


def maintain(state,allow_network):
    if not allow_network:raise ValueError('network approval required')
    from . import malware
    # Shared with manual signature refresh: concurrent updaters cannot race.
    with signature_lock(state):
        previous=read(state) or {}
        data={**previous,'schema':1,'attempted_at':now(),'outcome':'running'}
        write(state,data)
        errors=[]
        try:
            malware.update_signatures(state,True,_locked=True)
            data['signature_success_at']=now()
        except (OSError,ValueError):errors.append('signatures')
        age=age_hours(previous.get('release_checked_at'))
        if age is None or age>=24:
            try:
                versions={name:release_version(repo) for name,repo in [('clamav','Cisco-Talos/clamav'),('falco','falcosecurity/falco')]}
                data.update(releases=versions,release_checked_at=now(),release_error=False)
            except (OSError,ValueError):data['release_error']=True;errors.append('releases')
        elif previous.get('release_error'):errors.append('releases')
        data.update(outcome='failed' if errors else 'ok',errors=errors)
        write(state,data)
        return data


def unit_directory():return Path.home()/'.config/systemd/user'


def control(*args):
    from .maintenance import capture
    return capture(['/usr/bin/systemctl','--user',*args],timeout=8).strip()


def conflicts():
    bases=[unit_directory(),Path.home()/'.local/share/systemd/user',Path('/etc/systemd/user'),Path('/usr/lib/systemd/user')]
    return any((base/name).exists() or (base/name).is_symlink() for base in bases for name in (SERVICE_NAME+'.d',TIMER_NAME+'.d','service.d','timer.d')+(() if base==unit_directory() else tuple(UNITS)))


def configure(enabled):
    if conflicts():raise ValueError('maintenance unit overrides require review')
    directory=open_dir(unit_directory(),create=True);created=[]
    try:
        meta=os.fstat(directory)
        if meta.st_uid!=os.getuid() or meta.st_mode&0o022:raise ValueError('unsafe unit directory')
        # Validate all existing files before making any changes.
        for name,body in UNITS.items():
            try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            except FileNotFoundError:continue
            with os.fdopen(fd) as stream:
                meta=os.fstat(stream.fileno())
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or meta.st_mode&0o077 or stream.read(8192)!=body:raise ValueError('changed maintenance unit; preserve for review')
        if enabled:
            if not (PLUGIN/'companion.py').is_file():raise ValueError('install the plugin first')
            os.close(private_dir(Path.home()/'.local/state/ironclad'))
            for name,body in UNITS.items():
                try:fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                except FileExistsError:continue
                created.append(name)
                with os.fdopen(fd,'w') as stream:stream.write(body)
            try:control('daemon-reload');control('enable','--now',TIMER_NAME)
            except (OSError,ValueError):
                # Keep files if stopping cannot be confirmed.
                control('disable','--now',TIMER_NAME)
                for name in created:os.unlink(name,dir_fd=directory)
                control('daemon-reload');raise
        else:
            # Let an in-flight signature update finish; only disable future runs.
            control('disable','--now',TIMER_NAME)
            for name in UNITS:
                try:os.unlink(name,dir_fd=directory)
                except FileNotFoundError:pass
            control('daemon-reload')
    finally:os.close(directory)


def status(state):
    issues=[]
    try:record=read(state)
    except (OSError,ValueError,TypeError):record=None;issues.append('Update history could not be verified.')
    try:
        values=dict(line.split('=',1) for line in control('show',TIMER_NAME,'--property=LoadState,ActiveState,UnitFileState','--no-pager').splitlines() if '=' in line)
        active=values.get('LoadState')=='loaded' and values.get('ActiveState')=='active' and values.get('UnitFileState')=='enabled'
    except (OSError,ValueError):active=False;issues.append('Background update timer could not be verified.')
    if not active:issues.append('Automatic protection updates are off or unavailable.')
    try:
        service=dict(line.split('=',1) for line in control('show',SERVICE_NAME,'--property=Result,ExecMainStatus','--no-pager').splitlines() if '=' in line)
        if service.get('Result') not in (None,'success') or service.get('ExecMainStatus') not in (None,'0'):
            issues.append('The background maintenance service failed. Review its status; the timer will retry on schedule.')
    except (OSError,ValueError):issues.append('The background maintenance service result could not be verified.')
    if not record:issues.append('No background update has completed yet.')
    elif record['outcome']=='failed':issues.append('The last protection update failed; existing signatures and release information were retained. Another attempt runs on the next schedule.')
    elif record['outcome']=='running':issues.append('Protection maintenance is running or was interrupted; completion has not been verified.')
    success_age=age_hours(record.get('signature_success_at')) if record else None
    if success_age is None or success_age>24:issues.append('A successful signature refresh has not been verified within 24 hours.')
    release_age=age_hours(record.get('release_checked_at')) if record else None
    if release_age is None or release_age>48 or record.get('release_error'):issues.append('Engine release checks are missing, stale or unavailable.')
    from .maintenance import capture
    try:
        match=re.search(r'ClamAV ([0-9]+\.[0-9]+\.[0-9]+)',capture(['/usr/bin/clamscan','--version'],timeout=5))
        clamav=match.group(1) if match else None
    except (OSError,ValueError):clamav=None
    releases=record.get('releases',{}) if record else {}
    engines=[]
    for name,installed in [('clamav',clamav),('falco',sensor_policy.FALCO_VERSION)]:
        latest=releases.get(name)
        newer=bool(installed and latest and tuple(map(int,latest.split('.')))>tuple(map(int,installed.split('.'))))
        if newer:issues.append(name.title()+' has a newer upstream release; review a tested engine update.')
        engines.append({'name':name,'installed':installed,'latest':latest,'update_available':newer})
    git_managed=(PLUGIN/'.git').is_dir()
    return {'automatic':active,'cadence':'Every 4 hours, with up to 15 minutes of jitter; engine release metadata daily. Runs while your user session is available.',
            'last_attempt':record.get('attempted_at') if record else None,'last_success':record.get('signature_success_at') if record else None,
            'issues':issues,'engines':engines,'policy_version':sensor_policy.VERSION,
            'plugin_update':'Review plugin updates with omarchy plugin update com.zerodaysecurity.ironclad; engine/rule changes need separate tested installation.' if git_managed else 'Local development install: no published plugin update channel is configured. Engine and rule updates require a tested Ironclad release.',
            'plugin_managed':git_managed}
