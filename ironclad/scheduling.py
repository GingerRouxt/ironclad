"""Opt-in user scheduling, exact commands and owned-file rollback only."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
from .storage import open_dir
from .runner import limits

UNIT_ID = 'zds-ironclad'
SERVICE = '''[Unit]
Description=ZDS Ironclad opt-in offline read-only scan
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B %h/.config/omarchy/plugins/com.zerodaysecurity.ironclad/engine.py --state %S/ironclad check --profile full --save
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
StateDirectory=ironclad
StateDirectoryMode=0700
RuntimeDirectory=ironclad
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictSUIDSGID=true
LockPersonality=true
MemoryMax=256M
CPUQuota=20%
TasksMax=32
TimeoutStartSec=30
UMask=0077
StandardOutput=null
'''
TIMER = '''[Unit]
Description=ZDS Ironclad optional daily local scan
[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=false
[Install]
WantedBy=timers.target
'''
UNITS = {'zds-ironclad.service':SERVICE,'zds-ironclad.timer':TIMER}
OPERATIONS = {
    'reload': ['daemon-reload'],
    'enable': ['enable','--now','zds-ironclad.timer'],
    'disable': ['disable','--now','zds-ironclad.timer'],
    'enabled': ['is-enabled','zds-ironclad.timer'],
    'active': ['is-active','zds-ironclad.timer'],
}


def home(): return Path(pwd.getpwuid(os.getuid()).pw_dir)
def unit_directory(): return home()/'.config/systemd/user'
def installed_engine(): return home()/'.config/omarchy/plugins/com.zerodaysecurity.ironclad/engine.py'


def conflicts():
    result=[]
    bases=(unit_directory(), home()/'.local/share/systemd/user', Path('/etc/systemd/user'), Path('/usr/lib/systemd/user'))
    for base in bases:
        for name in ('zds-ironclad.service.d','zds-ironclad.timer.d','service.d','timer.d') + (() if base == unit_directory() else tuple(UNITS)):
            if (base/name).exists() or (base/name).is_symlink(): result.append(str(base/name))
    return result


def plan(operation):
    if operation not in ('enable','disable'): raise ValueError('schedule operation not allowed')
    files={name:hashlib.sha256(body.encode()).hexdigest() for name,body in UNITS.items()}
    details={'operation':operation, 'unit_names':list(UNITS), 'template_sha256':files,
             'cadence':'Daily; up to 30 min jitter, no missed-run catch-up',
             'impact':'Local saved full scans; no system configuration remediation, network calls or notifications',
             'commands':[['/usr/bin/systemctl','--user',*OPERATIONS[key]] for key in (('reload','enable') if operation=='enable' else ('disable','reload'))],
             'rollback':'Disable timer and remove only unchanged owned units; retain history and reports',
             'requires_root':False,'installed_engine_present':installed_engine().is_file(), 'conflicting_dropin_count':len(conflicts())}
    details['digest']=hashlib.sha256(json.dumps(details,sort_keys=True).encode()).hexdigest()
    return details


def control(operation):
    if operation not in OPERATIONS: raise ValueError('systemd operation not allowed')
    runtime=f'/run/user/{os.getuid()}'
    env={'PATH':'/usr/bin','LC_ALL':'C','XDG_RUNTIME_DIR':runtime,'DBUS_SESSION_BUS_ADDRESS':f'unix:path={runtime}/bus'}
    p=subprocess.Popen(['/usr/bin/systemctl','--user',*OPERATIONS[operation]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,start_new_session=True,preexec_fn=limits,cwd='/')
    try:
        try: return p.wait(timeout=5)
        except subprocess.TimeoutExpired: raise ValueError('systemd operation timed out') from None
    finally:
        try: os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        p.wait()


def status():
    # No file writes or daemon reload. Nonzero is reported as unknown/inactive.
    from .runner import run
    enabled=run('schedule_enabled')
    active=run('schedule_active')
    return {'unit_files_present':all((unit_directory()/name).is_file() for name in UNITS),
            'enabled':True if enabled.state=='available' and enabled.output.strip() in ('enabled','enabled-runtime') else None,
            'active':True if active.state=='available' and active.output.strip()=='active' else None,
            'note':'null means unknown/inactive, not a verified disabled state. Inspect systemctl --user status when needed.',
            'default':'Off until explicitly approved; units created by this program are owner-only.'}


def enable(approved_digest):
    current=plan('enable')
    if current['digest']!=approved_digest or not current['installed_engine_present'] or current['conflicting_dropin_count']:
        raise ValueError('plan changed or engine not installed')
    fd=open_dir(unit_directory(),create=True)
    created=[]
    try:
        meta=os.fstat(fd)
        if meta.st_uid!=os.getuid() or meta.st_mode & 0o022:
            raise ValueError('unsafe unit directory permissions')
        # Refuse replacement even when an existing file happens to match.
        for name in UNITS:
            try: os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError('existing unit must be reviewed')
        for name,body in UNITS.items():
            out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            created.append(name)
            with os.fdopen(out,'w') as f: f.write(body); f.flush(); os.fsync(f.fileno())
        if control('reload')!=0 or control('enable')!=0:
            raise ValueError('activation failed')
    except BaseException:
        # Stop our partially enabled timer before removing its files. Retain
        # unchanged units if rollback cannot be confirmed.
        if created and control('disable')!=0:
            raise ValueError('activation failed; rollback unconfirmed, preserve units and inspect status') from None
        for name in created:
            with os.fdopen(os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)) as f:
                if f.read(8192)!=UNITS[name]: raise ValueError('unit changed; preserve for review')
            os.unlink(name,dir_fd=fd)
        if created: control('reload')
        raise
    finally: os.close(fd)


def disable(approved_digest):
    if plan('disable')['digest']!=approved_digest or conflicts(): raise ValueError('plan changed or unit drop-ins require review')
    fd=open_dir(unit_directory())
    try:
        # Validate every unit before changing activation state.
        for name,body in UNITS.items():
            f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            with os.fdopen(f) as stream:
                meta=os.fstat(stream.fileno())
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or stream.read(8192)!=body: raise ValueError('unowned or changed unit')
        if control('disable')!=0: raise ValueError('timer disable failed; preserve files')
        for name in UNITS: os.unlink(name,dir_fd=fd)
        if control('reload')!=0: raise ValueError('reload failed; timer disabled but manager state needs review')
    finally: os.close(fd)
