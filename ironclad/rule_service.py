#!/usr/bin/python3 -I
"""Root-owned rule maintenance. Fixed verbs, fixed signed upstream, no shell."""
import fcntl
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import stat
import subprocess
import sys
import tempfile
import time

BASE=Path('/var/lib/ironclad-rules')
UNIT='ironclad-rule-updates.service'
TIMER='ironclad-rule-updates.timer'
SENSOR='ironclad-sensor.service'
ENV={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C','HOME':'/'}
ROOT_UID=0
# Maintainer release gate; customer consent remains separately off by default.
# No environment override. See docs/FALCO_RULE_UPDATES.md for acceptance evidence.
RELEASE_READY=True


def directory(path):
    path=Path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child;meta=os.fstat(fd)
            if meta.st_uid!=ROOT_UID or meta.st_mode&0o022:raise ValueError('unsafe rule directory')
    finally:os.close(fd)


def read(path,limit=65536,uid=0):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=uid or m.st_nlink!=1 or m.st_size>limit or m.st_mode&0o022:
            raise ValueError('unsafe rule file')
        b=f.read(limit+1)
        if len(b)>limit:raise ValueError('rule file size limit')
        return b


def atomic(name,data):
    if name not in ('active.json','pending.json','status.json','consent.json'):raise ValueError('invalid rule record')
    directory(BASE)
    dest=BASE/name
    if dest.exists() or dest.is_symlink():read(dest)
    temporary=BASE/('.write-'+secrets.token_hex(8))
    try:
        with temporary.open('xb') as f:
            os.chmod(temporary,0o644);f.write(json.dumps(data,sort_keys=True).encode());f.flush();os.fsync(f.fileno())
        os.replace(temporary,dest)
        fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def validate(data):
    if not isinstance(data,dict) or data.get('schema')!=1 or data.get('channel')!='falco-rules:5':raise ValueError('invalid rule metadata')
    for k in ('rules_sha256','source_sha256'):
        if not isinstance(data.get(k),str) or not re.fullmatch('[a-f0-9]{64}',data[k]):raise ValueError('invalid rule digest')
    catalog=data.get('catalog')
    if type(data.get('excluded_count')) is not int or not 0<=data['excluded_count']<=2048:raise ValueError('invalid excluded rule count')
    if not isinstance(catalog,dict) or not 1<=len(catalog)<=128:raise ValueError('invalid rule catalog')
    for name,row in catalog.items():
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ()_.,:/+\-]{0,159}',name) or not isinstance(row,dict):raise ValueError('invalid rule name')
        if row.get('id')!='upstream.'+hashlib.sha256(name.encode()).hexdigest()[:24] or row.get('title')!=name or row.get('severity') not in ('info','low','medium','high','critical'):
            raise ValueError('invalid rule identity')
        for k in ('meaning','action','verify'):
            if not isinstance(row.get(k),str) or not 1<=len(row[k])<=1024:raise ValueError('invalid rule context')
    return data


def active():
    directory(BASE)
    try:data=json.loads(read(BASE/'active.json'))
    except FileNotFoundError:return None
    if data is None:return None
    validate(data)
    folder=BASE/data['rules_sha256'];directory(folder)
    body=read(folder/'rules.yaml',1048576)
    if hashlib.sha256(body).hexdigest()!=data['rules_sha256']:raise ValueError('active rules changed')
    return data


def control(*args):
    result=subprocess.run(['/usr/bin/systemctl',*args],env=ENV,cwd='/',stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if result.returncode:raise ValueError('rule service operation failed')
    return result.stdout.decode().strip()


def running():
    return control('show',SENSOR,'--property=ActiveState','--value')=='active'


def health(since,digest):
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    deadline=time.monotonic()+35
    while time.monotonic()<deadline:
        try:
            data=json.loads(read(Path('/var/lib/ironclad/feed/snapshot.json'),262144))
            m=data['metrics']
            if data.get('upstream_rules_sha256','')==digest and data['boot_id']==boot and data['stopped'] is False and int(data['metric_ns'])>=since and m['async_reader']=='1' and all(m[k]=='0' for k in ('kernel_drops','output_drops','async_errors','async_pending')) and m['async_events']==m['async_emitted'] and data.get('parse_errors')==0:
                return
        except (OSError,ValueError,KeyError,TypeError):pass
        time.sleep(1)
    raise ValueError('updated sensor did not demonstrate healthy metrics')


def recover():
    try:old=json.loads(read(BASE/'pending.json'))
    except FileNotFoundError:return
    if old is not None:validate(old)
    atomic('active.json',old)
    # A pending transaction only exists if monitoring was active before switching.
    # Restart even if the candidate crashed and systemd now reports failed.
    started=time.monotonic_ns();control('restart',SENSOR);health(started,old['rules_sha256'] if old else '')
    (BASE/'pending.json').unlink()


def sandbox(work,work_fd=None):
    binding=['--bind',str(work),'/work'] if work_fd is None else ['--bind-fd',str(work_fd),'/work']
    args=['/usr/bin/bwrap','--unshare-all','--share-net','--die-with-parent','--new-session',
          '--unshare-user','--uid','65534','--gid','65534','--cap-drop','ALL','--clearenv',
          '--setenv','HOME','/work/home','--setenv','PATH','/usr/bin','--setenv','LANG','C',
          '--ro-bind','/usr','/usr','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64',
          '--proc','/proc','--dev','/dev','--size','33554432','--tmpfs','/tmp']+binding
    for name in ('/etc/ssl','/etc/ca-certificates','/etc/resolv.conf','/etc/hosts'):
        if Path(name).exists():args+=['--ro-bind',name,name]
    return args+['--chdir','/work','/usr/bin/python3','-I','-B','/usr/lib/ironclad/rule-worker']


@contextmanager
def scratch(work):
    """Bound downloads/extraction in RAM, in a private supervisor mount namespace."""
    directory(work)
    os.unshare(os.CLONE_NEWNS)
    def mount(*args):
        subprocess.run(args,env=ENV,cwd='/',stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,timeout=10,check=True)
    mount('/usr/bin/mount','--make-rprivate','/')
    mount('/usr/bin/mount','-t','tmpfs','-o','size=32M,nodev,nosuid,noexec,mode=0700','ironclad-rules',str(work))
    try:yield
    finally:mount('/usr/bin/umount',str(work))


def update():
    if not RELEASE_READY:raise ValueError('rule updater awaits security and native acceptance review')
    consent=json.loads(read(BASE/'consent.json'))
    if consent.get('enabled') is not True:raise ValueError('rule updates are not enabled')
    recover()
    if not running():raise ValueError('enable monitoring before updating rules')
    old=active()
    atomic('status.json',{'state':'checking','attempted_at':int(time.time())})
    try:
        with tempfile.TemporaryDirectory(prefix='.stage-',dir=BASE) as temp:
            # Keep the enclosing directory root-only. Host processes running as
            # nobody must not be able to forge the isolated worker's results.
            work=Path(temp)/'work';work.mkdir(mode=0o700)
            with scratch(work):
                work_fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:
                    with tempfile.TemporaryFile() as log:
                        r=subprocess.run(sandbox(work,work_fd),env=ENV,cwd='/',stdin=subprocess.DEVNULL,
                            stdout=log,stderr=log,timeout=240,pass_fds=(work_fd,))
                finally:os.close(work_fd)
                if r.returncode:raise ValueError('signed rule download or isolated compilation failed')
                data=validate(json.loads(read(work/'result.json',65536)))
                rules=read(work/'host-rules.yaml',1048576)
            if hashlib.sha256(rules).hexdigest()!=data['rules_sha256']:raise ValueError('prepared rules changed')
            folder=BASE/data['rules_sha256']
            if not folder.exists():
                folder.mkdir(mode=0o755)
                with (folder/'rules.yaml').open('xb') as f:f.write(rules);f.flush();os.fsync(f.fileno())
                os.chmod(folder/'rules.yaml',0o644)
            directory(folder)
            if read(folder/'rules.yaml',1048576)!=rules:raise ValueError('existing rule generation differs')
        if old!=data:
            # Journal before switching; interrupted activation rolls back next run.
            atomic('pending.json',old);atomic('active.json',data)
            started=time.monotonic_ns();control('restart',SENSOR);health(started,data['rules_sha256'])
            (BASE/'pending.json').unlink()
        atomic('status.json',{'state':'ok','checked_at':int(time.time()),'rules':len(data['catalog']),
                             'excluded_count':data['excluded_count'],'rules_sha256':data['rules_sha256'],'channel':data['channel']})
    except Exception:
        try:recover();rollback=True
        except Exception:rollback=False
        atomic('status.json',{'state':'failed','attempted_at':int(time.time()),'rollback_ok':rollback})
        raise


def main():
    if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('enable','disable','update'):
        raise ValueError('fixed administrator rule operation required')
    if sys.argv[1]!='disable' and not RELEASE_READY:
        raise ValueError('rule updater awaits security and native acceptance review')
    directory(BASE.parent)
    BASE.mkdir(mode=0o755,exist_ok=True);directory(BASE)
    lock=os.open(BASE/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode) or os.fstat(lock).st_uid!=0:raise ValueError('unsafe rule lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        action=sys.argv[1]
        if action=='update':update();return
        directory(Path('/usr/lib/ironclad'))
        helper=runpy.run_path('/usr/lib/ironclad/sensor-helper')
        uid=helper['caller']()
        if helper['owner']()!=uid:raise ValueError('sensor belongs to another user')
        if action=='enable':
            helper['verify_install']()
            if not running():raise ValueError('enable monitoring first')
            atomic('consent.json',{'schema':1,'enabled':True,'uid':uid,'channel':'falco-rules:5'})
            control('daemon-reload');control('enable','--now',TIMER)
        else:
            atomic('consent.json',{'schema':1,'enabled':False,'uid':uid})
            control('disable','--now',TIMER)
    finally:os.close(lock)


if __name__=='__main__':
    try:main()
    except Exception:
        print('Falco rule maintenance needs attention; previous rules are retained or rollback status is recorded.',file=sys.stderr)
        raise SystemExit(1)
