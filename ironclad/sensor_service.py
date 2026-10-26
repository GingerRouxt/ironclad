#!/usr/bin/python3 -I
"""Installed root-owned Ironclad sensor supervisor; standalone stdlib only.

No arbitrary paths/commands/configuration are accepted by its CLI. Tests patch
constants in an imported module, never elevate or start a host service.
"""
import collections
import fcntl
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode=True
ROOT_UID=0
BASE=Path('/var/lib/ironclad')
ASSETS=Path('/usr/share/ironclad-sensor')
ENGINE=Path('/usr/lib/ironclad/falco')
KRSI=Path('/usr/lib/ironclad/libkrsi.so')
UNIT='ironclad-sensor.service'
CONFIG=ASSETS/'falco.yaml'
POLICY=ASSETS/'policy.json'
MAX_EVENTS=256


def now():return datetime.now(timezone.utc).isoformat()


def trusted_file(path,limit=65536):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=ROOT_UID or meta.st_nlink!=1 or meta.st_mode&0o022 or meta.st_size>limit:raise ValueError('unsafe installed sensor file')
        with os.fdopen(fd,'rb',closefd=False) as stream:return stream.read(limit+1)
    finally:os.close(fd)


def root_dir(path,create=False):
    path=Path(path).absolute();fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if part in ('','.','..'):raise ValueError('unsafe sensor directory')
            if create:
                try:os.mkdir(part,0o755,dir_fd=fd)
                except FileExistsError:pass
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            meta=os.fstat(fd)
            if meta.st_uid!=ROOT_UID or meta.st_mode&0o022:raise ValueError('unsafe sensor directory owner')
        return fd
    except BaseException:os.close(fd);raise


def command(args,timeout=25):
    # Fixed system tools only; environment contains no caller Python/loader paths.
    if args[0] not in ('/usr/bin/systemctl','/usr/bin/setfacl'):raise ValueError('unapproved sensor command')
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'},cwd='/',check=False)
    if len(result.stdout)>8192:raise ValueError('sensor command output limit')
    return result.returncode,result.stdout.decode('utf-8',errors='replace').strip()


def owner():
    data=json.loads(trusted_file(BASE/'owner.json'))
    if not isinstance(data,dict) or not isinstance(data.get('uid'),int) or not 1000<=data['uid']<2147483648:raise ValueError('invalid sensor owner')
    pwd.getpwuid(data['uid'])
    return data['uid']


def caller():
    value=os.environ.get('PKEXEC_UID','')
    if not value.isdecimal() or not 1000<=int(value)<2147483648:raise ValueError('authenticated desktop user required')
    uid=int(value);pwd.getpwuid(uid)
    return uid


def atomic(name,data,uid=None):
    directory=BASE/'feed' if uid is not None else BASE
    fd=root_dir(directory,create=True)
    temporary='.write-'+secrets.token_hex(12)
    try:
        # Reject unsafe existing destinations; no arbitrary caller filenames.
        if name not in ('owner.json','snapshot.json'):raise ValueError('invalid sensor record')
        try:
            meta=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=ROOT_UID or meta.st_nlink!=1 or meta.st_mode&0o022:raise ValueError('unsafe sensor record')
        except FileNotFoundError:pass
        body=json.dumps(data,separators=(',',':')).encode()
        if len(body)>262144:raise ValueError('sensor record limit')
        out=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(out,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        if uid is not None:
            code,_=command(['/usr/bin/setfacl','-m',f'u:{uid}:r--',str(directory/temporary)])
            if code:raise ValueError('could not grant private sensor access')
        os.replace(temporary,name,src_dir_fd=fd,dst_dir_fd=fd)
    finally:
        try:os.unlink(temporary,dir_fd=fd)
        except FileNotFoundError:pass
        os.close(fd)


def policy():
    data=json.loads(trusted_file(POLICY))
    if not isinstance(data,dict) or not isinstance(data.get('rules'),dict) or not 1<=len(data['rules'])<=32:raise ValueError('invalid installed policy')
    identifiers=set()
    for name,row in data['rules'].items():
        if not isinstance(name,str) or not 1<=len(name)<=120 or not isinstance(row,dict):raise ValueError('invalid installed rule')
        identifier=row.get('id')
        if not isinstance(identifier,str) or not re.fullmatch(r'runtime\.[a-z_]{1,48}',identifier) or identifier in identifiers:raise ValueError('invalid installed rule id')
        identifiers.add(identifier)
        if row.get('severity') not in ('info','low','medium','high','critical'):raise ValueError('invalid installed rule severity')
        for key in ('title','meaning','action','verify'):
            if not isinstance(row.get(key),str) or not 1<=len(row[key])<=2048:raise ValueError('invalid installed rule context')
    return data


def verify_install():
    for directory in (ASSETS,ENGINE.parent):
        fd=root_dir(directory);os.close(fd)
    data=policy()
    # Engine bytes and policy/config were installed as an administrator-approved package.
    blob=trusted_file(ENGINE,134217728)
    if hashlib.sha256(blob).hexdigest()!=data['engine_sha256']:raise ValueError('sensor engine changed')
    if hashlib.sha256(trusted_file(KRSI,8388608)).hexdigest()!=data['krsi_sha256']:raise ValueError('async sensor component changed')
    if hashlib.sha256(trusted_file(CONFIG)).hexdigest()!=data['config_sha256']:raise ValueError('sensor configuration changed')
    if hashlib.sha256(trusted_file(ASSETS/'rules.yaml')).hexdigest()!=data['rules_sha256']:raise ValueError('sensor rules changed')
    return data


def add_upstream(data):
    """Only the administrator-installed helper reads an authenticated generation."""
    if not Path('/var/lib/ironclad-rules/active.json').exists():return data
    helper=Path('/usr/lib/ironclad/rule-helper')
    trusted_file(helper,65536)
    runtime=runpy.run_path(str(helper))
    upstream=runtime['active']()
    if upstream:
        if set(data['rules'])&set(upstream['catalog']):raise ValueError('upstream rule name collision')
        data['rules']={**data['rules'],**upstream['catalog']}
        data['_upstream_sha']=upstream['rules_sha256']
        data['_upstream_path']='/var/lib/ironclad-rules/'+upstream['rules_sha256']+'/rules.yaml'
    return data


def prepare_owner(uid):
    fd=root_dir(BASE,create=True);os.close(fd)
    try:
        if owner()!=uid:raise ValueError('another account owns this local sensor')
    except FileNotFoundError:atomic('owner.json',{'schema':1,'uid':uid})
    code,_=command(['/usr/bin/setfacl','-m',f'u:{uid}:r--',str(BASE/'owner.json')])
    if code:raise ValueError('could not grant private owner-record access')
    directory=BASE/'feed';fd=root_dir(directory,create=True);os.close(fd)
    os.chmod(directory,0o700)
    code,_=command(['/usr/bin/setfacl','-m',f'u:{uid}:r-x',str(directory)])
    if code:raise ValueError('could not grant private sensor access')


def sanitize_event(data,rules,identifier):
    if not isinstance(data,dict) or data.get('source','syscall')!='syscall' or data.get('rule') not in rules:return None
    fields=data.get('output_fields',{})
    if not isinstance(fields,dict):return None
    timestamp=data.get('time','')
    try:
        if not isinstance(timestamp,str) or len(timestamp)>64 or datetime.fromisoformat(timestamp.replace('Z','+00:00')).tzinfo is None:return None
    except ValueError:return None
    application=fields.get('proc.name','unknown')
    if not isinstance(application,str) or not re.fullmatch(r'[A-Za-z0-9_.+\-]{1,64}',application):application='unidentified application'
    event=fields.get('evt.type','unknown')
    if not isinstance(event,str) or not re.fullmatch('[a-z0-9_]{1,32}',event):event='unknown'
    entry=rules[data['rule']]
    result={'id':identifier,'rule_id':entry['id'],'severity':entry['severity'],'time':timestamp,'app':application,'event':event}
    if entry['id'].startswith('upstream.'):result['title']=entry['title']
    return result


def metrics(data):
    if not isinstance(data,dict) or data.get('rule')!='Falco internal: metrics snapshot':return None
    fields=data.get('output_fields',{})
    if not isinstance(fields,dict) or fields.get('scap.engine_name') not in ('modern_ebpf','modern_bpf'):return None
    names={'events':'scap.n_evts','kernel_drops':'scap.n_drops','output_drops':'falco.outputs_queue_num_drops',
           'async_reader':'plugins.krsi.ironclad_async_reader_alive','async_events':'plugins.krsi.ironclad_async_events','async_errors':'plugins.krsi.ironclad_async_errors',
           'async_emitted':'plugins.krsi.ironclad_async_emitted','async_pending':'plugins.krsi.ironclad_async_pending'}
    result={}
    for key,field in names.items():
        value=fields.get(field)
        if not isinstance(value,int) or isinstance(value,bool) or not 0<=value<9223372036854775808:return None
        result[key]=str(value)
    if result['async_reader'] not in ('0','1'):return None
    return result


def run():
    data=add_upstream(verify_install());uid=owner();prepare_owner(uid)
    rules=data['rules'];session=secrets.token_hex(8);sequence=0
    events=collections.deque(maxlen=MAX_EVENTS);omitted=0
    try:
        previous=json.loads(trusted_file(BASE/'feed/snapshot.json',262144))
        if previous.get('owner_uid')==uid and isinstance(previous.get('events'),list) and len(previous['events'])<=MAX_EVENTS:
            for row in previous['events']:
                if isinstance(row,dict) and set(row) in ({'id','rule_id','severity','time','app','event'},{'id','rule_id','severity','time','app','event','title'}):events.append(row)
            omitted=previous.get('omitted',0) if isinstance(previous.get('omitted'),int) else 0
    except (OSError,ValueError,KeyError,TypeError):pass
    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    last_metric=0;counts=None;parse_errors=0;stopping=False
    def stop(signum,frame):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    args=[str(ENGINE),'-c',str(CONFIG)]
    if data.get('_upstream_path'):args+=['-r',str(ASSETS/'rules.yaml'),'-r',data['_upstream_path']]
    child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'},cwd='/',start_new_session=False)
    selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
    pending=b'';last_write=0
    try:
        while not stopping and child.poll() is None:
            for key,_ in selector.select(timeout=0.5):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk:continue
                pending+=chunk
                if len(pending)>131072:pending=b'';parse_errors+=1;continue
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    if len(line)>65536:parse_errors+=1;continue
                    if not line.startswith(b'{'):continue
                    try:row=json.loads(line)
                    except (ValueError,UnicodeError):parse_errors+=1;continue
                    observed=metrics(row)
                    if observed is not None:counts=observed;last_metric=time.monotonic_ns();continue
                    event=sanitize_event(row,rules,session+':'+str(sequence+1))
                    if event:
                        sequence+=1
                        if len(events)==MAX_EVENTS:omitted+=1
                        events.append(event)
            if time.monotonic()-last_write>=2:
                snapshot={'upstream_rules_sha256':data.get('_upstream_sha',''),'policy_version':data['version'],'schema':1,'owner_uid':uid,'session':session,'boot_id':boot_id,'heartbeat_ns':str(time.monotonic_ns()),'metric_ns':str(last_metric),'metrics':counts,'events':list(events),'omitted':max(0,omitted),'parse_errors':parse_errors,'stopped':False}
                atomic('snapshot.json',snapshot,uid);last_write=time.monotonic()
    finally:
        selector.close()
        if child.poll() is None:
            child.terminate()
            try:child.wait(timeout=4)
            except subprocess.TimeoutExpired:child.kill();child.wait()
        atomic('snapshot.json',{'upstream_rules_sha256':data.get('_upstream_sha',''),'policy_version':data['version'],'schema':1,'owner_uid':uid,'session':session,'boot_id':boot_id,'heartbeat_ns':str(time.monotonic_ns()),'metric_ns':str(last_metric),'metrics':counts,'events':list(events),'omitted':max(0,omitted),'parse_errors':parse_errors,'stopped':True},uid)
    return 0 if stopping else child.returncode or 1


def manage(action):
    # Serialize explicit stop/remove with automatic activation. A user request
    # cannot be silently undone by an updater that checked liveness earlier.
    folder=Path('/var/lib/ironclad-rules')
    if not folder.exists():return manage_unlocked(action)
    fd=root_dir(folder);os.close(fd)
    lock=os.open(folder/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(lock)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=ROOT_UID or meta.st_nlink!=1 or meta.st_mode&0o022:raise ValueError('unsafe rule update lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return manage_unlocked(action)
    finally:os.close(lock)


def manage_unlocked(action):
    uid=caller()
    if action=='enable':
        verify_install()
        if not Path('/sys/kernel/btf/vmlinux').is_file():raise ValueError('kernel BTF support unavailable')
        prepare_owner(uid)
        if command(['/usr/bin/systemctl','daemon-reload'])[0]:raise ValueError('sensor service refresh failed')
        started=time.monotonic_ns()
        if command(['/usr/bin/systemctl','enable',UNIT])[0] or command(['/usr/bin/systemctl','restart',UNIT])[0]:raise ValueError('sensor did not start')
        # Capped BPF initialization can take over 20 seconds on a workstation.
        for _ in range(200):
            try:
                snapshot=json.loads(trusted_file(BASE/'feed/snapshot.json',262144))
                if snapshot.get('policy_version')==json.loads(trusted_file(POLICY))['version'] and int(snapshot.get('metric_ns','0'))>=started and snapshot.get('owner_uid')==uid and not snapshot.get('stopped') and snapshot.get('metric_ns','0')!='0' and 0<=(time.monotonic_ns()-int(snapshot['metric_ns']))/1e9<=15:
                    counts=snapshot.get('metrics',{})
                    if counts.get('async_reader')=='1' and counts.get('async_errors')=='0' and counts.get('async_pending')=='0' and counts.get('async_events')==counts.get('async_emitted') and command(['/usr/bin/systemctl','is-active',UNIT])[1]=='active':return {'verified':True,'message':'Local monitoring started with fresh kernel metrics and a live asynchronous reader.'}
            except (OSError,ValueError,KeyError,TypeError):pass
            time.sleep(.5)
        return {'verified':False,'message':'The component was installed, but fresh sensor activity has not been verified. Review status; no protection is assumed.'}
    if action=='disable':
        try:assigned=owner()
        except FileNotFoundError:assigned=uid  # A freshly installed component may not have been enabled yet.
        if assigned!=uid:raise ValueError('another account owns this sensor')
        code,_=command(['/usr/bin/systemctl','disable','--now',UNIT])
        _,state=command(['/usr/bin/systemctl','is-active',UNIT])
        _,enabled=command(['/usr/bin/systemctl','is-enabled',UNIT])
        return {'verified':code==0 and state in ('inactive','failed','unknown') and enabled in ('disabled','not-found'),'message':'Monitoring stop requested; existing local alerts are retained.'}
    raise ValueError('unsupported sensor action')


def main():
    if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('enable','disable','run'):return 2
    try:
        if sys.argv[1]=='run':return run()
        result=manage(sys.argv[1]);print(json.dumps(result));return 0 if result['verified'] else 2
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired):
        print(json.dumps({'verified':False,'message':'Sensor setup or control could not be verified. Check Ironclad status; no protection is assumed.'}));return 2


if __name__=='__main__':raise SystemExit(main())
