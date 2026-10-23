"""Private, reversible presentation preferences; never modify scan findings."""
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from .model import now, validate_scan
from .storage import open_dir, private_dir, safe_file

NAME='ignored-findings.json'
ID=re.compile(r'[a-z][a-z0-9_.]{1,100}\Z')


def fingerprint(check):
    # Observation timestamps, duration and generated explanations are volatile.
    evidence=sorted((item['source'],item['value']) for item in check['evidence'])
    value=[check['check_id'],check['status'],check['severity'],evidence]
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def read(state):
    try:directory=open_dir(state)
    except FileNotFoundError:return {}
    try:
        info=os.fstat(directory)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('unsafe finding preference directory')
        try:fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        except FileNotFoundError:return {}
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>131072:
                raise ValueError('unsafe finding preferences')
            data=json.loads(stream.read(131073))
    finally:os.close(directory)
    if not isinstance(data,dict) or set(data)!={'schema','ignored'} or data['schema']!=1 or not isinstance(data['ignored'],dict) or len(data['ignored'])>512:
        raise ValueError('invalid finding preferences')
    if any(not ID.fullmatch(key) or not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value) for key,value in data['ignored'].items()):
        raise ValueError('invalid finding preference entry')
    return data['ignored']


def apply(state,request):
    if not isinstance(request,dict) or request.get('action') not in ('status','ignore','restore'):
        raise ValueError('invalid finding preference action')
    checks=request.get('checks')
    validate_scan({'schema_version':'1.0','scan_id':'00000000-0000-4000-8000-000000000000','collected_at':now(),'host':{},'checks':checks})
    by_id={check['check_id']:check for check in checks}
    action=request['action'];target=request.get('check_id')
    if action=='status':records=read(state)
    else:
        if not isinstance(target,str) or target not in by_id:raise ValueError('choose a current finding')
        directory=private_dir(state);lock=None;temporary='.ignored-'+secrets.token_hex(8)
        try:
            lock=safe_file(directory,'finding-preferences.lock');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            records=read(state)
            if action=='ignore':records[target]=fingerprint(by_id[target])
            else:records.pop(target,None)
            if len(records)>512:raise ValueError('finding preference limit reached')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'w') as stream:
                json.dump({'schema':1,'ignored':records},stream);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,NAME,src_dir_fd=directory,dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError:pass
            if lock is not None:os.close(lock)
            os.close(directory)
    return {'schema':1,'ignored':[key for key,check in by_id.items() if records.get(key)==fingerprint(check)],'saved':len(records)}
