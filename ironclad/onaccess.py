"""Unprivileged plans and health for separately isolated ClamAV on-access services."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from . import onaccess_policy as policy
from .storage import open_dir

BASE=Path(policy.BASE)

def root_record(path,limit=65536):
 directory=open_dir(path.parent)
 try:
  st=os.fstat(directory)
  if st.st_uid!=0 or st.st_mode&0o022:raise ValueError('unsafe automatic protection directory')
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
  with os.fdopen(fd,'rb') as f:
   st=os.fstat(f.fileno())
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or st.st_size>limit:raise ValueError('unsafe automatic protection record')
   return json.loads(f.read(limit+1))
 finally:os.close(directory)

def service(name,verb='is-active'):
 from .maintenance import trusted,environment
 if name not in policy.UNITS or verb!='is-active':raise ValueError('invalid protection service request')
 try:
  r=subprocess.run([trusted('/usr/bin/systemctl'),verb,name],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4,env=environment(),cwd='/')
  value=r.stdout[:128].decode(errors='replace').strip()
  return value if value in ('active','inactive','failed','activating','deactivating','unknown') else 'unavailable'
 except (OSError,ValueError,subprocess.TimeoutExpired):return 'unavailable'

def status(state=None):
 result={'schema':1,'installed':False,'state':'not_installed','active':False,'mode':None,'scope':'Downloads','message':'Set up automatic malware protection to scan accessed downloads.',
 'coverage':policy.COVERAGE,'events':[],'scanned':0,'errors':0,'signatures_age_hours':None,'automatic_signatures':False}
 try:
  st=os.stat(policy.HELPER,follow_symlinks=False)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise ValueError('unsafe automatic protection helper')
  result['installed']=True
  assigned=root_record(BASE/'owner.json')
  if assigned.get('schema')!=1 or assigned.get('uid')!=os.getuid():raise ValueError('automatic scanner belongs to another account')
  if assigned.get('mode') not in ('notify','prevent'):raise ValueError('invalid scanner mode')
  result['mode']=assigned['mode'];result['automatic_signatures']=service(policy.TIMER_UNIT)=='active'
  live=service(policy.WATCH_UNIT)
  data=root_record(BASE/'feed/snapshot.json');boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  if data.get('schema')!=1 or data.get('version')!=policy.VERSION or data.get('owner_uid')!=os.getuid() or data.get('mode')!=assigned['mode'] or data.get('scope')!='Downloads':raise ValueError('invalid protection feed')
  age=(time.monotonic_ns()-int(data['heartbeat_ns']))/1e9
  valid=data.get('boot_id')==boot and 0<=age<=15 and data.get('stopped') is False and data.get('daemon_ready') is True and data.get('watcher_ready') is True and data.get('database_current') is True
  if type(data.get('scanned')) is not int or not 0<=data['scanned']<2**63 or type(data.get('errors')) is not int or not 0<=data['errors']<2**63:raise ValueError('invalid automatic scanner counts')
  rows=data.get('events')
  if not isinstance(rows,list) or len(rows)>64:raise ValueError('invalid automatic scanner events')
  for row in rows:
   if not isinstance(row,dict) or set(row)!={'id','name','detection','time'} or any(not isinstance(row[k],str) or not 1<=len(row[k])<=n or any(ord(c)<32 for c in row[k]) for k,n in [('id',24),('name',160),('detection',200),('time',64)]):raise ValueError('invalid automatic detection')
   if not re.fullmatch('[a-f0-9]{24}',row['id']):raise ValueError('invalid detection identifier')
  # Signature age is read only from the native root feed, not inaccessible daemon files.
  signatures=data.get('signatures_age_hours')
  if not isinstance(signatures,(int,float)) or isinstance(signatures,bool) or not 0<=signatures<=168:valid=False
  reviewed=review_state(state) if state is not None else []
  rows=[dict(row,reviewed=row['id'] in reviewed) for row in rows]
  result.update(events=rows,scanned=data['scanned'],errors=data['errors'],signatures_age_hours=signatures)
  active=valid and live=='active' and data['errors']==0 and service(policy.ENGINE_UNIT)=='active'
  result.update(state='protecting' if active and result['mode']=='prevent' else 'scanning' if active else 'stopped' if live=='inactive' else 'starting' if live=='activating' else 'degraded',active=active,
   message='Automatic Downloads scanning is active. Detected files are denied; scanner errors fail open.' if active and result['mode']=='prevent' else 'Automatic Downloads scanning is active in alert-only mode.' if active else 'Automatic malware scanning is stopped. Earlier detections are retained.' if live=='inactive' else 'Automatic malware scanning has a coverage gap. Check services, signatures and scanner errors; no active coverage is assumed.')
  detail=data.get('last_error','')
  if isinstance(detail,str) and len(detail)<=256 and not any(ord(c)<32 for c in detail):result['detail']=detail
 except FileNotFoundError:
  if result['installed']:result.update(state='not_configured',message='Automatic scanner is installed but not configured for this account.')
 except (OSError,ValueError,TypeError,KeyError,AttributeError):result.update(state='unavailable',active=False,message='Automatic malware protection could not be verified. One-off file scans are separate.')
 return result

def digest(data):return hashlib.sha256(json.dumps({k:v for k,v in data.items() if k!='digest'},sort_keys=True,separators=(',',':')).encode()).hexdigest()

def plan(state,action):
 from . import malware,onaccess_package
 if action not in ('notify','prevent','disable'):raise ValueError('choose automatic scanning alert mode, prevention or stop')
 if action!='disable' and not malware.status(state)['ready']:raise ValueError('set up the one-off scanner and official signatures first')
 package=onaccess_package.build(state) if action!='disable' else None
 data={'schema':1,'uid':os.getuid(),'created':int(time.time()),'action':action,'scope':'Downloads','component':package,'coverage':policy.COVERAGE,
  'title':'Stop automatic malware scanning' if action=='disable' else 'Enable automatic Downloads protection' if action=='prevent' else 'Enable automatic Downloads scanning',
  'impact':'Starts a separate unprivileged ClamAV daemon and a privileged on-access watcher. Only Downloads is watched; no deletion or quarantine. Official signature maintenance contacts database.clamav.net every four hours. Scanner time/size limits and fail-open errors remain visible.' if action!='disable' else 'Stops automatic malware scanning and its signature timer. One-off scanning and Falco behavior monitoring remain available.'}
 data['digest']=digest(data);return data

def apply(state,review,approval):
 from . import sensor
 if not isinstance(review,dict) or review.get('uid')!=os.getuid() or review.get('digest')!=approval or digest(review)!=approval or type(review.get('created')) is not int or not 0<=time.time()-review['created']<=180:raise ValueError('review a fresh automatic protection plan')
 current=plan(state,review.get('action'))
 if {k:v for k,v in current.items() if k not in ('created','digest')}!={k:v for k,v in review.items() if k not in ('created','digest')}:raise ValueError('automatic protection plan changed')
 if review['component']:
  # Same administrator-reviewed local package mechanism as the separate Falco component.
  code=sensor.run_privileged(['/usr/bin/pacman','-U','--noconfirm','--',review['component']['path']])
  if code!=0:raise ValueError('automatic protection component installation did not finish')
 action='disable' if review['action']=='disable' else 'enable-'+review['action']
 result=sensor.run_privileged([policy.HELPER,action],240)
 if result!=0:raise ValueError('automatic protection change did not verify; refresh status')
 value=status(state)
 verified=(not value['active'] and value['state']=='stopped') if action=='disable' else value['active'] and value['mode']==review['action']
 return {'verified':verified,'status':value,'message':value['message']}


def review_state(state):
 try:
  directory=open_dir(state)
  try:
   fd=os.open('antimalware-reviewed.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
   with os.fdopen(fd,'rb') as f:
    st=os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>4096:raise ValueError('unsafe detection review record')
    rows=json.loads(f.read(4097))
  finally:os.close(directory)
 except FileNotFoundError:return []
 if not isinstance(rows,list) or len(rows)>64 or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{24}',v) for v in rows):raise ValueError('invalid detection review record')
 return rows


def acknowledge(state,identifier):
 import fcntl,secrets
 from .storage import private_dir,safe_file
 if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{24}',identifier):raise ValueError('invalid detection identifier')
 directory=private_dir(state);lock=None;temporary='.antimalware-reviewed-'+secrets.token_hex(8)
 try:
  lock=safe_file(directory,'antimalware-reviewed.lock');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  data=status(state);ids={v['id'] for v in data['events']}
  if identifier not in ids:raise ValueError('detection no longer present')
  reviewed=[v for v in review_state(state) if v in ids];reviewed=list(dict.fromkeys([*reviewed,identifier]))[-64:]
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  with os.fdopen(fd,'w') as stream:
   json.dump(reviewed,stream);stream.flush();os.fsync(stream.fileno())
  os.replace(temporary,'antimalware-reviewed.json',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
 finally:
  try:os.unlink(temporary,dir_fd=directory)
  except FileNotFoundError:pass
  if lock is not None:os.close(lock)
  os.close(directory)
 return status(state)
