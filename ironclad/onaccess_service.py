#!/usr/bin/python3 -I
"""Root-owned ClamAV supervisor. Fixed commands/scope; no user code or shell input."""
from datetime import datetime,timezone
import collections
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode=True
BASE=Path('/var/lib/ironclad-antimalware')
ASSETS=Path('/usr/share/ironclad-antimalware')
SOCKET=Path('/run/ironclad-antimalware/clamd.sock')
ENGINE='ironclad-antimalware-engine.service'
WATCH='ironclad-antimalware.service'
TIMER='ironclad-antimalware-refresh.timer'
ROOT_UID=0
VERSION='0.1.1'
MAX_FEED=64

def now():return datetime.now(timezone.utc).isoformat()
def safe_read(path,limit=65536,uid=ROOT_UID):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=uid or st.st_nlink!=1 or st.st_mode&0o022 or st.st_size>limit:raise ValueError('unsafe component record')
  with os.fdopen(fd,'rb',closefd=False) as f:return f.read(limit+1)
 finally:os.close(fd)
def root_dir(path,create=False):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in Path(path).absolute().parts[1:]:
   if part in ('','.','..'):raise ValueError('unsafe component directory')
   if create:
    try:os.mkdir(part,0o755,dir_fd=fd)
    except FileExistsError:pass
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
   st=os.fstat(fd)
   if st.st_uid!=ROOT_UID or st.st_mode&0o022:raise ValueError('unsafe component directory')
  return fd
 except BaseException:os.close(fd);raise

def command(args,timeout=30):
 if args[0] not in ('/usr/bin/systemctl','/usr/bin/setfacl'):raise ValueError('unsupported system command')
 p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'},cwd='/')
 if len(p.stdout)>8192:raise ValueError('command output limit')
 return p.returncode,p.stdout.decode(errors='replace').strip()

def atomic(path,body,mode=0o600,gid=None,reader=None):
 fd=root_dir(path.parent,True);name='.write-'+secrets.token_hex(12)
 try:
  try:
   st=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=ROOT_UID or st.st_nlink!=1 or st.st_mode&0o022:raise ValueError('unsafe existing component file')
  except FileNotFoundError:pass
  out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=fd)
  with os.fdopen(out,'wb') as f:
   f.write(body);f.flush();os.fsync(f.fileno())
   if gid is not None:os.fchown(f.fileno(),ROOT_UID,gid)
  if reader is not None and command(['/usr/bin/setfacl','-m',f'u:{reader}:r--',str(path.parent/name)])[0]:raise ValueError('private feed access failed')
  os.replace(name,path.name,src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
 finally:
  try:os.unlink(name,dir_fd=fd)
  except FileNotFoundError:pass
  os.close(fd)

def caller():
 s=os.environ.get('PKEXEC_UID','')
 if not s.isdecimal() or not 1000<=int(s)<2147483648:raise ValueError('authenticated desktop user required')
 pwd.getpwuid(int(s));return int(s)
def owner():
 d=json.loads(safe_read(BASE/'owner.json'))
 if d.get('schema')!=1 or type(d.get('uid')) is not int or not 1000<=d['uid']<2147483648 or d.get('mode') not in ('notify','prevent'):raise ValueError('invalid owner record')
 return d

def verify_install():
 data=json.loads(safe_read(ASSETS/'manifest.json'))
 if data.get('version')!=VERSION or not isinstance(data.get('files'),dict) or not 5<=len(data['files'])<=12:raise ValueError('component manifest invalid')
 for name,digest in data['files'].items():
  if not re.fullmatch(r'usr/(lib/ironclad/antimalware-helper|lib/systemd/system/ironclad-antimalware[a-z.-]*|share/polkit-1/actions/com.zerodaysecurity.ironclad.antimalware.policy)',name):raise ValueError('unexpected component asset')
  path=Path('/')/name;fd=root_dir(path.parent);os.close(fd)
  if hashlib.sha256(safe_read(path,131072)).hexdigest()!=digest:raise ValueError('installed component changed')
 return data

def target(uid):
 home=Path(pwd.getpwuid(uid).pw_dir)
 if not re.fullmatch(r'/home/[A-Za-z0-9_.-]{1,80}',str(home)):raise ValueError('unsupported account home path')
 path=home/'Downloads';fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in path.parts[1:]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child;st=os.fstat(fd)
   if st.st_uid not in (ROOT_UID,uid) or st.st_mode&0o022:raise ValueError('Downloads must not be linked or writable by other users')
  if os.fstat(fd).st_uid!=uid:raise ValueError('Downloads must belong to the authenticated user')
  return path
 finally:os.close(fd)

def copy_signatures(uid):
 """Copy only bounded public signature files, never follow a caller symlink."""
 home=Path(pwd.getpwuid(uid).pw_dir);source=home/'.local/state/ironclad/signatures'
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in source.parts[1:]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child;st=os.fstat(fd)
   if st.st_uid not in (ROOT_UID,uid) or st.st_mode&0o022:raise ValueError('unsafe signature source')
  destination=BASE/'signatures'
  # This one dedicated directory is owned by the unprivileged ClamAV account.
  base=root_dir(BASE);os.close(base)
  try:os.mkdir(destination,0o700)
  except FileExistsError:pass
  d=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  account=pwd.getpwnam('clamav')
  try:
   st=os.fstat(d)
   if st.st_uid not in (ROOT_UID,account.pw_uid) or st.st_mode&0o077:raise ValueError('unsafe daemon signature directory')
   os.fchown(d,account.pw_uid,account.pw_gid)
   names=os.listdir(fd)
   selected=[n for n in names if re.fullmatch(r'(main|daily|bytecode)(\.(cvd|cld)|-[0-9]{1,9}\.(cvd|cld)\.sign)',n)]
   if len(selected)>12 or not all(any(n in selected for n in (stem+'.cvd',stem+'.cld')) for stem in ('main','daily')):raise ValueError('official signatures required first')
   total=0
   for name in selected:
    src=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    temp='.copy-'+secrets.token_hex(12)
    try:
     st=os.fstat(src)
     if not stat.S_ISREG(st.st_mode) or st.st_uid!=uid or st.st_nlink!=1 or st.st_mode&0o022 or not 0<st.st_size<=134217728:raise ValueError('unsafe signature source file')
     total+=st.st_size
     if total>268435456:raise ValueError('signature size limit')
     # Existing daemon data may only be replaced inside its dedicated directory.
     try:
      old=os.stat(name,dir_fd=d,follow_symlinks=False)
      if not stat.S_ISREG(old.st_mode) or old.st_uid!=account.pw_uid or old.st_nlink!=1 or old.st_mode&0o022:raise ValueError('unsafe daemon database')
     except FileNotFoundError:pass
     out=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
     with os.fdopen(out,'wb') as stream:
      copied=0
      while block:=os.read(src,min(1048576,st.st_size+1-copied)):
       copied+=len(block)
       if copied>st.st_size:raise ValueError('signature source changed')
       stream.write(block)
      after=os.fstat(src)
      if copied!=st.st_size or (after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(st.st_size,st.st_mtime_ns,st.st_ctime_ns):raise ValueError('signature source changed')
      stream.flush();os.fsync(stream.fileno());os.fchown(stream.fileno(),account.pw_uid,account.pw_gid)
     os.utime(temp,ns=(st.st_atime_ns,st.st_mtime_ns),dir_fd=d,follow_symlinks=False)
     os.replace(temp,name,src_dir_fd=d,dst_dir_fd=d)
    finally:
     os.close(src)
     try:os.unlink(temp,dir_fd=d)
     except FileNotFoundError:pass
  finally:os.close(d)
 finally:os.close(fd)

def configuration(path,mode):
 clam=pwd.getpwnam('clamav')
 if mode not in ('notify','prevent'):raise ValueError('invalid protection mode')
 # User path has already passed a strict character whitelist in target().
 return ('Foreground yes\nLocalSocket '+str(SOCKET)+'\nLocalSocketMode 600\nFixStaleSocket yes\n'
  'DatabaseDirectory '+str(BASE/'signatures')+'\nOfficialDatabaseOnly yes\nFailIfCvdOlderThan 7\n'
  'TemporaryDirectory /tmp\nMaxThreads 2\nMaxQueue 8\nMaxConnectionQueueLength 8\n'
  'StreamMaxLength 100M\nMaxFileSize 100M\nMaxScanSize 200M\nMaxRecursion 16\nMaxFiles 1000\n'
  'MaxScanTime 15000\nReadTimeout 20\nCommandReadTimeout 5\nSelfCheck 60\nConcurrentDatabaseReload no\n'
  'FollowDirectorySymlinks no\nFollowFileSymlinks no\nEnableShutdownCommand no\n'
  'LogClean no\nLogVerbose no\n'
  'OnAccessIncludePath '+str(path)+'\nOnAccessMaxFileSize 100M\nOnAccessMaxThreads 1\n'
  'OnAccessExcludeRootUID yes\nOnAccessExcludeUID '+str(clam.pw_uid)+'\n'
  'OnAccessPrevention '+('yes' if mode=='prevent' else 'no')+'\nOnAccessDenyOnError no\nOnAccessCurlTimeout 20000\n'
  'OnAccessDisableDDD no\nOnAccessExtraScanning yes\n'+
  ''.join('OnAccessExcludePath '+str(path/name)+'\n' for name in ('.ssh','.gnupg','.config','.local','.aws','.azure','.kube') if (path/name).exists()))

def prepare(uid,mode):
 path=target(uid)
 try:
  if owner()['uid']!=uid:raise ValueError('another account owns automatic scanning')
 except FileNotFoundError:pass
 fd=root_dir(BASE,True);os.close(fd)
 # Traverse only; databases and private feed retain their separate restrictions.
 os.chmod(BASE,0o711)
 if command(['/usr/bin/setfacl','-m',f'u:{uid}:r-x',str(BASE)])[0]:raise ValueError('private component access failed')
 copy_signatures(uid)
 gid=grp.getgrnam('clamav').gr_gid
 atomic(BASE/'clamd.conf',configuration(path,mode).encode(),0o640,gid)
 fresh=('DatabaseMirror database.clamav.net\nScriptedUpdates yes\nTestDatabases yes\n'
        'DatabaseOwner clamav\nNotifyClamd '+str(BASE/'clamd.conf')+'\n')
 atomic(BASE/'freshclam.conf',fresh.encode(),0o640,gid)
 drop=Path('/etc/systemd/system')/(WATCH+'.d')
 atomic(drop/'10-downloads.conf',('[Service]\nBindReadOnlyPaths='+str(path)+'\n').encode(),0o644)
 data={'schema':1,'uid':uid,'mode':mode,'scope':'Downloads','version':VERSION}
 atomic(BASE/'owner.json',json.dumps(data).encode(),reader=uid)
 feed=BASE/'feed';fd=root_dir(feed,True);os.close(fd);os.chmod(feed,0o700)
 if command(['/usr/bin/setfacl','-m',f'u:{uid}:r-x',str(feed)])[0]:raise ValueError('private feed access failed')
 # Record actual watcher scope without exposing it to unrelated users.
 return data

def daemon_request(value):
 if value not in (b'zPING\0',b'zVERSION\0'):raise ValueError('invalid daemon request')
 try:
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
   sock.settimeout(1);sock.connect(str(SOCKET));sock.sendall(value)
   return sock.recv(1024).rstrip(b'\0\n').decode('ascii')
 except (OSError,UnicodeError):return ''

def ping():return daemon_request(b'zPING\0')=='PONG'

def fanotify_live(pid):
 """Check only our own child descriptors, never other process arguments."""
 try:
  for p in Path('/proc',str(pid),'fdinfo').iterdir():
   body=p.read_text()[:8192]
   if 'fanotify flags:' in body and ('fanotify ino:' in body or 'fanotify mnt_id:' in body):return True
 except OSError:pass
 return False

def event(line):
 if not isinstance(line,str) or len(line)>8192 or not line.endswith(' FOUND'):return None
 path,sep,signature=line[:-6].rpartition(': ')
 if not sep or not re.fullmatch(r'[A-Za-z0-9_.:!+() /-]{1,200}',signature):return None
 # Names are untrusted; keep no full path and no file contents in the feed.
 name=Path(path).name
 if not name or any(ord(c)<32 for c in name):name='Detected file'
 return {'name':name[:160],'detection':signature,'time':now()}

def signature_metadata():
 try:
  # Use the official database's embedded build time, not copy/download mtime.
  for name in ('daily.cvd','daily.cld'):
   try:
    fd=os.open(BASE/'signatures'/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   except FileNotFoundError:continue
   try:
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_mode&0o022:return None,None
    header=os.read(fd,512).decode('ascii').split(':')
    if len(header)<3 or header[0]!='ClamAV-VDB':return None,None
    built=datetime.strptime(header[1],'%d %b %Y %H-%M %z')
    age=(datetime.now(timezone.utc)-built).total_seconds()/3600
    return (round(age,2),header[2]) if age>=0 and re.fullmatch('[0-9]{1,12}',header[2]) else (None,None)
   finally:os.close(fd)
 except (OSError,ValueError,UnicodeError):pass
 return None,None

def snapshot(data,child,events,scanned,errors,stopped=False):
 age,version=signature_metadata()
 loaded=re.fullmatch(r'ClamAV [0-9.]+/([0-9]{1,12})/[^\r\n]{1,100}',daemon_request(b'zVERSION\0'))
 database_current=bool(loaded and loaded.group(1)==version)
 return {'schema':1,'version':VERSION,'owner_uid':data['uid'],'mode':data['mode'],'scope':'Downloads',
  'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'heartbeat_ns':str(time.monotonic_ns()),
  'daemon_ready':ping(),'watcher_ready':child.poll() is None and fanotify_live(child.pid),'stopped':stopped,
  'events':list(events),'scanned':scanned,'errors':errors,'signatures_age_hours':age,'database_current':database_current}

def run():
 verify_install();data=owner();events=collections.deque(maxlen=MAX_FEED);scanned=0;errors=0
 try:
  previous=json.loads(safe_read(BASE/'feed/snapshot.json'))
  if previous.get('owner_uid')==data['uid'] and isinstance(previous.get('events'),list) and len(previous['events'])<=MAX_FEED:
   for row in previous['events']:
    if isinstance(row,dict) and set(row)=={'id','name','detection','time'} and re.fullmatch('[a-f0-9]{24}',str(row['id'])):events.append(row)
 except (OSError,ValueError,KeyError,TypeError):pass
 stopping=False;last_error=''
 def stop(signum,frame):
  nonlocal stopping
  stopping=True
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
 until=time.monotonic()+180
 while not ping() and not stopping and time.monotonic()<until:time.sleep(.5)
 if stopping or not ping():return 2
 child=subprocess.Popen(['/usr/bin/clamonacc','--foreground','--verbose','--fdpass','--config-file='+str(BASE/'clamd.conf')],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'},cwd='/')
 select=selectors.DefaultSelector();select.register(child.stdout,selectors.EVENT_READ);pending=b'';last=0
 try:
  while not stopping and child.poll() is None:
   for key,_ in select.select(timeout=.4):
    pending+=os.read(key.fileobj.fileno(),65536)
    if len(pending)>131072:pending=b'';errors+=1;continue
    while b'\n' in pending:
     line,pending=pending.split(b'\n',1);line=line.decode(errors='replace').strip()
     item=event(line)
     if item:
      if not events or (events[-1]['name'],events[-1]['detection'])!=(item['name'],item['detection']) or (datetime.now(timezone.utc)-datetime.fromisoformat(events[-1]['time'])).total_seconds()>30:events.append(dict(item,id=secrets.token_hex(12)))
      scanned+=1
     elif line.endswith(': OK'):scanned+=1
     elif 'ERROR:' in line or line.endswith(' ERROR') or 'overflow' in line.lower():
      errors+=1
      last_error=re.sub(r'/[^\s]+','<path>',line)[:256]
   if time.monotonic()-last>=2:
    value=snapshot(data,child,events,scanned,errors);value['last_error']=last_error;atomic(BASE/'feed/snapshot.json',json.dumps(value).encode(),reader=data['uid']);last=time.monotonic()
 finally:
  select.close()
  if child.poll() is None:
   child.terminate()
   try:child.wait(timeout=5)
   except subprocess.TimeoutExpired:child.kill();child.wait()
  value=snapshot(data,child,events,scanned,errors,True);value['last_error']=last_error;atomic(BASE/'feed/snapshot.json',json.dumps(value).encode(),reader=data['uid'])
 return 0 if stopping else child.returncode or 2

def manage(action):
 uid=caller();verify_install()
 if action=='disable':
  if owner()['uid']!=uid:raise ValueError('another account owns automatic scanning')
  code,_=command(['/usr/bin/systemctl','disable','--now',WATCH,TIMER]);command(['/usr/bin/systemctl','stop',ENGINE])
  return {'verified':code==0 and command(['/usr/bin/systemctl','is-active',WATCH])[1] in ('inactive','failed'),'message':'Automatic malware scanning stopped. One-off scans remain available.'}
 mode='prevent' if action=='enable-prevent' else 'notify'
 if action not in ('enable-prevent','enable-notify'):raise ValueError('invalid protection action')
 prepare(uid,mode)
 if command(['/usr/bin/systemctl','daemon-reload'])[0]:raise ValueError('service refresh failed')
 if command(['/usr/bin/systemctl','enable',WATCH,TIMER])[0]:raise ValueError('automatic service enable failed')
 if command(['/usr/bin/systemctl','restart',ENGINE])[0] or command(['/usr/bin/systemctl','restart',WATCH])[0] or command(['/usr/bin/systemctl','start',TIMER])[0]:raise ValueError('automatic service start failed')
 started=time.monotonic_ns()
 for _ in range(300):
  try:
   v=json.loads(safe_read(BASE/'feed/snapshot.json',65536))
   if v.get('owner_uid')==uid and v.get('mode')==mode and v.get('version')==VERSION and v.get('daemon_ready') and v.get('watcher_ready') and not v.get('stopped') and int(v.get('heartbeat_ns','0'))>=started and v.get('errors')==0 and v.get('database_current') is True:return {'verified':True,'message':'ClamAV Downloads protection verified.','mode':mode}
  except (OSError,ValueError):pass
  time.sleep(.5)
 return {'verified':False,'message':'Services were requested, but active scanning has not been verified. Review status.'}

def manage_locked(action):
 directory=root_dir(BASE,True)
 try:
  lock=os.open('control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
  try:
   info=os.fstat(lock)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('unsafe control lock')
   fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   return manage(action)
  finally:os.close(lock)
 finally:os.close(directory)

def main():
 if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('enable-notify','enable-prevent','disable','run'):return 2
 try:
  if sys.argv[1]=='run':return run()
  r=manage_locked(sys.argv[1]);print(json.dumps(r));return 0 if r['verified'] else 2
 except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as error:
  try:
   atomic(BASE/'feed/error.json',json.dumps({'schema':1,'error_type':type(error).__name__,'errno':getattr(error,'errno',None),'time':now()}).encode(),reader=owner()['uid'])
  except (OSError,ValueError):pass
  print(json.dumps({'verified':False,'message':'Automatic malware protection could not be verified. Refresh status and review OS authentication; no coverage is assumed.'}));return 2
if __name__=='__main__':raise SystemExit(main())
