"""Private gzip snapshots before a new scan; never prune or overwrite reports."""
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import stat
from uuid import UUID
from .model import redact,validate_scan
from .storage import private_dir,safe_file

LIMIT=4194304

def archive(state,snapshot,explanations=None):
 validate_scan(snapshot)
 identifier=str(UUID(snapshot['scan_id']))
 rows={} if explanations is None else explanations
 if not isinstance(rows,dict) or len(rows)>len(snapshot['checks']):raise ValueError('invalid archived explanations')
 ids={c['check_id'] for c in snapshot['checks']};clean={}
 for key,row in rows.items():
  if key not in ids or not isinstance(row,dict) or row.get('check_id')!=key:raise ValueError('explanation does not belong to scan')
  value={'check_id':key}
  for field in ('meaning','action','verification'):
   item=row.get(field)
   if not isinstance(item,str) or not item.strip() or len(item)>600:raise ValueError('invalid archived explanation')
   value[field]=redact(item)
  clean[key]=value
 body=json.dumps({'schema':1,'scan':snapshot,'explanations':clean},sort_keys=True,separators=(',',':'),allow_nan=False).encode()
 if len(body)>LIMIT:raise ValueError('archive size bound')
 digest=hashlib.sha256(body).hexdigest();name=identifier+'-'+digest[:16]+'.json.gz'
 parent=private_dir(state);directory=None;lock=None;temporary='.'+secrets.token_hex(16)+'.tmp'
 try:
  lock=safe_file(parent,'scan-archives.lock');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:os.mkdir('scan-archives',0o700,dir_fd=parent)
  except FileExistsError:pass
  directory=private_dir(Path(state)/'scan-archives')
  packed=gzip.compress(body,compresslevel=6,mtime=0)
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  with os.fdopen(fd,'wb') as stream:stream.write(packed);stream.flush();os.fsync(stream.fileno())
  try:os.link(temporary,name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
  except FileExistsError:
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
   with os.fdopen(fd,'rb') as stream:
    meta=os.fstat(stream.fileno())
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_size>LIMIT+65536:raise ValueError('unsafe existing archive')
    packed=stream.read(LIMIT+65537)
   with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:previous=stream.read(LIMIT+1)
   if previous!=body:raise ValueError('conflicting archive preserved')
  os.unlink(temporary,dir_fd=directory);os.fsync(directory)
 finally:
  if directory is not None:
   try:os.unlink(temporary,dir_fd=directory)
   except FileNotFoundError:pass
   os.close(directory)
  if lock is not None:os.close(lock)
  os.close(parent)
 return {'archived':True,'file':name,'scan_id':identifier,'checks':len(snapshot['checks']),'ai_explanations':len(clean),'sha256':digest}
