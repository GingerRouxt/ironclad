"""Unprivileged, reproducible package preparation; never installs or starts services."""
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import tarfile
from . import onaccess_policy as policy
from .storage import private_dir

def payload():
 files={'usr/lib/ironclad/antimalware-helper':Path(__file__).with_name('onaccess_service.py').read_bytes(),
 'usr/share/polkit-1/actions/com.zerodaysecurity.ironclad.antimalware.policy':policy.POLKIT.encode()}
 files.update({'usr/lib/systemd/system/'+n:v.encode() for n,v in policy.UNITS.items()})
 manifest={'version':policy.VERSION,'files':{n:hashlib.sha256(b).hexdigest() for n,b in files.items()}}
 files['usr/share/ironclad-antimalware/manifest.json']=json.dumps(manifest,sort_keys=True).encode()
 files['usr/share/licenses/ironclad-antimalware/LICENSE']=Path(__file__).resolve().parents[1].joinpath('LICENSE').read_bytes()
 return files

def build(state):
 from .maintenance import trusted,environment
 from .sensor_package import read_private
 files=payload();directory=Path(state)/'antimalware-component';os.close(private_dir(directory))
 fingerprint=hashlib.sha256(b''.join(n.encode()+b'\0'+hashlib.sha256(b).digest() for n,b in sorted(files.items()))).hexdigest()
 dest=directory/('ironclad-antimalware-'+policy.VERSION+'-'+fingerprint[:16]+'-any.pkg.tar.zst')
 raw=directory/('.package-'+secrets.token_hex(8)+'.tar');compressed=directory/('.package-'+secrets.token_hex(8)+'.zst')
 try:
  with raw.open('xb') as f:
   raw.chmod(0o600)
   with tarfile.open(fileobj=f,mode='w',format=tarfile.USTAR_FORMAT) as tar:
    info=('pkgname = ironclad-antimalware\npkgbase = ironclad-antimalware\npkgver = '+policy.VERSION+'-1\npkgdesc = Ironclad ClamAV Downloads protection\nurl = https://szdsecurity.com\nbuilddate = 1792699200\npackager = Zero Day Security local development\nsize = '+str(sum(map(len,files.values())))+'\narch = any\nlicense = MIT\ndepend = python\ndepend = clamav\ndepend = systemd\ndepend = acl\ndepend = polkit\n').encode()
    remove=b'pre_remove() { /usr/bin/systemctl disable --now ironclad-antimalware.service ironclad-antimalware-refresh.timer >/dev/null 2>&1 || return 1; /usr/bin/systemctl stop ironclad-antimalware-engine.service || return 1; }\npost_remove() { /usr/bin/systemctl daemon-reload; }\n'
    dirs=sorted({str(p) for n in files for p in Path(n).parents if str(p)!='.'},key=lambda p:(p.count('/'),p))
    for n in dirs:
     i=tarfile.TarInfo(n);i.type=tarfile.DIRTYPE;i.mode=0o755;i.uid=i.gid=0;tar.addfile(i)
    for n,b in sorted({'.PKGINFO':info,'.INSTALL':remove,**files}.items()):
     i=tarfile.TarInfo(n);i.size=len(b);i.mode=0o755 if n.endswith('antimalware-helper') else 0o644;i.uid=i.gid=0;tar.addfile(i,io.BytesIO(b))
  r=subprocess.run([trusted('/usr/bin/zstd'),'-q','-T1',str(raw),'-o',str(compressed)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=environment(),timeout=30)
  if r.returncode:raise ValueError('automatic protection package preparation failed')
  compressed.chmod(0o600)
  if dest.exists() and read_private(dest)!=read_private(compressed):raise ValueError('prepared component changed')
  os.replace(compressed,dest)
 finally:
  for p in (raw,compressed):
   try:p.unlink()
   except FileNotFoundError:pass
 body=read_private(dest)
 return {'path':str(dest),'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),'component_version':policy.VERSION,'payload_id':fingerprint}
