"""Unprivileged preparation of Ironclad's namespaced native sensor component."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import secrets
import stat
import subprocess
import tarfile
import time
import urllib.request
from . import sensor_policy as policy
from .storage import private_dir, open_dir

MAX_ARCHIVE=134217728


class SensorRedirect(urllib.request.HTTPRedirectHandler):
    """Permit only Falco's exact official CDN hop; bytes remain hash-pinned."""
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        destination=policy.ARCHIVE_URL.replace('https://download.falco.org/', 'https://d20hasrqv82i0q.cloudfront.net/', 1)
        if req.full_url!=policy.ARCHIVE_URL or newurl!=destination:
            raise ValueError('unexpected sensor download redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def sha(body):return hashlib.sha256(body).hexdigest()


def read_private(path,limit=MAX_ARCHIVE):
    parent=open_dir(Path(path).parent)
    try:fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:os.close(parent)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>limit:raise ValueError('unsafe sensor preparation file')
        return stream.read(limit+1)


def directory(state):
    path=Path(state)/'sensor-component';os.close(private_dir(path));return path


def archive(state,allow_network):
    path=directory(state)/policy.ARCHIVE_URL.rsplit('/',1)[1]
    if path.exists():
        body=read_private(path)
        if sha(body)!=policy.ARCHIVE_SHA:raise ValueError('cached sensor component failed integrity check')
        return body
    if not allow_network:raise ValueError('sensor component download requires explicit approval')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),SensorRedirect())
    request=urllib.request.Request(policy.ARCHIVE_URL,headers={'User-Agent':'Ironclad sensor preparation'})
    temporary=path.parent/('.download-'+secrets.token_hex(8));start=time.monotonic()
    try:
        with opener.open(request,timeout=10) as response,temporary.open('xb') as output:
            temporary.chmod(0o600);digest=hashlib.sha256();total=0
            while True:
                if time.monotonic()-start>120:raise ValueError('sensor download time limit')
                block=response.read1(1048576)
                if not block:break
                total+=len(block)
                if total>MAX_ARCHIVE:raise ValueError('sensor download size limit')
                output.write(block);digest.update(block)
        if digest.hexdigest()!=policy.ARCHIVE_SHA:raise ValueError('sensor download failed pinned integrity check')
        os.replace(temporary,path)
        return read_private(path)
    finally:
        try:temporary.unlink()
        except FileNotFoundError:pass


def krsi_payload():
    body=Path(__file__).with_name('krsi-component.tar.gz').read_bytes()
    if len(body)>8388608 or sha(body)!=policy.KRSI_ARCHIVE_SHA:raise ValueError('bundled async component integrity failure')
    files={};seen=set();total=0;library=None;metadata=None
    with tarfile.open(fileobj=io.BytesIO(body)) as source:
        for entry in source:
            name=entry.name;total+=entry.size
            if name in seen or len(seen)>=512 or not entry.isfile() or entry.size>4194304 or total>16777216 or name.startswith('/') or '..' in Path(name).parts:raise ValueError('unsafe async component archive')
            seen.add(name);content=source.extractfile(entry).read()
            if name=='libkrsi.so':library=content;files['usr/lib/ironclad/libkrsi.so']=content
            elif name=='build-info.json':metadata=json.loads(content);files['usr/share/ironclad-sensor/krsi-build-info.json']=content
            elif name.startswith('licenses/') or name in ('Cargo.lock','ironclad.patch','aya-obj-aliases.patch'):
                files['usr/share/licenses/ironclad-sensor/krsi/'+name]=content
            else:raise ValueError('unexpected async component member')
    if library is None or sha(library)!=policy.KRSI_SHA or not isinstance(metadata,dict) or metadata.get('library_sha256')!=policy.KRSI_SHA or metadata.get('version')!=policy.KRSI_VERSION or metadata.get('schema')!='4.5.0':raise ValueError('async component identity mismatch')
    return files


def payload(body):
    if sha(body)!=policy.ARCHIVE_SHA:raise ValueError('sensor archive hash mismatch')
    engine=None;license_files={}
    with tarfile.open(fileobj=io.BytesIO(body),mode='r:gz') as source:
        members=source.getmembers()
        if len(members)>5000:raise ValueError('sensor archive entry limit')
        for entry in members:
            # Only one known binary and license notices are copied. Nothing is extracted.
            if entry.name=='falco-0.45.1-x86_64/usr/bin/falco':
                if not entry.isfile() or entry.size>MAX_ARCHIVE:raise ValueError('unsafe sensor binary')
                engine=source.extractfile(entry).read(MAX_ARCHIVE+1)
            elif entry.isfile() and '/licenses/' in entry.name and entry.size<=1048576:
                relative=entry.name.split('/licenses/',1)[1]
                if '..' in Path(relative).parts or relative.startswith('/'):raise ValueError('unsafe license entry')
                license_files['usr/share/licenses/ironclad-sensor/upstream/'+relative]=source.extractfile(entry).read(1048577)
    if engine is None or sha(engine)!=policy.ENGINE_SHA:raise ValueError('sensor binary hash mismatch')
    data={'version':policy.VERSION,'engine_version':policy.FALCO_VERSION,'engine_sha256':policy.ENGINE_SHA,'krsi_version':policy.KRSI_VERSION,'krsi_sha256':policy.KRSI_SHA,'rules':policy.RULES,
          'config_sha256':sha(policy.CONFIG.encode()),'rules_sha256':sha(policy.RULES_YAML.encode())}
    helper=Path(__file__).with_name('sensor_service.py').read_bytes()
    files={'usr/lib/ironclad/falco':engine,'usr/lib/ironclad/sensor-helper':helper,
           'usr/share/ironclad-sensor/falco.yaml':policy.CONFIG.encode(),'usr/share/ironclad-sensor/rules.yaml':policy.RULES_YAML.encode(),
           'usr/share/ironclad-sensor/policy.json':json.dumps(data,sort_keys=True).encode(),
           'usr/lib/systemd/system/ironclad-sensor.service':policy.SERVICE.encode(),
           'usr/share/polkit-1/actions/com.zerodaysecurity.ironclad.sensor.policy':policy.POLKIT.encode(),
           'usr/share/licenses/ironclad-sensor/Falco-LICENSE':Path(__file__).with_name('FALCO-LICENSE').read_bytes(),
           'usr/share/licenses/ironclad-sensor/LICENSE':Path(__file__).resolve().parents[1].joinpath('LICENSE').read_bytes(),**license_files,**krsi_payload()}
    if not license_files:
        # The official static tarball currently may not include license files.
        files['usr/share/licenses/ironclad-sensor/Falco-NOTICE']=b'Falco 0.45.1, The Falco Authors. Apache-2.0. https://github.com/falcosecurity/falco/tree/0.45.1\nUpstream source, dependency notices and license: https://github.com/falcosecurity/falco\n'
    return files


def build(state,allow_network=False):
    from .maintenance import trusted,environment
    if platform.machine()!='x86_64':raise ValueError('embedded sensor currently supports x86_64 Linux only')
    files=payload(archive(state,allow_network));prepared=directory(state)
    fingerprint=sha(b''.join(name.encode()+b'\0'+sha(body).encode() for name,body in sorted(files.items())))
    dest=prepared/('ironclad-sensor-'+policy.VERSION+'-'+fingerprint[:16]+'-x86_64.pkg.tar.zst')
    temporary=prepared/('.package-'+secrets.token_hex(8)+'.tar')
    compressed=prepared/('.package-'+secrets.token_hex(8)+'.zst')
    try:
        with temporary.open('xb') as raw:
            temporary.chmod(0o600)
            with tarfile.open(fileobj=raw,mode='w',format=tarfile.USTAR_FORMAT) as package:
                info=('pkgname = ironclad-sensor\npkgbase = ironclad-sensor\npkgver = '+policy.VERSION+'-1\npkgdesc = Ironclad embedded local sensor (Falco)\nurl = https://szdsecurity.com\nbuilddate = 1792699200\npackager = Zero Day Security local development\nsize = '+str(sum(len(v) for v in files.values()))+'\narch = x86_64\nlicense = MIT\nlicense = Apache-2.0\ndepend = python\ndepend = glibc\ndepend = gcc-libs\ndepend = systemd\ndepend = acl\ndepend = polkit\n').encode()
                removal=b'pre_remove() { /usr/bin/systemctl disable --now ironclad-sensor.service >/dev/null 2>&1 || return 1; }\npost_remove() { /usr/bin/systemctl daemon-reload; }\n'
                entries={'.PKGINFO':info,'.INSTALL':removal,**files}
                # Explicit directory entries keep privileged parent paths root-owned.
                dirs=sorted({str(parent) for name in files for parent in Path(name).parents if str(parent)!='.'},key=lambda v:(v.count('/'),v))
                for name in dirs:
                    item=tarfile.TarInfo(name);item.type=tarfile.DIRTYPE;item.mode=0o755;item.uid=item.gid=0;package.addfile(item)
                for name,content in sorted(entries.items()):
                    item=tarfile.TarInfo(name);item.size=len(content);item.mode=0o755 if name in ('usr/lib/ironclad/falco','usr/lib/ironclad/sensor-helper') else 0o644;item.uid=item.gid=0;package.addfile(item,io.BytesIO(content))
        result=subprocess.run([trusted('/usr/bin/zstd'),'-q','-T1','--no-progress',str(temporary),'-o',str(compressed)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=environment(),timeout=60,check=False)
        if result.returncode:raise ValueError('sensor packaging did not complete')
        compressed.chmod(0o600)
        if dest.exists() and read_private(dest)!=read_private(compressed):raise ValueError('prepared package failed integrity check')
        os.replace(compressed,dest)
    finally:
        for path in (temporary,compressed):
            try:path.unlink()
            except FileNotFoundError:pass
    blob=read_private(dest)
    return {'path':str(dest),'sha256':sha(blob),'bytes':len(blob),'component_version':policy.VERSION,'engine_version':policy.FALCO_VERSION,'payload_id':fingerprint}
