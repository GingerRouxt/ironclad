#!/usr/bin/env python3
"""Build the reviewed, local KRSI fork from pinned public inputs (never install it)."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tomllib
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
INPUTS={
 'sdk':('https://api.github.com/repos/falcosecurity/plugin-sdk-rs/tarball/1a7e29e62d025dcd91796537421343111e55cd61','f17396805a0fdf87ceb9edc07c9f5827b4e64215ec777f23a67d8e0277d1f3ed'),
 'krsi':('https://api.github.com/repos/falcosecurity/plugins/tarball/plugins/krsi/v0.2.0','6758706bc60814482a28b44567c55f8e1d70718917bf1d4dc39fc730e708c467'),
 'binary':('https://download.falco.org/plugins/stable/krsi-0.2.0-linux-x86_64.tar.gz','b94e5bdf4f2e629befd11949139a636b99da177962da34b78a7149b3bb3fe115'),
 'ayaobj':('https://static.crates.io/crates/aya-obj/aya-obj-0.2.1.crate','c51b96c5a8ed8705b40d655273bc4212cbbf38d4e3be2788f36306f154523ec7'),
}
BPF_SHA='898eda944bd24cd15096946bf667771da30686fc784f5f239c6d265fa349193f'
RUSTC_VERSION='rustc 1.99.1 (58cf8f9c3 2026-10-13)'
FORK_VERSION='0.2.0-ironclad.2'


def build_environment(work, cargo_home, toolchain, bpf):
    """Allowlisted environment; the caller must also isolate build execution."""
    toolchain=toolchain.resolve()
    rustc=toolchain/'bin/rustc'
    env={'PATH':str(toolchain/'bin')+':/usr/bin', 'HOME':str(work/'home'),
         'LANG':'C.UTF-8', 'CARGO_HOME':str(cargo_home.absolute()),
         'RUSTC':str(rustc), 'CARGO_BUILD_JOBS':'2',
         'IRONCLAD_UPSTREAM_BPF':str(bpf), 'SOURCE_DATE_EPOCH':'1792699200',
         'RUSTFLAGS':' '.join(('--remap-path-prefix='+str(work)+'=/ironclad-build',
                              '--remap-path-prefix='+str(cargo_home.absolute())+'=/cargo-cache',
                              '--remap-path-prefix='+str(toolchain)+'=/rust-toolchain'))}
    version=subprocess.check_output([str(rustc),'--version'],env=env,text=True,timeout=10).strip()
    if version!=RUSTC_VERSION:raise ValueError('unexpected Rust compiler; use the recorded pinned toolchain')
    (work/'home').mkdir(mode=0o700,exist_ok=True)
    return env


def sha(body):return hashlib.sha256(body).hexdigest()


def unpack(body,destination,subtree=None):
    total=0
    with tarfile.open(fileobj=io.BytesIO(body)) as archive:
        members=archive.getmembers()
        if len(members)>20000:raise ValueError('source entry limit')
        prefix=members[0].name.split('/')[0]+'/'
        for item in members:
            if not item.isfile():continue
            name=item.name[len(prefix):]
            if subtree and not name.startswith(subtree):continue
            if not item.name.startswith(prefix) or not name or name.startswith('/') or '..' in Path(name).parts or item.size>33554432:raise ValueError('unsafe source member')
            total+=item.size
            if total>134217728:raise ValueError('source size limit')
            path=destination/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(archive.extractfile(item).read())


def bpf_program(library):
    offset=0;found=[]
    while True:
        offset=library.find(b'\x7fELF',offset)
        if offset<0:break
        start=offset;offset+=4
        if start+64>len(library) or library[start+4:start+6]!=b'\x02\x01' or struct.unpack_from('<H',library,start+18)[0]!=247:continue
        shoff=struct.unpack_from('<Q',library,start+40)[0];entry,count=struct.unpack_from('<HH',library,start+58)
        if entry!=64 or not 0<count<4096 or start+shoff+entry*count>len(library):raise ValueError('unsafe BPF sections')
        size=shoff+entry*count
        for index in range(count):
            row=struct.unpack_from('<IIQQQQIIQQ',library,start+shoff+index*entry)
            if row[1]!=8:size=max(size,row[4]+row[5])
        if start+size>len(library):raise ValueError('unsafe BPF size')
        found.append(library[start:start+size])
    if len(found)!=1 or sha(found[0])!=BPF_SHA:raise ValueError('upstream BPF identity mismatch')
    return found[0]


def bundle(files):
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,body in sorted(files.items()):
            item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o644;item.uid=item.gid=item.mtime=0
            archive.addfile(item,io.BytesIO(body))
    output=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as stream:stream.write(raw.getvalue())
    return output.getvalue()


def openat_aliases(program):
    """Expose identical open handlers at both kernel entry points.

    Only the ELF symbol/string tables change. Instructions, relocations, maps,
    and BTF remain byte-for-byte upstream. Both aliases share the same maps.
    """
    if sha(program)!=BPF_SHA:raise ValueError('unexpected BPF input')
    body=bytearray(program)
    shoff=struct.unpack_from('<Q',body,40)[0]
    size,count=struct.unpack_from('<HH',body,58)
    sections=[list(struct.unpack_from('<IIQQQQIIQQ',body,shoff+i*size)) for i in range(count)]
    tables=[i for i,s in enumerate(sections) if s[1]==2]
    if len(tables)!=1:raise ValueError('expected one symbol table')
    index=tables[0];symbols=sections[index];strings=sections[symbols[6]]
    if symbols[9]!=24 or symbols[5]%24:raise ValueError('unexpected ELF symbols')
    names=bytearray(body[strings[4]:strings[4]+strings[5]])
    entries=bytearray(body[symbols[4]:symbols[4]+symbols[5]])
    for old,new in ((b'io_openat2_e',b'io_openat_e'),(b'io_openat2_x',b'io_openat_x')):
        matches=[]
        for offset in range(0,len(entries),24):
            row=list(struct.unpack_from('<IBBHQQ',entries,offset))
            name=bytes(names[row[0]:]).split(b'\0',1)[0]
            if name==old:matches.append(row)
            if name==new:raise ValueError('alias already present')
        if len(matches)!=1 or matches[0][1]!=0x12 or not matches[0][5]:raise ValueError('unexpected open handler')
        row=matches[0];row[0]=len(names);names.extend(new+b'\0')
        entries.extend(struct.pack('<IBBHQQ',*row))
    for section,data in ((strings,names),(symbols,entries)):
        body.extend(b'\0'*(-len(body)%8));section[4]=len(body);section[5]=len(data);body.extend(data)
    for i,section in enumerate(sections):struct.pack_into('<IIQQQQIIQQ',body,shoff+i*size,*section)
    return bytes(body)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir',type=Path,required=True,help='new disposable build directory')
    parser.add_argument('--inputs',type=Path,required=True,help='directory with pinned sdk, krsi, binary and ayaobj .tar.gz inputs')
    parser.add_argument('--cargo-home',type=Path,required=True,help='isolated public build cache; never a credential-bearing Cargo home')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--toolchain-dir',type=Path,help='pinned Rust installation root; otherwise resolve through mise/rustup')
    parser.add_argument('--allow-network',action='store_true',help='download exact pinned inputs and public crates')
    args=parser.parse_args();work=args.work_dir.absolute()
    if work.exists():raise ValueError('preserve existing build directory; choose a new path')
    work.mkdir(parents=True,mode=0o700);args.inputs.mkdir(parents=True,exist_ok=True)
    bodies={}
    for key,(url,expected) in INPUTS.items():
        path=args.inputs/(key+'.tar.gz')
        if not path.exists():
            if not args.allow_network:raise ValueError('pinned input missing: '+key)
            with urllib.request.urlopen(url,timeout=20) as response:body=response.read(33554433)
            if len(body)>33554432 or sha(body)!=expected:raise ValueError('input integrity failure: '+key)
            path.write_bytes(body);path.chmod(0o600)
        body=path.read_bytes()
        if len(body)>33554432 or sha(body)!=expected:raise ValueError('input integrity failure: '+key)
        bodies[key]=body
    unpack(bodies['sdk'],work/'sdk');unpack(bodies['krsi'],work/'plugins','plugins/krsi/')
    unpack(bodies['ayaobj'],work/'aya-obj')
    subprocess.run(['/usr/bin/patch','--batch','--fuzz=0','-p1','--input',str(ROOT/'tools/aya-obj-aliases.patch')],cwd=work/'aya-obj',check=True,timeout=10)
    with tarfile.open(fileobj=io.BytesIO(bodies['binary'])) as archive:
        members=archive.getmembers()
        if len(members)!=1 or members[0].name!='libkrsi.so' or not members[0].isfile() or members[0].size>16777216:raise ValueError('unsafe upstream binary')
        library=archive.extractfile(members[0]).read()
    bpf=work/'openat-aliases.bpf.o';bpf.write_bytes(openat_aliases(bpf_program(library)))
    source=work/'plugins/plugins/krsi'
    subprocess.run(['/usr/bin/patch','--batch','--fuzz=0','-p1','--input',str(ROOT/'tools/krsi-ironclad.patch')],cwd=source,check=True,timeout=10)
    lock=(ROOT/'tools/krsi-Cargo.lock').read_bytes();(source/'Cargo.lock').write_bytes(lock)
    toolchain=args.toolchain_dir
    if toolchain is None:
        rustc=subprocess.check_output(['mise','exec','--','rustup','which','rustc'],text=True,timeout=20).strip()
        toolchain=Path(rustc).parent.parent
    env=build_environment(work,args.cargo_home,toolchain,bpf)
    cargo=str(toolchain.resolve()/'bin/cargo')
    command=[cargo,'build','--release','--locked','-p','krsi','--manifest-path',str(source/'Cargo.toml')]
    if not args.allow_network:command.append('--offline')
    subprocess.run(command,env=env,check=True,timeout=600)
    library=(source/'target/release/libkrsi.so').read_bytes()
    if any(path.encode() in library for path in (str(Path.home()),str(work),str(args.cargo_home.absolute()))):
        raise ValueError('native library contains a private build path')
    toolchain=RUSTC_VERSION
    metadata={'version':FORK_VERSION,'schema':'4.5.0','sdk_commit':'1a7e29e62d025dcd91796537421343111e55cd61','inputs':{k:{'url':u,'sha256':h} for k,(u,h) in INPUTS.items()},'bpf_sha256':BPF_SHA,'library_sha256':sha(library),'patch_sha256':sha((ROOT/'tools/krsi-ironclad.patch').read_bytes()),'lock_sha256':sha(lock),'toolchain':toolchain,'upstream_release':False}
    metadata['aliased_bpf_sha256']=sha(bpf.read_bytes())
    metadata['bpf_changes']='ELF symbol aliases for io_openat; upstream instructions, maps, relocations and BTF unchanged'
    metadata['loader_patch_sha256']=sha((ROOT/'tools/aya-obj-aliases.patch').read_bytes())
    files={'libkrsi.so':library,'build-info.json':(json.dumps(metadata,sort_keys=True,indent=2)+'\n').encode(),'Cargo.lock':lock,'ironclad.patch':(ROOT/'tools/krsi-ironclad.patch').read_bytes(),
           'aya-obj-aliases.patch':(ROOT/'tools/aya-obj-aliases.patch').read_bytes(),
           'licenses/SDK-LICENSE':(work/'sdk/LICENSE').read_bytes(),'licenses/KRSI-LICENSE':(ROOT/'ironclad/FALCO-LICENSE').read_bytes()}
    for path in (work/'aya-obj').glob('LICENSE*'):
        if path.is_file():files['licenses/aya-obj-'+path.name]=path.read_bytes()
    # Include public registry license/notice files for statically linked Rust crates.
    registry=args.cargo_home/'registry/src'
    locked={p['name']+'-'+p['version'] for p in tomllib.loads(lock.decode())['package']
            if p.get('source')=='registry+https://github.com/rust-lang/crates.io-index'}
    if registry.is_dir():
        for crate in registry.glob('*/*'):
            if not crate.is_dir() or crate.is_symlink() or crate.name not in locked:continue
            for path in sorted(crate.iterdir()):
                if path.is_file() and not path.is_symlink() and path.name.upper().startswith(('LICENSE','COPYING','NOTICE')) and path.stat().st_size<=1048576:
                    files['licenses/'+crate.name+'/'+path.name]=path.read_bytes()
    body=bundle(files)
    if args.output.exists():raise ValueError('preserve existing artifact; choose a new output')
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(body)
    print(json.dumps({'artifact':str(args.output),'archive_sha256':sha(body),'bytes':len(body),'library_sha256':metadata['library_sha256'],'license_files':len(files)-4}))


if __name__=='__main__':main()
