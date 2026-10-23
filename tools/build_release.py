#!/usr/bin/env python3
"""Reproducible allowlisted runtime archive; no home/cache/git metadata included."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

ROOT=Path(__file__).resolve().parents[1]
VERSION=json.loads((ROOT/'manifest.json').read_text())['version']
spec=importlib.util.spec_from_file_location('ironclad_packaging',ROOT/'packaging/manage.py')
manage=importlib.util.module_from_spec(spec); spec.loader.exec_module(manage)


def build():
    output=io.BytesIO()
    with gzip.GzipFile(fileobj=output,mode='wb',filename='',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            for name,body in sorted(manage.payload().items()):
                entry=tarfile.TarInfo('zds-ironclad-'+VERSION+'/'+name)
                entry.size=len(body); entry.mode=0o755 if name == 'zds-ironclad' else 0o644; entry.mtime=0; entry.uid=entry.gid=0; entry.uname=entry.gname=''
                archive.addfile(entry,io.BytesIO(body))
    return output.getvalue()


def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',type=Path,default=ROOT/('dist/zds-ironclad-'+VERSION+'.tar.gz')); a=p.parse_args()
    body=build(); a.output.parent.mkdir(parents=True,exist_ok=True)
    if a.output.exists():
        if a.output.read_bytes()!=body: raise ValueError('existing artifact differs; preserve and choose a new output name')
    else:
        with a.output.open('xb') as f: f.write(body)
    checksum=hashlib.sha256(body).hexdigest()
    checksum_file=a.output.with_suffix(a.output.suffix+'.sha256')
    expected=checksum+'  '+a.output.name+'\n'
    if checksum_file.exists():
        if checksum_file.read_text()!=expected: raise ValueError('existing checksum differs')
    else: checksum_file.write_text(expected)
    print(checksum+'  '+a.output.name)
    return 0

if __name__=='__main__': raise SystemExit(main())
