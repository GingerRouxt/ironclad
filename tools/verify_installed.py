#!/usr/bin/env python3
"""Read-only audit of the live user plugin against the reviewed payload allowlist."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def audit(destination=None):
    spec=importlib.util.spec_from_file_location('ironclad_package_manifest',ROOT/'packaging/manage.py')
    package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
    destination=Path(destination) if destination else Path.home()/'.config/omarchy/plugins'/package.ID
    receipt=json.loads((destination/'.ironclad-install.json').read_text())
    expected=set(package.FILES)
    actual={path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    extras=sorted(actual-expected-{'.ironclad-install.json'})
    missing=sorted(expected-actual)
    receipt_matches=receipt.get('id')==package.ID and set(receipt.get('files',{}))==expected
    unsafe=[];changed=[];source_mismatch=[]
    for name in sorted(expected & actual):
        path=destination/name
        if path.is_symlink() or path.stat().st_nlink!=1:
            unsafe.append(name);continue
        body=path.read_bytes()
        if hashlib.sha256(body).hexdigest()!=receipt.get('files',{}).get(name):changed.append(name)
        if body!=(ROOT/name).read_bytes():source_mismatch.append(name)
    result={'payload_files':len(expected),'extra_files':extras,'missing_files':missing,'receipt_allowlist_matches':receipt_matches,
            'unsafe_files':unsafe,'changed_files':changed,'source_mismatch':source_mismatch}
    result['passed']=receipt_matches and not any((extras,missing,unsafe,changed,source_mismatch))
    return result


if __name__=='__main__':
    result=audit();print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
