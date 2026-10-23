#!/usr/bin/env python3
"""Build a local review bundle. Never push, tag, publish, or change repository visibility."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ironclad import __version__, sensor_policy
from tools.verify_publication import inspect


def git(*args):
    return subprocess.check_output(['/usr/bin/git','-C',str(ROOT),*args],text=True,timeout=10).strip()


def prepare(destination,tag=None,require_clean=False):
    manifest=json.loads((ROOT/'manifest.json').read_text())
    project=tomllib.loads((ROOT/'pyproject.toml').read_text())['project']
    version=manifest['version']
    if version!=project['version'] or version!=__version__:raise ValueError('product versions differ')
    if tag is not None and tag!='v'+version:raise ValueError('tag does not match product version')
    dirty=bool(git('status','--porcelain','--untracked-files=normal'))
    if require_clean and dirty:raise ValueError('release source must be clean')
    spec=importlib.util.spec_from_file_location('release_builder',ROOT/'tools/build_release.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    body=builder.build()
    findings=inspect('release.tar.gz',body,(str(Path.home()).encode(),str(ROOT).encode()))
    if findings:raise ValueError('publication privacy checks failed; matched data withheld')
    if builder.build()!=body:raise ValueError('archive is not reproducible')
    name='zds-ironclad-'+version+'.tar.gz';checksum=hashlib.sha256(body).hexdigest()
    metadata={'schema':1,'plugin_id':manifest['id'],'version':version,'source_commit':git('rev-parse','HEAD'),
              'source_dirty':dirty,'requested_tag':tag,'publication_performed':False,
              'archive':{'name':name,'sha256':checksum,'bytes':len(body)},
              'sensor':{'policy_version':sensor_policy.VERSION,'falco_version':sensor_policy.FALCO_VERSION,'archive_sha256':sensor_policy.ARCHIVE_SHA,'binary_sha256':sensor_policy.ENGINE_SHA,'krsi_version':sensor_policy.KRSI_VERSION,'krsi_archive_sha256':sensor_policy.KRSI_ARCHIVE_SHA,'krsi_binary_sha256':sensor_policy.KRSI_SHA,'rules_sha256':hashlib.sha256(sensor_policy.RULES_YAML.encode()).hexdigest(),'rule_count':len(sensor_policy.RULES)},
              'payload_sha256':{key:hashlib.sha256(value).hexdigest() for key,value in sorted(builder.manage.payload().items())},
              'limits':['Checksums are integrity records, not signed provenance.','A clean source or successful build is not security certification.','No fresh-machine or reboot acceptance is claimed by this tool.']}
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    assets={name:body,name+'.sha256':(checksum+'  '+name+'\n').encode(),'release-manifest.json':(json.dumps(metadata,sort_keys=True,indent=2)+'\n').encode()}
    # Refuse all conflicts before writing any asset.
    for key,value in assets.items():
        path=destination/key
        if path.is_symlink() or path.exists() and (not path.is_file() or path.read_bytes()!=value):raise ValueError('existing release asset differs; preserve it and choose a new directory')
    for key,value in assets.items():
        path=destination/key
        if not path.exists():
            with path.open('xb') as stream:stream.write(value)
    return metadata


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--tag')
    parser.add_argument('--require-clean',action='store_true')
    args=parser.parse_args()
    result=prepare(args.output,args.tag,args.require_clean)
    print(json.dumps({'version':result['version'],'sha256':result['archive']['sha256'],'source_dirty':result['source_dirty'],'payload_files':len(result['payload_sha256']),'publication_performed':False}))
    return 0


if __name__=='__main__':raise SystemExit(main())
