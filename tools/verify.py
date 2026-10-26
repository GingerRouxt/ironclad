#!/usr/bin/env python3
"""Run local checks and isolated CLI/report/package flows; never enable anything."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ironclad.storage import Store


def call(args, env=None, timeout=30):
    p=subprocess.run(args,cwd=ROOT,env=env,capture_output=True,text=True,timeout=timeout)
    if p.returncode: raise RuntimeError(f'{Path(args[0]).name} check failed: code {p.returncode}\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}')
    return p.stdout+p.stderr


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--ui-python',type=Path,help='existing PySide6 interpreter for real-process button-flow verification')
    parser.add_argument('--sensor-engine',type=Path,help='explicit pinned candidate engine for pre-installation policy validation')
    options=parser.parse_args()
    evidence=ROOT/'.local-evidence'; evidence.mkdir(exist_ok=True,mode=0o700)
    result={}
    for name,args in [
        ('python-tests',[sys.executable,'-B','-m','unittest','discover','-s','tests','-v']),
        ('model-tests',['node','--test','tests/model.test.cjs']),
        ('qml-lint',[sys.executable,'-B','tools/lint_qml.py']),
        ('detection-policy',[sys.executable,'-B','tools/verify_detection_policy.py']+(['--engine',str(options.sensor_engine.resolve())] if options.sensor_engine else [])),
        ('ruff',['ruff','check','--select','E9,F','ironclad','tests','packaging','tools','engine.py']),
        ('systemd-verify',['/usr/bin/systemd-analyze','--user','verify','packaging/systemd-user/zds-ironclad.service','packaging/systemd-user/zds-ironclad.timer','packaging/systemd-user/ironclad-protection-updates.service','packaging/systemd-user/ironclad-protection-updates.timer']),
    ]:
        begin=time.monotonic(); text=call(args,timeout=120 if name=='python-tests' else 30); (evidence/(name+'.txt')).write_text(text)
        result[name]={'passed':True,'elapsed_seconds':round(time.monotonic()-begin,3)}
    if options.ui_python:
        output=call([str(options.ui_python),'-B','tools/verify_update_ui.py'],timeout=120)
        (evidence/'update-ui-flow.json').write_text(output)
        result['update-ui-flow']=json.loads(output)
        output=call([str(options.ui_python),'-B','tools/verify_protection_ui.py'],timeout=60)
        (evidence/'protection-ui-flow.json').write_text(output)
        result['protection-ui-flow']=json.loads(output)
    else:
        result['update-ui-flow']={'passed':False,'skipped':'Provide --ui-python with PySide6 before release/install acceptance.'}
    with tempfile.TemporaryDirectory(prefix='ironclad-e2e-') as d:
        temp=Path(d); state=temp/'state'
        env={**os.environ,'XDG_RUNTIME_DIR':str(temp),'TMPDIR':str(temp)}
        base=[sys.executable,'-I','-B',str(ROOT/'engine.py'),'--state',str(state)]
        scan=json.loads(call(base+['check','--profile','full','--save'],env=env))
        result['full-scan']={'checks':len(scan['checks']),'elapsed_ms':scan['elapsed_ms'],'profile':scan['profile']}
        with Store(state) as s: s.replace_baseline(s.latest())
        drift=json.loads(call(base+['compare'],env=env)); assert drift['changed']==[]
        for format in ('html','json','markdown'):
            path=temp/('report.'+format)
            call(base+['report','--format',format,'--output',str(path)],env=env)
            assert path.stat().st_mode&0o777==0o600
            assert path.stat().st_size>0
        history=json.loads(call(base+['history'],env=env)); assert history['activity']=={'entries':[], 'limits':[]} and len(history['scans'])==1
        packet=json.loads(call(base+['ai-packet'],env=env)); assert packet['policy']['authorizes_actions'] is False
        result['cli-flow']={'passed':True,'reports':['html','json','markdown'],'baseline_compare':'no timestamp-only drift','ai_packet':'no transport/actions'}
        spec=importlib.util.spec_from_file_location('build_release',ROOT/'tools/build_release.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        first=module.build(); second=module.build(); assert first==second
        with tarfile.open(fileobj=io.BytesIO(first),mode='r:gz') as archive:
            members=archive.getmembers()
            assert all(m.isfile() and m.uid==0 and m.gid==0 and m.mtime==0 and not m.name.startswith('/') and '..' not in Path(m.name).parts for m in members)
            assert not any('/.venv/' in m.name or 'MASTER_SPEC' in m.name or '.local-evidence' in m.name for m in members)
            # Every entry is generated from a strict allowlist above; extraction is into a disposable fixture.
            archive.extractall(temp/'release',filter='data')
        release=temp/('release/zds-ironclad-'+module.VERSION)
        # Validate the actual shipped payload; ignored developer caches are not plugin files.
        manifest=call(['/usr/bin/omarchy','plugin','validate',str(release)])
        (evidence/'manifest.txt').write_text(manifest)
        result['manifest']={'passed':True,'scope':'allowlisted release payload'}
        call([sys.executable,'-I','-B',str(release/'packaging/manage.py'),'--root',str(temp/'config'),'--apply'],env=env)
        installed=temp/'config/omarchy/plugins/com.zerodaysecurity.ironclad'
        output=json.loads(call([sys.executable,'-I','-B',str(installed/'engine.py'),'check','--profile','quick'],env=env))
        assert len(output['checks'])==90
        software=json.loads(call([sys.executable,'-I','-B',str(installed/'engine.py'),'--state',str(temp/'installed-state'),'software'],env=env))
        assert software['schema']==2 and isinstance(software['items'],list) and not software['fresh']
        assert not (temp/'installed-state').exists()
        call([sys.executable,'-I','-B',str(installed/'companion.py'),'--help'],env=env)
        call([sys.executable,'-I','-B',str(installed/'packaging/manage.py'),'--root',str(temp/'config'),'--remove','--apply'],env=env)
        assert not installed.exists()
        result['release-flow']={'passed':True,'reproducible':True,'files':len(members),'sha256':hashlib.sha256(first).hexdigest(),'installed-engine-quick-checks':len(output['checks']),'installed-software-inventory':len(software['items']),'companion-entrypoint':'help loads without mutation','uninstall':'self-contained; no user state removed'}
    (evidence/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0

if __name__=='__main__': raise SystemExit(main())
