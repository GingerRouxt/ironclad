#!/usr/bin/env python3
"""Opt-in bounded native coexistence test; creates/scans only disposable fixtures.

Does not install, stop, restart, remove or enable any service. Requires an already
healthy sensor and scanner. Records only health metrics and test outcomes.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ironclad import sensor, malware

WORKLOAD = '''import os,time,compileall
from pathlib import Path
os.nice(10)
root=Path(__import__('sys').argv[1]);end=time.monotonic()+float(__import__('sys').argv[2])
for n in range(64):
 (root/('module_'+str(n)+'.py')).write_text('def calculate(x):\\n return x*x+1\\n'*32)
while time.monotonic()<end:
 compileall.compile_dir(root,force=True,quiet=2)
 for p in root.glob('module_*.py'):p.read_bytes()
 time.sleep(.2)
'''


def memory_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1])*1024
    raise ValueError('memory availability could not be verified')


def process_record(pid, proc=Path('/proc')):
    """Read identity/liveness only; never collect command arguments or environment."""
    try:
        raw=(proc/str(pid)/'stat').read_text()
        prefix, tail=raw.rsplit(') ',1); fields=tail.split()
        return {'pid':pid,'name':prefix.split('(',1)[1], 'state':fields[0],
                'parent':int(fields[1]),'start':int(fields[19])}
    except (OSError,ValueError,IndexError):
        return None


def codex_ancestors(pid=None, proc=Path('/proc')):
    pid=os.getppid() if pid is None else pid
    watched=[];seen=set()
    while pid>1 and pid not in seen:
        seen.add(pid);record=process_record(pid,proc)
        if record is None:break
        if record['name']=='codex':watched.append(record)
        pid=record['parent']
    if not watched:raise RuntimeError('Run this workstation coexistence check from the active Codex session')
    return watched


def missing_processes(watched, proc=Path('/proc')):
    missing=[]
    for original in watched:
        current=process_record(original['pid'],proc)
        if current is None or current['start']!=original['start'] or current['state'] in ('Z','X'):
            missing.append(original['pid'])
    return missing


def guard_failure(sample):
    if not sample['codex_alive']:return 'active Codex session exited or changed identity'
    if sample['available_bytes']<2*1024**3:return 'available memory fell below 2 GiB'
    return None


def save_result(path, result):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n')


def require_healthy_start(initial, scanner_ready, available):
    if initial.get('state')!='monitoring' or not initial.get('monitoring') or not scanner_ready:
        raise RuntimeError('sensor must have clean current metrics and scanner signatures must be ready before testing')
    if available<5*1024**3:
        raise RuntimeError('at least 5 GiB available memory is required before testing')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='approve disposable native scan/workload fixtures')
    parser.add_argument('--duration',type=int,default=120)
    parser.add_argument('--output',type=Path,default=ROOT/'.local-evidence/native-load-acceptance.json')
    args=parser.parse_args()
    if not args.run or not 30<=args.duration<=180:
        parser.error('--run and a duration between 30 and 180 seconds are required')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    state=Path.home()/'.local/state/ironclad'
    initial=sensor.status(state)
    try:
        require_healthy_start(initial,malware.status(state)['ready'],memory_available())
    except RuntimeError as error:
        save_result(args.output,{'passed':False,'failure':str(error),'phase':'preflight',
                                'sensor_state':initial['state'],'metrics':initial['metrics']})
        raise
    codex=codex_ancestors()
    samples=[]
    with tempfile.TemporaryDirectory(prefix='ironclad-native-test-',dir=Path.home()/'Downloads') as temporary:
        base=Path(temporary);build=base/'build';build.mkdir()
        target=base/'eicar-test.txt'
        target.write_bytes(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        target.chmod(0o600)
        with (base/'scanner-result.json').open('w+') as output:
            worker=subprocess.Popen([sys.executable,'-I','-B','-c',WORKLOAD,str(build),str(args.duration)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            code='import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from ironclad import malware;s=Path(sys.argv[2]);p=malware.plan(s,sys.argv[3]);print(json.dumps(malware.scan(s,p,p["digest"])))'
            scanner=subprocess.Popen([sys.executable,'-I','-B','-c',code,str(ROOT),str(state),str(target)],stdout=output,stderr=subprocess.DEVNULL)
            start=time.monotonic()
            try:
                while time.monotonic()-start<args.duration:
                    status=sensor.status(state)
                    missing=missing_processes(codex)
                    sample={'elapsed_seconds':round(time.monotonic()-start,2),'state':status['state'],'metrics':status['metrics'],
                            'available_bytes':memory_available(),'codex_alive':not missing,'missing_codex_process_ids':missing}
                    samples.append(sample)
                    failure=guard_failure(sample)
                    if failure:
                        save_result(args.output,{'passed':False,'failure':failure,'samples':samples})
                        raise RuntimeError(failure+'; evidence recorded; stopping test workload')
                    time.sleep(2)
                worker.wait(timeout=10)
                scanner.wait(timeout=160)
                output.seek(0);scan=json.load(output)
                service=subprocess.check_output(['systemctl','show','ironclad-sensor.service','-p','MemoryCurrent','-p','MemoryPeak','-p','NRestarts','-p','CPUUsageNSec'],text=True)
                result={'duration_seconds':args.duration,'workload':'one low-priority worker compiling 64 synthetic modules repeatedly',
                        'codex_process_count':len(codex),'process_scope':'active Codex ancestry with PID start-time identity','samples':samples,'scan_outcome':scan['outcome'],
                        'scanner_exit':scanner.returncode,'worker_exit':worker.returncode,'service':dict(line.split('=',1) for line in service.splitlines()),
                        'passed':bool(codex) and all(s['codex_alive'] and s['state']=='monitoring' for s in samples) and scan['outcome']=='detected' and scanner.returncode==0 and worker.returncode==0}
                save_result(args.output,result)
                print(json.dumps({key:value for key,value in result.items() if key!='samples'}))
                return 0 if result['passed'] else 1
            finally:
                for child in (worker,scanner):
                    if child.poll() is None:
                        child.terminate()
                        try:child.wait(timeout=5)
                        except subprocess.TimeoutExpired:child.kill();child.wait()


if __name__=='__main__':
    raise SystemExit(main())
