"""Unprivileged embedded sensor lifecycle, private alert intake and review state."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import time
from . import sensor_policy as policy
from .model import redact
from .storage import open_dir, private_dir

BASE=Path(policy.BASE)
HELPER=Path(policy.HELPER)
ALERT_ID=re.compile(r'[a-f0-9]{16}:[0-9]{1,12}\Z')
MAX_EVENTS=256


def installed():
    from .maintenance import trusted
    try:trusted(str(HELPER));return True
    except (OSError,ValueError):return False


def compatibility():
    version=platform.release().split('-')[0].split('.')
    recent=len(version)>=2 and all(v.isdecimal() for v in version[:2]) and tuple(int(v) for v in version[:2])>=(5,8)
    return {'supported':platform.machine()=='x86_64' and platform.system()=='Linux' and Path('/sys/kernel/btf/vmlinux').is_file() and recent,
            'architecture':platform.machine(),'btf':Path('/sys/kernel/btf/vmlinux').is_file(),'kernel':platform.release()[:100]}


def read_root(path,limit=262144):
    fd=open_dir(Path(path).parent)
    try:f=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    finally:os.close(fd)
    with os.fdopen(f,'rb') as stream:
        meta=os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_nlink!=1 or meta.st_mode&0o022 or meta.st_size>limit:raise ValueError('unsafe sensor feed')
        return json.loads(stream.read(limit+1))


def service_state():
    from .maintenance import capture
    try:
        text=capture(['/usr/bin/systemctl','show',policy.UNIT,'--property=LoadState,ActiveState,SubState','--no-pager'],timeout=3)
        data=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
        return data.get('ActiveState','unknown') if data.get('LoadState')=='loaded' else 'not-found'
    except (OSError,ValueError):return 'unknown'


def review_state(state):
    path=Path(state)/'sensor-reviewed.json'
    try:
        from .sensor_package import read_private
        data=json.loads(read_private(path,32768))
    except FileNotFoundError:return []
    if not isinstance(data,list) or len(data)>MAX_EVENTS or any(not isinstance(v,str) or not ALERT_ID.fullmatch(v) for v in data):raise ValueError('invalid reviewed-alert state')
    return data


def parse_feed(data):
    if not isinstance(data,dict) or data.get('schema')!=1 or not isinstance(data.get('events'),list) or len(data['events'])>MAX_EVENTS:raise ValueError('invalid sensor snapshot')
    events=[];rules={v['id']:v for v in policy.RULES.values()}
    for row in data['events']:
        if isinstance(row,dict) and isinstance(row.get('rule_id'),str) and row['rule_id'].startswith('upstream.'):
            from .falco_rules import catalog_entry
            priority={'critical':'CRITICAL','high':'ERROR','medium':'WARNING','low':'NOTICE','info':'INFO'}.get(row.get('severity'))
            entry=catalog_entry(row.get('title'),priority)
            if entry['id']!=row['rule_id']:raise ValueError('upstream rule identity mismatch')
            rules[entry['id']]=entry
        if not isinstance(row,dict) or row.get('rule_id') not in rules or not isinstance(row.get('id'),str) or not ALERT_ID.fullmatch(row['id']):raise ValueError('invalid sensor event')
        for field,limit in [('time',64),('app',64),('event',32)]:
            if not isinstance(row.get(field),str) or len(row[field])>limit:raise ValueError('invalid sensor event text')
        if datetime.fromisoformat(row['time'].replace('Z','+00:00')).tzinfo is None:raise ValueError('invalid sensor timestamp')
        source=rules[row['rule_id']]
        if row['id'] in {event['id'] for event in events}:raise ValueError('duplicate sensor event')
        events.append({**source,'rule_id':row['rule_id'],'id':row['id'],'time':row['time'],'app':redact(row['app']),'event':row['event']})
    return events


def status(state):
    compatible=compatibility();present=installed();limits=[]
    result={'schema':1,'installed':present,'compatible':compatible['supported'],'state':'not_installed' if compatible['supported'] else 'unsupported','monitoring':False,
            'message':'Enable local monitoring to add the embedded sensor.' if compatible['supported'] else 'This sensor currently needs x86_64 Linux, kernel 5.8+ and BTF support.',
            'engine':'Falco '+policy.FALCO_VERSION,'policy_version':policy.VERSION,'rules_count':len(policy.RULES),'alerts':[],'unreviewed':0,'metrics':None,'owner_match':True,'limits':limits}
    try:reviewed=review_state(state)
    except (OSError,ValueError,TypeError):reviewed=[];limits.append('Reviewed-alert state could not be read; alerts remain unreviewed.')
    if not present:return result
    try:
        component=read_root(Path('/usr/share/ironclad-sensor/policy.json'),65536)
        if not isinstance(component,dict):raise ValueError('invalid installed component')
        result['installed_policy_version']=component.get('version')
        result['installed_engine_version']=component.get('engine_version')
        result['update_available']=component.get('version')!=policy.VERSION or component.get('engine_sha256')!=policy.ENGINE_SHA or component.get('krsi_sha256')!=policy.KRSI_SHA or component.get('rules_sha256')!=hashlib.sha256(policy.RULES_YAML.encode()).hexdigest()
        if result['update_available']:limits.append('A different sensor engine or policy is installed. Review the bundled sensor update to match this plugin release.')
    except (OSError,ValueError,TypeError):
        result['update_available']=True
        limits.append('Installed sensor version could not be verified. Review the bundled sensor installation.')
    live=service_state()
    result.update(state='stopped' if live in ('inactive','not-found') else 'failed' if live=='failed' else 'starting' if live in ('active','activating','reloading') else 'unavailable',message='Monitoring is stopped. Existing local alerts are retained.' if live in ('inactive','not-found') else 'Sensor state is being verified; no active coverage is assumed.')
    try:
        ownership=read_root(BASE/'owner.json',4096)
        if ownership.get('uid')!=os.getuid():result.update(state='other_owner',owner_match=False,message='Another local account owns this sensor. Administrator review is needed.');return result
        data=read_root(BASE/'feed/snapshot.json')
        if data.get('owner_uid')!=os.getuid():raise ValueError('wrong feed owner')
        events=parse_feed(data)
        for event in events:event['reviewed']=event['id'] in reviewed
        result['alerts']=list(reversed(events))[:64];result['unreviewed']=sum(not event['reviewed'] for event in events)
        if data.get('omitted',0):limits.append('Older detections are outside the bounded local alert window; this is not a complete incident history.')
        if live!='active':return result
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        heartbeat=(time.monotonic_ns()-int(data['heartbeat_ns']))/1e9;age=(time.monotonic_ns()-int(data['metric_ns']))/1e9
        if data.get('boot_id')!=boot or data.get('stopped') is not False or not 0<=heartbeat<=15 or not 0<=age<=20 or data.get('policy_version')!=policy.VERSION:
            result.update(state='degraded',message='The service is running, but fresh sensor coverage has not been verified.');return result
        counts=data.get('metrics')
        if not isinstance(counts,dict) or set(counts)!={'events','kernel_drops','output_drops','async_reader','async_events','async_errors','async_emitted','async_pending'} or any(not isinstance(v,str) or not re.fullmatch(r'[0-9]{1,19}',v) for v in counts.values()) or counts['async_reader'] not in ('0','1'):raise ValueError('invalid sensor metrics')
        result.update(monitoring=True,metrics=counts)
        gaps=int(counts['kernel_drops'])+int(counts['output_drops'])+int(counts['async_errors'])+int(counts['async_pending'])>0 or counts['async_events']!=counts['async_emitted'] or counts['async_reader']!='1' or data.get('parse_errors',0)!=0
        result.update(state='degraded' if gaps else 'monitoring',message='Kernel or asynchronous processing has event gaps. Review monitoring; absence of alerts is not clearance.' if gaps else 'Local monitoring has fresh kernel metrics and a live asynchronous reader with no reported processing backlog.')
    except FileNotFoundError:
        if live=='active':result.update(state='starting',message='Waiting for the sensor’s first verified activity. No coverage is assumed yet.')
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        result.update(state='unavailable',message='The private sensor state could not be safely verified. No active coverage is assumed.')
    return result


def acknowledge(state,identifier):
    if not isinstance(identifier,str) or not ALERT_ID.fullmatch(identifier):raise ValueError('invalid alert identifier')
    data=status(state)
    if identifier not in {row['id'] for row in data['alerts']}:raise ValueError('alert no longer present; refresh first')
    reviewed=[v for v in review_state(state) if v in {row['id'] for row in data['alerts']}]
    reviewed=list(dict.fromkeys([*reviewed,identifier]))[-MAX_EVENTS:]
    fd=private_dir(state);temporary='.sensor-review-'+secrets.token_hex(8)
    try:
        out=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(out,'w') as stream:json.dump(reviewed,stream)
        os.replace(temporary,'sensor-reviewed.json',src_dir_fd=fd,dst_dir_fd=fd)
    finally:
        try:os.unlink(temporary,dir_fd=fd)
        except FileNotFoundError:pass
        os.close(fd)
    return status(state)


def digest(plan):return hashlib.sha256(json.dumps({k:v for k,v in plan.items() if k!='digest'},sort_keys=True,separators=(',',':')).encode()).hexdigest()


def plan(state,action,allow_network=False):
    if action not in ('enable','disable','remove'):raise ValueError('unsupported sensor action')
    current=status(state)
    if action=='enable' and not current['compatible']:raise ValueError(current['message'])
    if not current['owner_match']:raise ValueError(current['message'])
    if action!='enable' and not current['installed']:raise ValueError('sensor component is not installed')
    component=None
    if action=='enable':
        from .sensor_package import build
        component=build(state,allow_network)
    result={'schema':1,'action':action,'created':int(time.time()),'component':component,'version':policy.VERSION,'uid':str(os.getuid()),
            'impact':'Installs the embedded Falco sensor if needed, then starts monitoring at boot and now. Falco observes system-wide kernel activity and builds process state, which can include command arguments internally. Ironclad retains only rule, time, app name and event type; arguments, file paths, file contents and raw Falco logs are not retained or sent to AI. No automatic blocking. Limits: 512 MiB memory and 25% of one CPU; known drops and processing gaps are reported; some internal losses remain unmeasured.' if action=='enable' else 'Stops the Ironclad sensor and disables its next-boot start. Existing alerts remain local.' if action=='disable' else 'Stops and removes only the Ironclad sensor component. Existing local alert history is retained.',
            'recovery':'Stop monitoring in Ironclad to disable the sensor; existing software and unrelated services are unchanged.' if action=='enable' else 'Enable monitoring in Ironclad to start it again.'}
    result['digest']=digest(result);return result


def run_privileged(command,timeout=180):
    from .maintenance import trusted,environment
    # Authentication occurs through the OS agent; no passwords enter Ironclad.
    child=subprocess.Popen([trusted('/usr/bin/pkexec'),trusted(command[0]),*command[1:]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=environment(),cwd='/',start_new_session=True)
    try:return child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # A root package transaction must not be killed from an unprivileged UI.
        return None


def apply(state,review,approval):
    if not isinstance(review,dict) or approval!=review.get('digest') or digest(review)!=approval or review.get('uid')!=str(os.getuid()) or review.get('version')!=policy.VERSION or not isinstance(review.get('created'),int) or not 0<=time.time()-review['created']<=180:raise ValueError('review a fresh exact monitoring change')
    action=review.get('action')
    if action not in ('enable','disable','remove'):raise ValueError('unsupported monitoring change')
    current=status(state)
    if not current['owner_match']:raise ValueError('another local account owns the sensor')
    if action=='enable':
        if not current['compatible']:raise ValueError('kernel compatibility changed')
        from .sensor_package import build
        component=build(state,False)
        if component!=review.get('component'):raise ValueError('prepared sensor changed; review again')
        if run_privileged(['/usr/bin/pacman','-U','--noconfirm','--',component['path']],600)!=0:
            return {'verified':False,'message':'Component installation was cancelled, failed or is still incomplete. Refresh monitoring status before retrying.','status':status(state)}
        code=run_privileged([policy.HELPER,'enable'],120)
    else:
        if not current['installed']:raise ValueError('sensor component changed; refresh first')
        code=run_privileged([policy.HELPER,'disable'],45)
        if code==0 and action=='remove':code=run_privileged(['/usr/bin/pacman','-R','--noconfirm','--','ironclad-sensor'],120)
    fresh=status(state)
    verified=code==0 and (fresh['state']=='monitoring' if action=='enable' else not fresh['installed'] if action=='remove' else fresh['state']=='stopped')
    return {'verified':verified,'message':fresh['message'] if verified else 'The requested change did not verify. Review the current monitoring status; no protection or successful stop is assumed.','status':fresh}
