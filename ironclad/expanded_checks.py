"""Offline, cached, bounded implementations for the fixed diagnostic catalog."""
import gzip
import io
import json
import os
from pathlib import Path
import re
import stat
from . import check_catalog as catalog
from .collectors import finding, read
from .runner import COMMANDS, run

PROPERTIES=tuple(row.split('|')[0] for row in catalog.SERVICE_PROPERTIES.strip().splitlines())
UNITS=('sshd.service','cups.service','avahi-daemon.service','ironclad-antimalware-engine.service')
for unit in UNITS:
 COMMANDS['catalog_'+unit]=('systemctl','show',unit,'--no-pager','--property='+','.join(('LoadState','ActiveState',*PROPERTIES)))

class Context:
 def __init__(self,state=None):
  self.state=Path(state) if state is not None else Path(os.environ.get('XDG_STATE_HOME',Path.home()/'.local/state'))/'ironclad'
  self.cache={}
 def cached(self,key,loader):
  if key not in self.cache:
   try:self.cache[key]=loader()
   except (OSError,ValueError,KeyError,TypeError,EOFError):self.cache[key]=None
  return self.cache[key]
 def config(self):
  def load():
   fd=os.open('/proc/config.gz',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   with os.fdopen(fd,'rb') as stream:
    meta=os.fstat(stream.fileno())
    if meta.st_uid!=0 or meta.st_mode & 0o022:raise ValueError('untrusted kernel configuration')
    compressed=stream.read(262145)
    if len(compressed)>262144:raise ValueError('compressed kernel configuration bound')
   with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:body=stream.read(2097153)
   if len(body)>2097152:raise ValueError('kernel configuration bound')
   values={}
   for line in body.decode('ascii').splitlines():
    yes=re.fullmatch(r'CONFIG_([A-Z0-9_]+)=([ymn]|[0-9]+)',line)
    no=re.fullmatch(r'# CONFIG_([A-Z0-9_]+) is not set',line)
    if yes:values[yes[1]]=yes[2]
    elif no:values[no[1]]='n'
   if not values:raise ValueError('invalid kernel configuration')
   return values
  return self.cached('config',load)
 def service(self,unit):
  def load():
   result=run('catalog_'+unit,timeout=.6)
   if result.state!='available':raise ValueError('service query unavailable')
   values={}
   for line in result.output.splitlines():
    if '=' not in line:raise ValueError('invalid service property')
    key,value=line.split('=',1)
    if key in values:raise ValueError('duplicate service property')
    values[key]=value
   if values.get('LoadState') not in ('loaded','not-found','masked','error','bad-setting','stub','merged'):raise ValueError('invalid load state')
   return values
  return self.cached('service:'+unit,load)
 def mounts(self):
  def load():
   values=[]
   for line in read('/proc/self/mountinfo',262144).splitlines():
    parts=line.split();separator=parts.index('-')
    # Only a mount's path and flag set remain in memory. No device/source data
    # or personal mount paths enter evidence or reports.
    path=re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),parts[4])
    values.append((path,set(parts[5].split(','))|set(parts[separator+3].split(','))))
   return values
  return self.cached('mounts',load)
 def listeners(self):
  def load():
   result=run('sockets')
   if result.state!='available':raise ValueError('socket query unavailable')
   values=[]
   for line in result.output.splitlines():
    p=line.split()
    if len(p)<6 or p[0] not in ('tcp','udp'):raise ValueError('invalid socket row')
    address,port=p[4].rsplit(':',1)
    if not port.isdecimal() or not 0<int(port)<=65535:raise ValueError('invalid socket port')
    loopback=address.strip('[]')=='::1' or address.startswith('127.')
    values.append((p[0],int(port),loopback))
   return values
  return self.cached('listeners',load)
 def protection(self):
  def load():
   # Existing health collectors have independent service-manager timeouts.
   # Bound the whole group so they cannot consume the diagnostic scan budget.
   from .maintenance import capture
   companion=Path(__file__).resolve().parents[1]/'companion.py'
   value=json.loads(capture(['/usr/bin/python3','-I','-B',str(companion),'--state',str(self.state),'protection-status','--json'],timeout=2))
   return {'falco':{'monitoring':value['continuous_monitoring'],'state':value['sensor']['state']},'automatic':value['automatic_malware'],'manual':value['scanner'],'updates':value['updates']}
  return self.cached('protection',load)

def predicate(policy,value):
 """Strict typed predicates. None means observation, not a policy pass."""
 if policy=='observe':return None
 if ':' in policy:
  operation,limit=policy.split(':');limit=int(limit)
  if not isinstance(value,int):raise ValueError('integer required')
  if operation=='ge':return value>=limit
  if operation=='le':return value<=limit
  if operation=='eq':return value==limit
  if operation=='mask':return value!=0 and value & ~limit==0
  raise ValueError('unknown numeric predicate')
 if not isinstance(value,str):raise ValueError('string required')
 if policy=='bool':
  if value not in ('yes','no','true','false','disconnected'):raise ValueError('invalid boolean property')
  return value in ('yes','true','disconnected')
 if policy=='protectsystem':return value in ('full','strict') if value in ('no','yes','full','strict') else invalid()
 if policy=='protecthome':return value in ('yes','read-only','tmpfs') if value in ('no','yes','read-only','tmpfs') else invalid()
 if policy=='protectproc':return value in ('invisible','ptraceable','noaccess') if value in ('default','invisible','ptraceable','noaccess') else invalid()
 if policy=='procsubset':return value=='pid' if value in ('all','pid') else invalid()
 if policy=='umask':
  if not re.fullmatch('[0-7]{4}',value):return invalid()
  return int(value,8)&0o077==0o077
 if policy=='user':return bool(value) and value not in ('root','0')
 if policy=='ambient':return not bool(value.strip())
 if policy=='keyring':return value=='private' if value in ('inherit','private','shared') else invalid()
 # These lists are observations: blacklist/allowlist syntax and runtime
 # application need interpretation, so mere presence is not a safety pass.
 if policy in ('namespaces','caps','families','filter','arch','filesystems'):return None
 return invalid()

def invalid():raise ValueError('unsupported or malformed policy value')

def outcome(rule,status,value,detail=''):
 summary=rule.label+': '+({'pass':'policy satisfied','attention':'review policy tradeoff','observed':'observed, not a safety verdict','unavailable':'could not verify','not_applicable':'not applicable to this host'}[status])
 c=finding(rule.id,summary,value,rule.target,status,'low' if status=='attention' else 'info','low' if status=='unavailable' else 'high',rule.reason)
 c.documentation_url=rule.doc;c.verification='Rerun this profile and inspect the exact control. '+(detail or 'A pass applies only to this predicate, not to the whole machine.')
 c.remediation_steps=['Inspect the evidence for '+rule.label+'.',rule.reason,'Review compatibility and upstream documentation before any manual change. Ironclad applies nothing during scans.']
 return c

def evaluate(rule,context):
 kind=rule.kind
 if kind=='sysctl':
  raw=read('/proc/sys/'+rule.target,256)
  if rule.policy=='observe':
   if not re.fullmatch(r'[0-9]+(?:\s+[0-9]+)*',raw):raise ValueError('invalid numeric observation')
   return outcome(rule,'observed','value='+raw)
  if not re.fullmatch(r'[0-9]+',raw):raise ValueError('invalid numeric setting')
  return outcome(rule,'pass' if predicate(rule.policy,int(raw)) else 'attention','value='+raw)
 if kind=='cpu_mitigation':
  value=read('/sys/devices/system/cpu/vulnerabilities/'+rule.target,1024)
  if value=='Not affected':status='pass'
  elif value.startswith('Vulnerable') or 'vulnerable' in value.lower():status='attention'
  elif value.startswith('Mitigation:'):status='pass'
  else:status='unavailable'
  return outcome(rule,status,value)
 if kind=='metadata':
  try:meta=os.stat(rule.target)
  except FileNotFoundError:return outcome(rule,'not_applicable','optional path absent')
  mode=stat.S_IMODE(meta.st_mode)
  ok=meta.st_uid==0 and not mode & 0o022
  if rule.target in ('/etc/shadow','/etc/gshadow','/root'):ok=ok and not mode & 0o007
  return outcome(rule,'pass' if ok else 'attention',f'root_owned={meta.st_uid==0}; mode={mode:04o}; contents_not_read=true')
 if kind=='kconfig':
  values=context.config()
  if values is None:return outcome(rule,'unavailable','running kernel does not expose a readable bounded /proc/config.gz')
  if rule.target not in values:return outcome(rule,'not_applicable','symbol not exposed by this kernel/architecture; not treated as disabled')
  status=('pass' if values[rule.target]=='y' else 'attention') if rule.policy=='enabled' else 'observed'
  return outcome(rule,status,'build_value='+values[rule.target]+'; runtime_enforcement=not_established')
 if kind=='mount':
  target,flag=rule.target.rsplit('/',1)
  if not Path(target).exists():return outcome(rule,'not_applicable','optional mount path absent')
  mounts=context.mounts()
  if mounts is None:return outcome(rule,'unavailable','mount metadata unavailable')
  applicable=[(p,flags) for p,flags in mounts if target==p or target.startswith(p.rstrip('/')+'/')]
  if not applicable:return outcome(rule,'unavailable','covering mount not found')
  _,flags=max(enumerate(applicable),key=lambda row:(len(row[1][0]),row[0]))[1]
  return outcome(rule,'pass' if flag in flags else 'attention',f'{flag}={flag in flags}; effective covering mount; namespace-local observation')
 if kind=='service':
  unit,prop=rule.target.split('/')
  values=context.service(unit)
  if values is None:return outcome(rule,'unavailable','service manager query failed or timed out')
  if values['LoadState']=='not-found':return outcome(rule,'not_applicable','service not installed')
  if values['LoadState']!='loaded':return outcome(rule,'unavailable','service is not in a loaded state')
  if values.get('ActiveState')!='active':return outcome(rule,'not_applicable','service inactive; no active isolation verdict')
  if prop not in values:return outcome(rule,'unavailable','property not returned by this systemd version')
  value=values[prop];result=predicate(rule.policy,value)
  # Raw lists may contain private paths, user IDs or service-specific arguments.
  # Export only booleans, enums, masks and whether a list was configured.
  if prop in ('DynamicUser','RemoveIPC','PrivateNetwork') and value not in ('yes','no','true','false'):raise ValueError('invalid optional boolean')
  visible=('nonroot' if value not in ('','root','0') else 'root/default') if prop=='User' else value if prop in ('DynamicUser','RemoveIPC','PrivateNetwork') else value if rule.policy in ('bool','protectsystem','protecthome','protectproc','procsubset','umask','keyring') else 'nonroot' if rule.policy=='user' and result else 'root/default' if rule.policy=='user' else 'configured' if value else 'empty/default'
  return outcome(rule,'observed' if result is None else 'pass' if result else 'attention','configured='+visible+'; live enforcement not independently exercised')
 if kind=='listener':
  rows=context.listeners()
  if rows is None:return outcome(rule,'unavailable','listener query failed or timed out')
  proto,port=rule.target.split('/');exposed=sum(p==proto and n==int(port) and not local for p,n,local in rows)
  return outcome(rule,'attention' if exposed else 'pass',f'nonloopback_listeners={exposed}; addresses/processes omitted; external reachability untested')
 if kind=='protection':
  data=context.protection()
  if data is None:return outcome(rule,'unavailable','protection state unavailable')
  value=data['manual' if rule.target=='signatures' else rule.target]
  if rule.target=='falco':ok=value['monitoring'];detail='state='+value['state']
  elif rule.target=='automatic':ok=value['active'];detail='state='+value['state']+'; mode='+str(value['mode'])
  elif rule.target=='manual':ok=value['ready'];detail='ready='+str(ok)
  elif rule.target=='signatures':
   age=value['signatures_age_hours'];ok=age is not None and 0<=age<=168;detail='signature_age_hours='+str(age)
  else:
   ok=value.get('automatic') is True and not value.get('issues');detail='automatic='+str(value.get('automatic'))+'; maintenance_issues='+str(len(value.get('issues',[])))
  return outcome(rule,'pass' if ok else 'attention',detail)
 raise ValueError('unsupported check kind')
