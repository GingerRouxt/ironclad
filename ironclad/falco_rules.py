"""Reduce verified upstream rules to host-only, privacy-preserving detections.

Called in an isolated worker, never used to execute upstream instructions.
PyYAML is an OS dependency of that worker, not of the desktop companion.
"""
import hashlib
import json
import re
from pathlib import Path
import subprocess

FALCOCTL_SHA='8ac0c07b90e4a437d4f44b8a360c3f6a91ae560706aea8b41627caf7019e5918'
FALCOCTL_ARCHIVE_SHA='46b2e864cfe54cb9202b41a67f295606ec6899d0262d42019f4e08f1991048a6'
FALCOCTL_VERSION='0.14.2-ironclad.1'
INDEX='''- name: falco-rules
  type: rulesfile
  registry: ghcr.io
  repository: falcosecurity/rules/falco-rules
  signature:
    cosign:
      certificate-oidc-issuer: https://token.actions.githubusercontent.com
      certificate-identity-regexp: '^https://github[.]com/falcosecurity/rules/[.]github/workflows/[^/]+@refs/(heads/main|tags/[^/]+)$'
      ignore-tlog: false
'''

# Explicitly select our local cache; falcoctl otherwise defaults to a remote index.
CONFIG = 'indexes:\n  - name: ironclad\n    url: https://invalid.invalid/ironclad-local-index\n    backend: https\n'

MAX_BYTES = 1048576
PRIORITIES = {'EMERGENCY':'critical','ALERT':'critical','CRITICAL':'critical',
              'ERROR':'high','WARNING':'medium','NOTICE':'low','INFORMATIONAL':'info','INFO':'info','DEBUG':'info'}


def restrict_worker_sockets():
    """Keep shared-network abstract sockets from conveying the supervisor's UID.

    The filter is inherited by the downloader/compiler. Only IPv4/IPv6 socket
    creation is allowed; io_uring cannot bypass the socket syscall filter.
    """
    import ctypes
    import errno
    import platform
    class Comparison(ctypes.Structure):
        _fields_=[('arg',ctypes.c_uint),('op',ctypes.c_uint),('a',ctypes.c_uint64),('b',ctypes.c_uint64)]
    machine=platform.machine()
    if machine not in ('x86_64','aarch64'):raise ValueError('unsupported worker filter architecture')
    paths=['/usr/lib/libseccomp.so.2','/usr/lib/'+machine+'-linux-gnu/libseccomp.so.2']
    path=next((p for p in paths if Path(p).is_file()),None)
    if path is None:raise ValueError('system libseccomp required')
    lib=ctypes.CDLL(path)
    lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_release.argtypes=[ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Comparison)]
    lib.seccomp_load.argtypes=[ctypes.c_void_p]
    context=lib.seccomp_init(0x7fff0000)
    if not context:raise ValueError('worker filter initialization failed')
    try:
        socket_call=lib.seccomp_syscall_resolve_name(b'socket')
        if socket_call<0:raise ValueError('worker socket filter unavailable')
        # Deny <=1, 3..9 and >=11: exactly AF_INET=2 / AF_INET6=10 remain.
        for op,value in [(3,1),*[(4,n) for n in range(3,10)],(5,11)]:
            comparison=Comparison(0,op,value,0)
            if lib.seccomp_rule_add_array(context,0x00050000|errno.EPERM,socket_call,1,ctypes.byref(comparison))<0:raise ValueError('worker socket filter failed')
        for name in (b'socketpair',b'io_uring_setup',b'io_uring_enter',b'io_uring_register'):
            syscall=lib.seccomp_syscall_resolve_name(name)
            if syscall<0 or lib.seccomp_rule_add_array(context,0x00050000|errno.EPERM,syscall,0,None)<0:raise ValueError('worker bypass filter failed')
        if ctypes.CDLL(None).prctl(38,1,0,0,0)!=0 or lib.seccomp_load(context)<0:raise ValueError('worker filter installation failed')
    finally:lib.seccomp_release(context)


def catalog_entry(name, priority):
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ()_.,:/+\-]{0,159}',name):
        raise ValueError('unsupported upstream rule name')
    if priority not in PRIORITIES:raise ValueError('unsupported rule priority')
    return {'id':'upstream.'+hashlib.sha256(name.encode()).hexdigest()[:24],
            'severity':PRIORITIES[priority],'title':name,
            'meaning':'An official Falco host rule matched observed behavior. Legitimate activity can also match; this is not proof of malware.',
            'action':'Compare the application and time with your activity. Investigate unexplained behavior locally before changing or removing anything.',
            'verify':'Confirm the activity is expected and check that monitoring remains healthy.'}


def prepare(body):
    import yaml
    if not isinstance(body,bytes) or not 0<len(body)<=MAX_BYTES:raise ValueError('rule download size limit')
    # Reject aliases before constructing objects: bounded YAML, no object tags.
    if any(isinstance(token,(yaml.tokens.AliasToken,yaml.tokens.AnchorToken)) for token in yaml.scan(body)):
        raise ValueError('rule aliases are not supported')
    rows=yaml.safe_load(body)
    if not isinstance(rows,list) or not 1<=len(rows)<=2048:raise ValueError('invalid rules document')
    symbols={};rules=[];engine=[]
    for row in rows:
        if not isinstance(row,dict):raise ValueError('invalid rule entry')
        kinds=set(row)&{'macro','list','rule','required_engine_version','required_plugin_versions'}
        if len(kinds)!=1:raise ValueError('unknown rules directive')
        kind=next(iter(kinds))
        if kind=='required_engine_version':engine.append(row);continue
        if kind=='required_plugin_versions':continue
        if kind=='rule':
            if set(row)-{'rule','desc','condition','output','priority','tags','enabled','warn_evttypes','skip-if-unknown-filter','exceptions','source'}:
                raise ValueError('unsupported rule directive')
            if row.get('source','syscall')!='syscall':continue
            rules.append(row);continue
        name=row[kind]
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',name) or name in symbols:
            raise ValueError('duplicate or invalid rule symbol')
        if set(row)-({kind,'condition'} if kind=='macro' else {kind,'items'}):raise ValueError('unsupported symbol directive')
        symbols[name]=row
    if len(engine)!=1:raise ValueError('missing engine requirement')
    # Exclude rules and transitive macros/lists requiring container/plugin fields.
    # Falco's compiler is the final authority on supported host fields.
    def text(row):return json.dumps({k:v for k,v in row.items() if k in ('condition','items','exceptions')},sort_keys=True)
    def tokens(row):return set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b',text(row)))
    def foreign(row):return bool(re.search(r'\b(?:container|k8s|ka|jevt|aws|cloudtrail|plugin)\.',text(row)))
    excluded={name for name,row in symbols.items() if foreign(row)}
    while True:
        more={name for name,row in symbols.items() if tokens(row)&excluded}
        if more<=excluded:break
        excluded|=more
    selected=[];catalog={};skipped=[]
    for row in rules:
        name=row['rule']
        if row.get('enabled',True) is not True or foreign(row) or tokens(row)&excluded:
            skipped.append(name);continue
        entry=catalog_entry(name,row.get('priority'))
        if name in catalog:raise ValueError('duplicate rule')
        if not isinstance(row.get('condition'),str):raise ValueError('missing rule condition')
        catalog[name]=entry
        clean={k:v for k,v in row.items() if k in ('rule','condition','priority','exceptions','warn_evttypes')}
        clean.update(desc='Verified upstream host detection.',output='Ironclad upstream host event (app=%proc.name event=%evt.type)',source='syscall')
        selected.append(clean)
    if not 1<=len(catalog)<=128:raise ValueError('unsupported host rule count')
    needed=set().union(*(tokens(row)&set(symbols) for row in selected))
    while True:
        more=set().union(*(tokens(symbols[name])&set(symbols) for name in needed))
        if more<=needed:break
        needed|=more
    result=engine+[row for name,row in symbols.items() if name in needed]+selected
    return yaml.safe_dump(result,sort_keys=False).encode(),catalog,skipped


def worker():
    """Fixed inputs, disposable filesystem and no host home; run by rule-service."""
    restrict_worker_sockets()
    work=Path('/work')
    cache=work/'home/.config/falcoctl';(cache/'indexes').mkdir(parents=True)
    (cache/'indexes.yaml').write_text('configs:\n  - name: ironclad\n    url: https://falcosecurity.github.io/falcoctl/index.yaml\n')
    (cache/'indexes/ironclad.yaml').write_text(INDEX)
    (work/'config.yaml').write_text(CONFIG)
    for name in ('download','state','unused'):(work/name).mkdir()
    if hashlib.sha256(Path('/usr/lib/ironclad/falcoctl').read_bytes()).hexdigest()!=FALCOCTL_SHA:
        raise ValueError('unexpected rule downloader')
    subprocess.run(['/usr/lib/ironclad/falcoctl','--config','/work/config.yaml','artifact','install','falco-rules:5',
        '--allowed-types','rulesfile','--resolve-deps=false','--rulesfiles-dir','/work/download',
        '--state-dir','/work/state','--plugins-dir','/work/unused','--assets-dir','/work/unused'],check=True,timeout=180)
    source=work/'download/falco_rules.yaml'
    if source.is_symlink() or source.stat().st_size>MAX_BYTES:raise ValueError('unsafe downloaded rules')
    original=source.read_bytes();rules,catalog,skipped=prepare(original)
    (work/'host-rules.yaml').write_bytes(rules)
    subprocess.run(['/usr/lib/ironclad/falco','-c','/usr/share/ironclad-sensor/falco.yaml',
        '-r','/usr/share/ironclad-sensor/rules.yaml','-r','/work/host-rules.yaml','--dry-run'],check=True,timeout=30)
    result={'schema':1,'rules_sha256':hashlib.sha256(rules).hexdigest(),
            'source_sha256':hashlib.sha256(original).hexdigest(),'catalog':catalog,
            'excluded_count':len(skipped),'channel':'falco-rules:5'}
    (work/'result.json').write_text(json.dumps(result,sort_keys=True))


if __name__=='__main__':worker()
