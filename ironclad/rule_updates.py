"""Explicit opt-in to official Falco host rule maintenance; no engine upgrades."""
from pathlib import Path
import subprocess
import time

HELPER='/usr/lib/ironclad/rule-helper'
SERVICE='''[Unit]
Description=Ironclad signed Falco host rule updates
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/lib/ironclad/rule-helper update
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/ironclad-rules
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETFCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN
MemoryMax=2G
CPUQuota=10%
TasksMax=64
LimitFSIZE=16M
LimitCORE=0
TimeoutStartSec=6min
UMask=0022
Nice=15
StandardOutput=null
StandardError=null
'''
TIMER='''[Unit]
Description=Ironclad Falco rule maintenance schedule
[Timer]
OnCalendar=*-*-* 00/6:00:00
OnActiveSec=5min
RandomizedDelaySec=15min
Persistent=true
[Install]
WantedBy=timers.target
'''
POLKIT='''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig><vendor>Zero Day Security</vendor><action id="com.zerodaysecurity.ironclad.rules"><description>Manage automatic Falco detection updates</description><message>Authenticate to manage signed Falco rule updates and brief monitoring restarts</message><defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin</allow_active></defaults><annotate key="org.freedesktop.policykit.exec.path">/usr/lib/ironclad/rule-helper</annotate></action></policyconfig>
'''


def configure(enabled,allow_network=False):
    from .maintenance import trusted,environment
    from .rule_service import RELEASE_READY
    if enabled and not allow_network:raise ValueError('rule network consent required')
    if enabled and not RELEASE_READY:raise ValueError('Falco rule updates await security and native acceptance review')
    result=subprocess.run([trusted('/usr/bin/pkexec'),trusted(HELPER),'enable' if enabled else 'disable'],
        env=environment(),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
    if result.returncode:raise ValueError('rule maintenance configuration failed')


def status():
    from .sensor import read_root
    from .maintenance import capture,trusted
    from .rule_service import RELEASE_READY
    result={'installed':False,'available':RELEASE_READY,'enabled':False,'state':'unavailable','rules':0,
            'message':'Update the monitoring component to add automatic Falco host rules.'}
    try:
        trusted(HELPER);result['installed']=True
        try:consent=read_root(Path('/var/lib/ironclad-rules/consent.json'))
        except FileNotFoundError:consent={}
        units=capture(['/usr/bin/systemctl','show','ironclad-rule-updates.timer','--property=ActiveState,UnitFileState,ActiveEnterTimestampMonotonic'],timeout=3)
        result['enabled']=consent.get('enabled') is True and 'ActiveState=active' in units and 'UnitFileState=enabled' in units
        try:record=read_root(Path('/var/lib/ironclad-rules/status.json'))
        except FileNotFoundError:record={}
        try:active=read_root(Path('/var/lib/ironclad-rules/active.json'))
        except FileNotFoundError:active=None
        result['rules']=len(active.get('catalog',{})) if isinstance(active,dict) else 0
        result['state']=record.get('state','not_checked')
        checked=record.get('checked_at')
        result['checked_at']=checked
        if result['enabled'] and result['state'] != 'failed':
            properties=dict(line.split('=',1) for line in units.splitlines() if '=' in line)
            try: enabled_age=time.monotonic()-int(properties.get('ActiveEnterTimestampMonotonic','0'))/1000000
            except ValueError: enabled_age=-1
            attempted=record.get('attempted_at')
            if result['state']=='checking' and type(attempted) is int and 0<=time.time()-attempted<600:
                result['state']='checking'
            elif checked is None and result['state']=='not_checked' and 0<=enabled_age<1800:
                result['state']='scheduled'
            elif result['state']=='checking' or type(checked) is not int or not 0<=time.time()-checked<86400:
                result['state']='needs_attention'
        result['message']=('Automatic signed Falco host rules enabled.' if result['enabled'] else 'Automatic Falco rule updates are off.')
        if result['state']=='scheduled':result['message']+=' First check is scheduled within 5–20 minutes while this machine is running.'
        if result['state']=='checking':result['message']+=' Checking signed rules now.'
        if result['state'] in ('failed','needs_attention'):result['message']+=' Latest rule refresh needs attention; check monitoring health.'
        if result['rules']:result['message']+=f" {result['rules']} additional host rules installed."
    except (OSError,ValueError,TypeError):result['message']='Falco rule update health could not be verified.'
    if not RELEASE_READY:
        result['message']='New Falco rule activation is under review. Existing automatic updates can still be turned off.'
    return result
