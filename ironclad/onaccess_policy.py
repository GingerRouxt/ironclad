"""Versioned native ClamAV on-access component; no host state changes on import."""
VERSION='0.1.1'
BASE='/var/lib/ironclad-antimalware'
HELPER='/usr/lib/ironclad/antimalware-helper'
ENGINE_UNIT='ironclad-antimalware-engine.service'
WATCH_UNIT='ironclad-antimalware.service'
REFRESH_UNIT='ironclad-antimalware-refresh.service'
TIMER_UNIT='ironclad-antimalware-refresh.timer'
COVERAGE=('ClamAV scans accessed files in Downloads and its subdirectories, up to 100 MiB per file, within archive/time limits. '
          'This is not a full-system scan. Known credential folders at the Downloads root, root and scanner activity are excluded. '
          'Notify mode alerts only; prevention mode denies detected files, but scanner errors fail open. '
          'No automatic deletion or quarantine. Encrypted, skipped and over-limit files are not certified safe.')
COMMON='''NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX
PrivateNetwork=true
SystemCallArchitectures=native
UMask=0077
Nice=15
IOSchedulingClass=idle
TasksMax=48
LimitCORE=0
StandardOutput=null
StandardError=null
'''
ENGINE='''[Unit]
Description=Ironclad isolated ClamAV scanning daemon
[Service]
Type=simple
User=clamav
Group=clamav
ProtectProc=invisible
ExecStart=/usr/bin/clamd --foreground --config-file=/var/lib/ironclad-antimalware/clamd.conf
RuntimeDirectory=ironclad-antimalware
RuntimeDirectoryMode=0700
ReadWritePaths=/run/ironclad-antimalware
ReadOnlyPaths=/var/lib/ironclad-antimalware/signatures
CapabilityBoundingSet=
MemoryMax=1536M
CPUQuota=25%
Restart=on-failure
RestartSec=15
TimeoutStopSec=10
'''+COMMON
WATCH='''[Unit]
Description=Ironclad ClamAV automatic Downloads protection
Requires=ironclad-antimalware-engine.service
After=ironclad-antimalware-engine.service
[Service]
Type=simple
ExecStart=/usr/lib/ironclad/antimalware-helper run
ReadWritePaths=/var/lib/ironclad-antimalware/feed
MemoryMax=160M
CPUQuota=10%
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER
SystemCallFilter=~@mount @reboot @swap @module @raw-io @cpu-emulation @obsolete @debug
Restart=on-failure
RestartSec=15
TimeoutStopSec=8
'''+COMMON.replace('ProtectHome=true','ProtectHome=tmpfs').replace('RestrictAddressFamilies=AF_UNIX','RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK')+'''[Install]
WantedBy=multi-user.target
'''
REFRESH='''[Unit]
Description=Ironclad automatic ClamAV daemon signature refresh
[Service]
Type=oneshot
User=clamav
Group=clamav
ExecStart=/usr/bin/freshclam --config-file=/var/lib/ironclad-antimalware/freshclam.conf --datadir=/var/lib/ironclad-antimalware/signatures --stdout
ReadWritePaths=/var/lib/ironclad-antimalware/signatures
MemoryMax=768M
CPUQuota=15%
TimeoutStartSec=12min
CapabilityBoundingSet=
'''+COMMON.replace('RestrictAddressFamilies=AF_UNIX','RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6').replace('PrivateNetwork=true','PrivateNetwork=false')
TIMER='''[Unit]
Description=Ironclad on-access signature maintenance
[Timer]
OnCalendar=*-*-* 00/4:00:00
OnActiveSec=5min
RandomizedDelaySec=15min
Persistent=true
[Install]
WantedBy=timers.target
'''
UNITS={ENGINE_UNIT:ENGINE,WATCH_UNIT:WATCH,REFRESH_UNIT:REFRESH,TIMER_UNIT:TIMER}
POLKIT='''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig><vendor>Zero Day Security</vendor><action id="com.zerodaysecurity.ironclad.antimalware.manage"><description>Manage Ironclad automatic malware protection</description><message>Authenticate to change ClamAV Downloads protection</message><defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin</allow_active></defaults><annotate key="org.freedesktop.policykit.exec.path">/usr/lib/ironclad/antimalware-helper</annotate></action></policyconfig>
'''
