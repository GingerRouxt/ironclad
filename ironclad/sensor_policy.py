"""Versioned local Falco policy. No argument/content fields or generated actions."""
VERSION='0.2.33'
FALCO_VERSION='0.45.1'
ARCHIVE_URL='https://download.falco.org/packages/bin/x86_64/falco-0.45.1-x86_64.tar.gz'
ARCHIVE_SHA='a4a384055327207202c36e3f89a3e954d131db71d55088737c5174ff7dab7c7b'
ENGINE_SHA='cd3ab1310ea27ba8ab33546fc50c3af707aeaee21908957a973b3d5376e804de'
KRSI_VERSION='0.2.0-ironclad.2'
KRSI_ARCHIVE_SHA='d64d617b24a56d93bbfcf680582e49fbecee869741bb3699350cedfb812ddf5d'
KRSI_SHA='9935296a6dd5b0395833055a84dcfa527d630c241532a0e90afc6ca055cb5bd1'
KRSI='/usr/lib/ironclad/libkrsi.so'
ENGINE='/usr/lib/ironclad/falco'
HELPER='/usr/lib/ironclad/sensor-helper'
UNIT='ironclad-sensor.service'
BASE='/var/lib/ironclad'
RULES={
 'ZDS Runtime preload changed':{'id':'runtime.preload','severity':'high','title':'System-wide library loading changed','meaning':'A program wrote the system-wide library preload setting. This can affect programs across the machine; a legitimate administrator may also change it.','action':'Review the recent administrative change and its publisher before running more downloaded software. Ask an administrator to inspect the preload configuration; do not delete it blindly.','verify':'Confirm the setting matches the intended configuration and that unexplained changes do not recur.'},
 'ZDS Startup policy changed':{'id':'runtime.startup','severity':'medium','title':'System startup policy changed','meaning':'A program wrote a system service or scheduled-startup configuration. Updates and approved application installations can cause this.','action':'Compare the time and application with your recent installations or administration. Review unfamiliar startup entries locally and investigate the owning package before disabling anything.','verify':'Confirm that only intended entries remain enabled and essential services still start.'},
 'ZDS Authentication policy changed':{'id':'runtime.authentication','severity':'high','title':'Authentication policy changed','meaning':'A program wrote an SSH, PAM or administrator-access policy file. This can affect who can sign in or elevate privileges.','action':'Check whether the change came from an approved update or administrator. Keep a working session open and have an administrator inspect unexpected changes before adjusting access.','verify':'Test intended sign-in and administrator access, and confirm no unauthorized rule remains.'},
 'ZDS Kernel module loaded':{'id':'runtime.kernel_module','severity':'low','title':'Kernel code was loaded','meaning':'A program loaded a kernel module. Normal device drivers and system administration can cause this; the event alone does not identify malware.','action':'Check whether a device, driver update or approved administration explains the event. Investigate the responsible package if it is unexpected.','verify':'Confirm the module belongs to an intended trusted driver or approved component.'},
 'ZDS Memory-backed execution':{'id':'runtime.memory_execution','severity':'medium','title':'A program ran from a memory-backed file','meaning':'A program executed from an anonymous memory-backed file. Some legitimate applications do this, and attackers can use the same technique to avoid a normal executable file.','action':'Review whether the application and time match your activity. If unfamiliar, avoid entering secrets in that application and investigate its installation source before taking action.','verify':'Confirm the behavior is expected for that application; unexplained repeated events need further investigation.'},
}
RULES.update({
 'ZDS User startup changed':{'id':'runtime.user_startup','severity':'medium','title':'User startup entry changed','meaning':'A program opened a user systemd unit or desktop autostart entry for writing. These entries can launch programs at sign-in; normal app installs and your own configuration also do this.','action':'Compare the application and time with your recent installs or startup edits. Review unfamiliar startup entries locally before disabling them; do not assume that an alert proves malicious persistence.','verify':'Confirm that intended apps still start and unfamiliar startup entries have been reviewed.'},
 'ZDS Audit policy changed':{'id':'runtime.audit_policy','severity':'medium','title':'Audit policy changed','meaning':'A program opened Linux audit configuration for writing. An administrator may be changing logging policy; unexpected changes can reduce investigation visibility.','action':'Check whether an approved administrator or package update explains the change. Review the intended audit configuration locally without clearing logs or disabling the audit service.','verify':'Confirm the intended audit policy remains active and expected events are still recorded.'},
 'ZDS Account database changed':{'id':'runtime.accounts','severity':'medium','title':'Local account database changed','meaning':'A program opened local account or group databases for writing. Password changes, account administration and package installation can be legitimate causes; unexpected changes merit review.','action':'Confirm whether you changed a password, added an account or installed a package at this time. Ask an administrator to review unexpected account changes without sharing password hashes or database contents.','verify':'Confirm intended users and groups and working sign-in; do not delete account data or lock out the current session.'},
})
RULES_YAML='''- macro: zds_policy_write
  condition: evt.type in (open, openat, openat2, creat) and evt.is_open_write=true and evt.rawres>=0
- macro: zds_async_policy_write
  condition: evt.type=krsi_open and krsi.write_open=1
- rule: ZDS Runtime preload changed
  desc: A write-open of the system dynamic-library preload policy.
  condition: (zds_policy_write and fd.name=/etc/ld.so.preload) or (zds_async_policy_write and krsi.name=/etc/ld.so.preload)
  output: "Ironclad preload policy event (app=%proc.name event=%evt.type)"
  priority: WARNING
  tags: [ironclad]
- rule: ZDS Startup policy changed
  desc: A write-open of system service or cron configuration.
  condition: (zds_policy_write and (fd.name startswith /etc/systemd/system/ or fd.name startswith /etc/cron.d/ or fd.name=/etc/crontab)) or (zds_async_policy_write and (krsi.name startswith /etc/systemd/system/ or krsi.name startswith /etc/cron.d/ or krsi.name=/etc/crontab))
  output: "Ironclad startup policy event (app=%proc.name event=%evt.type)"
  priority: NOTICE
  tags: [ironclad]
- rule: ZDS Authentication policy changed
  desc: A write-open of administrator, SSH or PAM configuration.
  condition: (zds_policy_write and (fd.name=/etc/sudoers or fd.name startswith /etc/sudoers.d/ or fd.name=/etc/ssh/sshd_config or fd.name startswith /etc/ssh/sshd_config.d/ or fd.name startswith /etc/pam.d/)) or (zds_async_policy_write and (krsi.name=/etc/sudoers or krsi.name startswith /etc/sudoers.d/ or krsi.name=/etc/ssh/sshd_config or krsi.name startswith /etc/ssh/sshd_config.d/ or krsi.name startswith /etc/pam.d/))
  output: "Ironclad authentication policy event (app=%proc.name event=%evt.type)"
  priority: WARNING
  tags: [ironclad]
- rule: ZDS Kernel module loaded
  desc: A successful kernel module load; legitimate drivers also trigger this.
  condition: evt.type in (init_module, finit_module) and evt.rawres=0
  output: "Ironclad kernel module event (app=%proc.name event=%evt.type)"
  priority: NOTICE
  tags: [ironclad]
- rule: ZDS Memory-backed execution
  desc: Successful execution from a memfd-backed image; not proof of compromise.
  condition: evt.type in (execve, execveat) and evt.rawres>=0 and proc.is_exe_from_memfd=true
  output: "Ironclad memory execution event (app=%proc.name event=%evt.type)"
  priority: WARNING
  tags: [ironclad]
- rule: ZDS User startup changed
  desc: A write-open of user systemd units or desktop autostart entries.
  condition: (zds_policy_write and (fd.name glob /home/*/.config/systemd/user/* or fd.name glob /home/*/.config/autostart/*.desktop)) or (zds_async_policy_write and (krsi.name glob /home/*/.config/systemd/user/* or krsi.name glob /home/*/.config/autostart/*.desktop))
  output: "Ironclad user startup event (app=%proc.name event=%evt.type)"
  priority: NOTICE
  tags: [ironclad]
- rule: ZDS Audit policy changed
  desc: A write-open of Linux audit configuration; approved administration can trigger this.
  condition: (zds_policy_write and (fd.name=/etc/audit/auditd.conf or fd.name=/etc/audit/audit.rules or fd.name startswith /etc/audit/rules.d/)) or (zds_async_policy_write and (krsi.name=/etc/audit/auditd.conf or krsi.name=/etc/audit/audit.rules or krsi.name startswith /etc/audit/rules.d/))
  output: "Ironclad audit policy event (app=%proc.name event=%evt.type)"
  priority: NOTICE
  tags: [ironclad]
- rule: ZDS Account database changed
  desc: A write-open of local account databases; never includes their contents.
  condition: (zds_policy_write and fd.name in (/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow)) or (zds_async_policy_write and krsi.name in (/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow))
  output: "Ironclad account policy event (app=%proc.name event=%evt.type)"
  priority: NOTICE
  tags: [ironclad]
'''
CONFIG='''engine:
  kind: modern_ebpf
rules_files: [/usr/share/ironclad-sensor/rules.yaml]
load_plugins: [krsi]
plugins:
  - name: krsi
    library_path: /usr/lib/ironclad/libkrsi.so
    init_config:
      io_uring: true
      syscalls: false
json_output: true
json_include_output_property: false
json_include_tags_property: false
stdout_output:
  enabled: true
syslog_output:
  enabled: false
file_output:
  enabled: false
http_output:
  enabled: false
program_output:
  enabled: false
  program: ""
webserver:
  enabled: false
log_stderr: true
log_syslog: false
log_level: warning
buffered_outputs: false
watch_config_files: false
metrics:
  enabled: true
  interval: 5s
  output_rule: true
  rules_counters_enabled: false
  resource_utilization_enabled: false
  state_counters_enabled: false
  kernel_event_counters_enabled: true
  kernel_event_counters_per_cpu_enabled: false
  libbpf_stats_enabled: false
  plugins_metrics_enabled: true
  include_empty_values: true
  jemalloc_stats_enabled: false
'''
SERVICE='''[Unit]
Description=Ironclad local behavior sensor (Falco)
After=basic.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=simple
ExecStart=/usr/lib/ironclad/sensor-helper run
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillMode=control-group
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
IPAddressDeny=any
ReadWritePaths=/var/lib/ironclad
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
MemoryMax=512M
CPUQuota=25%
TasksMax=64
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''
POLKIT='''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
 <vendor>Zero Day Security</vendor>
 <action id="com.zerodaysecurity.ironclad.sensor">
  <description>Manage Ironclad local monitoring</description>
  <message>Authentication is required to manage Ironclad's background sensor</message>
  <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin_keep</allow_active></defaults>
  <annotate key="org.freedesktop.policykit.exec.path">/usr/lib/ironclad/sensor-helper</annotate>
 </action>
</policyconfig>
'''
