# Detection coverage — policy 0.2.24

Eight custom Falco categories are shipped. This is a focused host policy, not the
complete upstream Falco ruleset or a measured malware detection rate.

| Category | Observed signal | Common legitimate cause |
|---|---|---|
| Library preload | Successful write-open of /etc/ld.so.preload | Administrator or runtime configuration |
| System startup | Successful write-open in system systemd/cron policy | Package install or service setup |
| Authentication | Successful write-open in sudo, SSH-server or PAM policy | Administrator configuration |
| Kernel modules | Successful kernel module load | Driver or device setup |
| Memory execution | Successful execution from memfd | Some legitimate runtimes/installers |
| User startup | Successful write-open of /home/*/.config/systemd/user/* or autostart/*.desktop | App install or user startup edit |
| Audit policy | Successful write-open of auditd.conf, audit.rules or rules.d | Audit administration or package update |
| Accounts | Successful write-open of passwd/shadow/group/gshadow | Password, account, group or package administration |

An open-for-write is evidence of intent to write, not proof of changed bytes.
The new categories use NOTICE severity at the engine and medium review priority
in Ironclad. They do not establish malicious activity and do not block anything.
Reads and failed opens do not trigger the write rules. No password database
contents, paths or command arguments are retained in Ironclad's alert feed.

## Tests and limits

The behavior matrix interprets the shipped condition expressions and checks
positive cases, read-only/failed access, adjacent directory names and normal
build/download/cache/settings writes. This is a predicate-level test, not a
kernel replay. Separately, tools/verify_detection_policy.py compiles every shipped syscall rule
using the exact hash-pinned Falco binary with --dry-run; no events are processed.
Native acceptance covers a harmless memory-execution alert and an inert user
autostart fixture (Hidden=true, no Exec, removed after its alert was reviewed).
The account/audit categories are not tested by changing live host policy. No
category is claimed to have independently measured real-attack recall.

Coverage excludes persistence outside these specific paths, custom XDG home
locations, /root startup paths, rename/unlink-only changes and direct raw-device
writes. Atomic replacement may be missed when only a different temporary path
is opened. Credential theft, browser attacks, many script/network attacks and
kernel-level evasion are not comprehensively detected. A compromised privileged
host can interfere with the sensor. Event drops/stale health are shown explicitly.

Expected administration can generate review alerts. Do not broadly allowlist
package managers or interpreters: attackers can use the same executables. Review
the time/application against intended activity. Expand conditions only with
positive, negative and legitimate-workload cases and resource checks. Rules ship
as a versioned component; no AI-generated rule is silently installed.

Official rule semantics and performance guidance:
https://falco.org/docs/concepts/rules/basic-elements/
https://falco.org/docs/concepts/rules/style-guide/

## Asynchronous open coverage in 0.2.33

The bundled component combines official dynamic Falco 0.45.1 with a pinned local
KRSI 0.2.0-ironclad.2 candidate fork. It rebuilds against the SDK's real event schema 4.5.0;
no compatibility check is bypassed. The upstream official 0.2.0 binary failed its
schema check and remains a rejected artifact, not the deployed integration.

Real OPENAT, OPENAT2 and OPENAT_DIRECT write-open probes trigger the existing user
startup rule. Read-only opens and writes outside watched locations remain negative.
The same six file-policy categories accept the scoped async open event; the two
module/execution categories remain syscall based. Kernel hooks attach at both
io_openat and io_openat2. Shared kernel-CPU-indexed buffers are sized from possible
CPU IDs, rather than the service quota's available CPU count. ELF aliases require
a small pinned Aya relocation correction; upstream BPF instructions are unchanged.

The component reports reader liveness, input/emitted counts, pending events and processing/queue errors. Opens still reach rules when short-lived process metadata is unavailable; the app is then unidentified rather than invented. Kernel event timestamps are preserved.
Missing/stale metrics, a stopped reader or reported errors cannot show healthy
monitoring. Native acceptance under the installed service's resource/capability
restrictions is required before installation and recorded separately in local
release evidence. Rule validation is unprivileged and does not attach BPF hooks.

This covers selected successful write-open intents, not all asynchronous I/O or
all file mutations. Pre-opened descriptors, rename/unlink, network async operations,
unknown threats and loss in the upstream BPF ring buffer are not comprehensively
covered. Fresh metrics are operational evidence, not a malware-free verdict.
No kernel io_uring control, boot LSM setting or TPM change is needed.

Build recipe and source pins: tools/build_krsi_component.py, tools/krsi-ironclad.patch,
tools/aya-obj-aliases.patch and tools/krsi-Cargo.lock. Bundle build-info.json records
source, binary, patch and license provenance; root startup verifies library bytes.

[KRSI upstream](https://github.com/falcosecurity/plugins/tree/plugins/krsi/v0.2.0/plugins/krsi),
[SDK source](https://github.com/falcosecurity/plugin-sdk-rs/tree/1a7e29e62d025dcd91796537421343111e55cd61),
[Linux open handlers](https://github.com/torvalds/linux/blob/v7.2/io_uring/openclose.c),
[Aya loader](https://github.com/aya-rs/aya/tree/aya-v0.13.1) and
[Falco advisory](https://github.com/falcosecurity/falco/security/advisories/GHSA-7cq5-h4p2-h37p).


## Automatic ClamAV and one-off scanning

Ironclad 0.2.34 adds a separate opt-in ClamAV Downloads watcher, alongside Falco behavior monitoring and sandboxed one-off file scans. Alert-only and prevention are distinct modes; verify current health before assuming coverage. No automatic deletion or quarantine. See [Automatic malware protection](AUTOMATIC_MALWARE.md) for scope, authentication, signature maintenance, limitations and stopping.
