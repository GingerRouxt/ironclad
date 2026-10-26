# Optional automatic Falco host rules

**Available in 0.2.37:** the security fixes now use a reproducible,
rules-only downloader build. Customers explicitly opt in; installing this release does not enable automatic rule updates.

This feature is **off by default**, including after installation or a plugin or
sensor update. Existing consent for ClamAV signatures does not enable it.
In Protection → Updates, the customer separately chooses **Enable Falco rule
updates…** and authenticates through the OS. The explanation states the download
schedule, additional host rules and brief monitoring restart. Monitoring must
already be enabled. The community feature remains free.

The root-owned timer checks the official `falco-rules:5` channel every six hours,
with up to fifteen minutes of jitter. The first scheduled check follows activation
by five to twenty minutes. Missed checks resume when the machine is available;
the timer does not wake or reboot it. Turning updates off disables future checks
and retains installed rules. Stopping monitoring prevents rule activation.
An in-progress activation is locked against explicit monitoring changes; a busy
change fails visibly and can be retried after the update finishes.

## Trust and activation

The optional sensor component includes the bundled `0.14.2-ironclad.1` rules-only
fork of falcoctl, rebuilt with Go 1.27.3, Cosign 3.1.4 and Rekor 1.5.5. Driver,
registry-management and signing commands are not registered. Public artifact
requests use anonymous authentication; cloud/host credential discovery is removed
from the download path. Missing signature policy and `--no-verify` are rejected.
Cosign verifies the artifact digest using its in-toto claim verifier for new
bundles and simple claim verifier for legacy signatures. Issuer, workflow identity,
certificate transparency and transparency-log verification remain required.

Pinned source, patches, Go module locks, binary/module inventory and notices are
included with the [build recipe](FALCO_DOWNLOADER_BUILD.md). All 159 recorded Go
modules have collected license/notice files; this is not a legal certification or
an independent provenance attestation. A hash establishes expected bytes, not an
absence of vulnerabilities.

Each update uses a fresh, disposable Bubblewrap filesystem, PID and user namespace,
without the user's home, credentials, desktop sockets or host state. The worker
has network access for public registry and Sigstore verification. Its namespace
UID is 65534 with no effective capabilities. Because the root supervisor creates
the namespace, this maps to host UID 0; it is not a separate host service account.
Only root-private scratch storage is writable. Downloads/extraction use a 32 MiB
tmpfs in a private supervisor mount namespace; the worker's `/tmp` is separately
capped at 32 MiB. These are removed after the attempt. Individual service file
writes are capped at 16 MiB; persistent rule/metadata copies have tighter checked
limits. An inherited libseccomp filter
permits only IPv4/IPv6 socket creation, denies socket pairs and blocks io_uring
syscalls. This prevents shared-network abstract Unix sockets from conveying the
supervisor's host UID; downloaded code receives no local socket authority. A directory descriptor is
passed to Bubblewrap (`>=0.10.0`) without exposing a traversable staging path to
other local users. Home, host state, desktop sockets and `/sys` are not mounted.
`NoNewPrivileges` remains set. The supervisor needs `CAP_SETFCAP` to create the
root UID mapping. `RestrictSUIDSGID` and `ProtectKernelTunables` are deliberately
not applied to the outer unit: their syscall/proc restrictions prevented
Bubblewrap setup in live tests. The worker's actual namespace and capability
restrictions are checked separately; these unit settings are not a sandbox by
themselves. Its fixed local
index pins the official rules repository, GitHub Actions issuer and rules-workflow
identity; an upstream index cannot replace that trust policy. Signature and
transparency-log checks stay enabled. Dependency resolution is disabled and only
rulesfile artifacts are allowed: downloaded plugins and scripts are not executed.

The worker rejects unsupported YAML directives, aliases and oversized inputs.
It excludes container/plugin-dependent rules and their transitive macros, then
rewrites rule output to application name and event type. Existing eight Ironclad
rules remain. Falco compiles the combined rules in the isolated worker before any
activation. A compiler failure preserves the current generation.

Activation atomically selects a root-owned, hash-checked generation, briefly
restarts only Ironclad monitoring and checks fresh kernel/asynchronous metrics
and the selected generation's hash. Failure restores the previous selection and
restarts it. A transaction journal permits recovery after interruption; rollback
failure is reported rather than called success. No engine, kernel, OS package,
prevention mode, customer file or production website is updated by the timer.

## Coverage, privacy and limitations

The tested signed upstream snapshot produced 13 additional host rules; 12 disabled
or container-dependent rules were excluded. This count can change with accepted
updates. These are behavior detections, not ClamAV malware signatures, a complete
EDR platform, or a guarantee against new malware. False positives remain possible.
Compilation and fresh metrics do not measure detection accuracy. A broken rule
update can cause a brief monitoring gap even when rollback succeeds.

Rule names, time, application name, event type and severity enter the bounded local
alert feed. Command arguments, file paths, contents and raw Falco output are not
retained in it or uploaded. Rule downloads contact GHCR/GitHub and Sigstore public
services; no local alerts, files, package inventory or credentials are sent.
Falco still maintains internal process state as documented for existing monitoring.

The channel is constrained to major rule series 5. New requirements or incompatible
updates fail validation; changing the channel or downloader requires a reviewed
component update. This mechanism does not prevent a trusted publisher from shipping
a poor detection or replaying older signed content. Trust-root changes, freshness
failures, independent review, false-positive calibration and complete native
dependency auditing remain maintainer responsibilities. Previous generations are
retained locally for investigation; disabling does not delete them.

## Verification and release gates

See [post-launch evidence](../POST_LAUNCH_STATUS.md) for executed checks and failures.
The reproducible native acceptance tool refuses machines without both KVM/QEMU
virtualization and a root-owned disposable-test marker. It exercises the real
systemd service, signed updates, negative signature/compile cases, explicit
consent, unchanged-generation behavior, and live-service rollback with a clearly
identified injected health failure. It never reboots a machine itself.

The acceptance guest is headless Arch, not a complete Omarchy Quattro desktop.
Full Quattro GUI/Polkit acceptance, independent rebuild, workload/false-positive
calibration and external security review remain release work. Fresh metrics are
not a guarantee of continuous lossless monitoring: counters can later show dropped
events under load, and the UI must retain that degraded-health indication.
No host sensor or customer timer was enabled by this development work.

Official references: [Falco rule distribution](https://falco.org/docs/concepts/rules/default-custom/),
[signature verification](https://falco.org/blog/sign-verify-plugins-rules/),
[falcoctl](https://github.com/falcosecurity/falcoctl).
