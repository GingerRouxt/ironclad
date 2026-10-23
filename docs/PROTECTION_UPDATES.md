# Protection maintenance (0.2.21)

Ironclad is an Omarchy plugin. Automatic maintenance is enabled in Protection
and can be turned off there. Enabling authorizes recurring downloads from the
official ClamAV signature service and public ClamAV/Falco release metadata from
api.github.com. No files, findings, package inventory or credentials are uploaded.
Installation alone never enables a network schedule for another user.

The user timer checks signatures every four hours with up to fifteen minutes of
jitter, plus an initial run five to twenty minutes after activation. Persistent
calendar scheduling catches a missed run when the user manager next starts.
It does not wake a sleeping machine or enable user lingering. The updater runs
unprivileged at low CPU/I/O priority, with 1 GiB memory, 20% of one CPU, 32 tasks
and a twelve-minute timeout. Filesystem namespace options are deliberately absent:
they can remap root ownership and break the strict packaged-command
trust checks. This service is not claimed to isolate same-user malicious code. Failed runs retry
at the next schedule. Update protection now runs a check immediately. A shared
lock prevents simultaneous automatic/manual signature downloads. FreshClam
validates official signatures and tests downloaded databases; existing databases
are not proactively removed on failure. A scan whose database changes reports
incomplete rather than clearing the file.

Protection shows the actual enabled/active timer state, last attempted and
successful refresh, failed/interrupted runs, signature checks older than 24 hours,
and engine metadata older than 48 hours. A successful check can leave unchanged
signature-file timestamps: last refresh and database age are different measures.
The scanner also refuses databases older than seven days. Finding Ignore never
changes this status, schedules or scanner configuration.

Engine metadata is checked at most daily after a successful check; errors are
retried on subsequent runs. Only stable numeric release versions from the two
fixed official repositories are accepted. Versions are advisory, not evidence
that an engine update was installed or that the machine is safe. No downloaded
release text or executable is run. Falco's displayed bundled version is the pinned
version offered by this Ironclad release. Installed sensor/policy mismatch is
shown separately by Monitoring with Review bundled sensor update.

## Engine, rule and plugin releases

- ClamAV engine updates use the supported Omarchy/Arch full system update path.
  Signature maintenance does not run a package transaction or partial system upgrade.
- Falco and custom rules are versioned together in sensor_policy.py. A maintainer
  reviews upstream changes, pins and independently verifies the official archive
  and binary hashes, updates package extraction/license paths if needed, and bumps
  the component version. Hashes authenticate expected bytes; they are not a
  substitute for establishing upstream provenance.
- A plugin update does not silently replace the root sensor. Monitoring compares
  installed policy/engine/rules with the bundled target and offers a reviewed
  reinstall through existing OS authentication and fresh-metrics verification.
  The short sensor restart is explicit; Codex and other applications are not stopped.
- Published git-managed plugins use `omarchy plugin update com.zerodaysecurity.ironclad`.
  Omarchy previews changes, fast-forwards and validates the manifest, rolling back
  validation failures. Its validation does not establish detection quality or
  cryptographic release provenance. The local receipt-based development install
  has no configured published update channel, and the UI says so explicitly.
- There is no automatic code updater or signed release channel in this build.
  Do not claim otherwise. Publication requires separate maintainer authorization.

## Maintainer cadence and release checks

Review upstream engine/security releases and detection changes weekly, prioritize
security fixes when notified, and review rule coverage monthly. These are human
maintenance duties, not a promise that the plugin manufactures new detections.
Every rule change needs malicious-behavior fixtures, legitimate-workload cases,
field/version compatibility checks and owner-visible coverage notes. Keep the
previous verified component artifact available for a reviewed rollback.

Before releasing: run `mise exec -- uv run --offline python tools/verify.py
--ui-python /path/to/pinned/ui-python`, then isolated native sensor/EICAR acceptance,
resource/drop checks and legitimate desktop/developer workload checks. The EICAR
fixture is a scanner plumbing test, not a measured malware detection rate. Run
fresh-VM, reboot and independent review gates before claiming broad compatibility.
Do not run live malware on a user's desktop. Document changed coverage, false
positives, engine/policy versions and recovery instructions with each release.

## Removal

Turn off automatic updates in Protection before removing the plugin. This disables
only ironclad-protection-updates.timer and removes its unchanged owned unit files.
An already-running update can finish; signatures and update records stay local.
The file uninstaller refuses to remove controls while maintenance units remain.
Remove the native sensor separately through its reviewed Protection action.


## Automatic ClamAV and one-off scanning

Ironclad 0.2.34 adds a separate opt-in ClamAV Downloads watcher, alongside Falco behavior monitoring and sandboxed one-off file scans. Alert-only and prevention are distinct modes; verify current health before assuming coverage. No automatic deletion or quarantine. See [Automatic malware protection](AUTOMATIC_MALWARE.md) for scope, authentication, signature maintenance, limitations and stopping.
