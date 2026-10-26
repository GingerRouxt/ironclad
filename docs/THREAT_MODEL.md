# Threat model — Ironclad post-launch branch

Ironclad protects diagnostic privacy, reviewed-action boundaries and desktop
availability. It provides bounded observations and selected detections; it is not
an assurance that the workstation is free of malware or every application is patched.

## Boundaries and controls

- The diagnostic engine is unprivileged and read-only. A fail-closed process-local
  libseccomp guard blocks new IPv4/IPv6 sockets in it and its children. It is not a
  complete sandbox: inherited descriptors and local IPC proxies are outside that
  narrow guard. Collectors use fixed commands, minimal environments and bounded
  time, memory and output; no shell or model-supplied commands.
- Local exports are escaped, exclusive and private. Directory-fd walks reject
  linked ancestors; sensitive files/receipts have ownership/mode/link checks.
  Saved scans are opt-in. Repair/update activity receipts remain local separately.
- Optional network operations are separate companion actions. Software checks
  contact configured tool sources, OSV and the CISA catalog with disclosed package
  metadata. Enabled maintenance refreshes official ClamAV signatures and checks
  public engine-release versions. It does not automatically install code.
- On this branch GUI scans remain local until an explicit AI action through the
  signed-in Codex/Claude client; CLI scans do not invoke AI. Published 0.2.36
  automatically requested GUI explanations; see the version-specific privacy note.
  Advice is plain text, bounded and has no
  execution/approval authority. Client tools/extensions are disabled. No Ironclad
  provider key storage; unknown private strings cannot be universally redacted.
- Reviewed repairs have a fixed action registry, expiring exact plans, revalidation
  after authentication, one-use receipts and verification. Protected boot/session
  services and unsupported firmware work are excluded from generic repairs.
- Optional monitoring installs a hash-pinned Falco component through OS
  authentication. The root-owned helper accepts only its fixed run/enable/disable
  operations and validates installed asset hashes and ownership. The systemd unit
  restricts capabilities, resources, writes and network access. Falco internally
  builds system process state, potentially including arguments. The retained
  private bridge feed contains only rule/time/app/event, not arguments or paths.
- ClamAV receives one explicitly selected owned regular file through a validated
  sealed, immutable, size-bounded snapshot on stdin. The original descriptor is
  never inherited by the parser. Hidden/common credential/database paths, links and unsafe targets are
  refused. Scan/file/archive/time limits apply; no deletion or quarantine. The
  scanner runs unprivileged inside mandatory Bubblewrap user, mount, PID, IPC
  and network namespaces, with all capabilities dropped, no new nested user
  namespaces, a read-only runtime and two public signature databases, public
  ClamAV verification certificates, and disposable size-bounded scratch. Host
  home, desktop sockets and host process files are absent. Sandbox setup failure
  cannot fall back to an unisolated scan. Kernel and sandbox vulnerabilities
  remain part of the shared-kernel risk; this is not a virtual machine.
- Update availability and advisory matching are distinct. A patched configured
  global tool does not make retained versions safe: project pins can still select
  them. Publisher fixed releases are bounded package-matched guidance, not
  executable plans or authorization to change pins/remove versions.

## Known limits and residual risk

The eight custom detection categories are narrower than the complete Falco ruleset.
Rename-only/atomic replacement, other persistence paths, many network/script attacks
and privileged evasion are not comprehensively covered. Version 0.2.33 adds a
pinned local KRSI fork for OPENAT, OPENAT2 and direct-open write intents at the
watched locations. Native positive/negative and service-constrained acceptance
are required for deployment; see [detection coverage](DETECTION_COVERAGE.md).
Other asynchronous operations and loss in the upstream BPF ring buffer remain
unmeasured. The official incompatible plugin is not used; the SDK schema is real,
not spoofed. No engine downgrade, kernel io_uring control, boot LSM or TPM change
is involved. Reader death, processing errors and stale/missing counters prevent
healthy status. Zero counters do not establish complete attack detection.

Same-UID/root/kernel compromise, malicious administrator-approved packages,
compromised publishers/tool managers, parser zero-days, complete CVE/transitive
coverage and firmware attestation remain outside this assessment. HTTPS and pinned
hashes reduce specific supply-chain risks; they are not a complete dependency audit.
Signature freshness and package freshness differ; all-clear claims must account for
unverified sources, unsupported software and retained versions.

## Release acceptance still required

Independent security review, a clean-machine lifecycle/recovery run, broader
accessibility/resource testing, native authentication-focus acceptance and complete
static sensor dependency/SBOM/license review remain outstanding. No signed public
code-update channel is claimed. The partial SBOM and matched dependency advisories are
documented in [supply-chain review](SUPPLY_CHAIN_REVIEW.md); they are not dependency clearance.
See [test results](../TEST_RESULTS.md) for the sanitized validation summary;
passing tests are not a security certification.
