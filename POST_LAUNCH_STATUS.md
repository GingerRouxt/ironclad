# Ironclad post-launch status

Review date: **October 26, 2026 America/Chicago**; automated checks/advisory lookup continued into October 26 UTC. Scope: `GingerRouxt/ironclad`, baseline **0.2.36 / `73e2275b3bb8b83c3c7c72c570cd6adff1402779`**, branch `feat/gated-falco-rules`, stacked on the post-launch branch. These are proposed changes, not a new release or deployment. Community Ironclad remains free and MIT licensed.

## Verified starting state

- The public checkout was clean at the requested baseline; remote `main` matched it. Existing release, tests, CI, README, native provenance and implementation were inspected before changing code. A separate dirty development checkout was not modified or copied into public history.
- [Marketplace catalog](https://omarchyplugins.com/catalog.json) reports `Available`, `maintainer-reviewed`, `snapshot-verified`, version 0.2.36, verification commit `73e2275b3bb8b83c3c7c72c570cd6adff1402779`, reviewed at `2026-10-25T22:05:39.627Z` by `HANCORE-linux`. [Submission #12687](https://github.com/omacom/omarchy-plugin-marketplace/issues/12687) is closed/listed/approved-and-verified. Its retained `security-review-required` label does not override the exact approval/publication record.
- The [maintainer comment](https://github.com/omacom/omarchy-plugin-marketplace/issues/12687#issuecomment-6403977517) explicitly excludes independent rebuild and privileged live behavior from its static review. Verification is not certification and does not automatically cover this branch.
- [Published release v0.2.36](https://github.com/GingerRouxt/ironclad/releases/tag/v0.2.36) dates to October 23, source `5b80ec2dd3f14f24d840b55771ca132fed33a968`, clean manifest, 78 runtime files. Downloaded archive checksum and GitHub asset digest agree: `083c1c2e1f0795f3420a3e2dfe4c858ec16a024cf5c844e091a7a2bfd4e998aa` (1,190,542 bytes). Release source and marketplace snapshot are different; neither was replaced.
- Baseline hosted [Local contracts](https://github.com/GingerRouxt/ironclad/actions/runs/39933396027) and [release-candidate build](https://github.com/GingerRouxt/ironclad/actions/runs/39933489998) passed at `73e2275`. Earlier failing runs are historical and were already superseded by the baseline fixes. The repository had no open issues or existing PRs at inspection. This branch's PR checks are separate evidence, not inferred from baseline CI.

## Completed changes

| Mission area | Completed, reviewable result |
|---|---|
| Publication wording | README, changelog, roadmap, rules and release guide state published/verified snapshot status; historical video and submission wording are explicitly labeled. No security-assurance upgrade is implied. |
| AI consent | GUI scan/rescan no longer initiates provider requests. Explicit Explain all checks/per-check/Ask actions remain. Tests exercise real clicks and verify zero requests before consent; docs distinguish the unreleased fix from published 0.2.36. |
| Update review UI | Long single/batch review text scrolls within a bound, keeping approval/cancel controls visible at the tested 1020×700 layout. Fixtures reject clipped/out-of-window clicks. |
| Uninstall | Copied installer refuses removal with remaining diagnostic service/timer units, including dangling links. Synthetic tests confirm controls are preserved and removal succeeds after units are removed. No host services were changed. |
| SBOM/audit | Deterministic partial CycloneDX inventory, integrity/drift tests, schema validation, dated advisory query and source review. CI reproduces the checked-in inventory; release CI retains it as a candidate artifact without publishing. |
| Acceptance | [Separate-machine matrix](docs/ACCEPTANCE_TESTS.md) covers install, reboot, optional native setup, binary provenance, opt-in, update, uninstall and preservation. Live rows remain NOT RUN. |
| Release/contributors | [Release checklist](docs/RELEASE_CHECKLIST.md) and [contributor checklist](docs/CONTRIBUTOR_TESTING.md) reuse existing tooling and require honest failed/skipped results. |
| Launch/business | [Announcement draft](docs/LAUNCH_ANNOUNCEMENT.md), updated [installation guide](docs/INSTALL.md) and [szdsecurity.com brief](docs/LANDING_PAGE_BRIEF.md); nothing posted or deployed. |
| Future Core | [Import-only interface proposal](docs/CORE_INTERFACE_PROPOSAL.md), with explicit future authorization, data minimization and no inherited agent authority. No connector, cloud agent, network telemetry or account requirement implemented. |

## Initial validation at e775ba9

Tests ran as an unprivileged synthetic user in a disposable rootless Ubuntu 24.04 container with no network or host home/desktop/service sockets, read-only tools/source input, scratch-only writable storage, 2 CPUs, 4 GiB memory, 256 processes, 1 GiB scratch, 256 MiB per-file limit and 480-second outer timeout. Existing local tools were mounted; no dependency installer or native build fetched code during target execution. Nested Bubblewrap tests needed an unmasked **container** `/proc` and namespace syscalls; host kernel settings were not changed. This shares the host kernel and is not a VM.

Environment: pinned project Python 3.14.8 / uv 0.13.4; existing Python 3.13.16 with PySide6/Shiboken6 6.12.0 for UI fixtures; real Omarchy manifest validator and QML lint tooling. Disposable base image ID: `b6862d3036a770b5c0e8a0987e9546dc1844f10ba70925f746e7a44ca84660c0`. No runtime upgrade or package installation on the host.

| Executed command/check | Result and precise scope |
|---|---|
| `uv run --offline python -m unittest discover -s tests -v` | **312 passed, 0 skipped** on the post-launch candidate. Baseline had 303. New tests: eight SBOM contracts and one diagnostic-unit removal regression. |
| `node --test tests/model.test.cjs` | **34 passed**. |
| `tools/verify_update_ui.py` using the existing PySide6 interpreter | **36 passed**, 164 real child processes, fixture operations only. Includes explicit AI consent and reachable review buttons. |
| `tools/verify_protection_ui.py` using the same interpreter | **31 passed**, 91 real child processes, no actual apps/engines installed or host files scanned. |
| `tools/verify_publication.py` | Passed on proposed public files and nested native archive; no private matching content disclosed. This is a pattern check, not proof every possible secret is absent. |
| `tools/verify.py --ui-python /path/to/ui-python --sensor-engine /path/to/pinned/falco` | Complete verifier passed: Python/model tests, root/extracted manifest, QML, Ruff, systemd syntax, policy, both UI suites, offline Full 180, three private report formats, baseline comparison, AI packet with no transport/action, reproducible package, isolated install/Quick 90/inventory/help/uninstall. |
| Pinned Falco policy dry-run | Eight rules compile with Falco 0.45.1 and bundled KRSI; `events_processed: false`. This did not attach a sensor. |
| Systemd syntax verification | Exit 0; absent system bus warning is expected in isolation. No service start, timer enable or reboot was tested. |
| SBOM generation twice and `cmp` | Identical 160,537-byte output; SHA-256 `31c8ad2d6ba767a061443660a46f46c8e72bf14beecdc17d88107160a96f3c96`; 173 components with scope limits. Official CycloneDX 1.6 schema validation: zero errors. |
| OSV public-package batch query | 150 queries, complete response, five matches. [Dated evidence](docs/dependency-advisories.json) is bound to SBOM and lock hashes. No dependency clearance claim. |
| Published archive | Downloaded checksum verified against sidecar and release manifest; original assets untouched. |
| Agent diff review | Separate focused AI/permission/lifecycle and supply-chain reviews; documentation discrepancies corrected. This is agent source review, not external human approval or independent certification. |

At e775ba9, the runtime-bearing changed files were bound by SHA-256: `ui0236/Workspace.qml` = `be8c1960669fc87bcc7e2899e78f4a50762576b17aaacddc9edd1400bcece773`; `packaging/manage.py` = `4cc9af8162d9159982f1364751193547abca0a6e9b037c10d17dd1c73a5f6653`; `tools/generate_sbom.py` = `018956d5fcdf1ed38514ac1c9ff2f7b24b32c2f99e1ea069c4add3d8607816f7`. Candidate archive hashes change with documentation; the final exact archive hash belongs in the PR/build evidence rather than recursively inside this packaged status file.

### Failures found and resolved

The first Bubblewrap harness could not preserve root-owned system-file identity and lacked a synthetic passwd record: 303 tests ran with 11 failures and 83 errors. These were harness failures, not evidence of 94 product regressions. Rootless-container setup initially lacked zstd and the manifest validator, blocked nested proc mounts, and used a non-executable loader fixture. Those prerequisites were corrected inside the disposable environment; source trust checks were not weakened. The corrected baseline Python suite passed all 303 tests.

The baseline workflow UI then reproduced a product layout failure: Cancel was at y=705 outside a 700-pixel window. A first fix exposed batch-review clipping at y=700. Both layouts were corrected and the complete candidate UI suites passed with strict real-click bounds. Baseline JavaScript/privacy/policy checks were already passing; completed work was reused.

## Native dependency follow-up

The candidate now bundles fork `0.2.0-ironclad.2`, rebuilt with anyhow 1.0.103 and Tokio 1.53.3. Only those two registry package versions changed. Pinned public inputs and the existing source/loader/BPF patches were retained. The recipe verifies Rust 1.99.1 and uses an allowlisted environment; compilation occurred without network or access to user credentials. Native unit tests: **7 passed, 1 ignored** (`load_and_attach_programs`); the ignored kernel-loading test was not executed. Two additional Python contracts verify environment filtering and compiler mismatch refusal.

The current partial inventory SHA-256 is `46acac9493291136375b86eae90cd6ec607842e8adc9ea81504e8e675ca8ef5b`; lock SHA-256 is `7475b33f8395f80fb30ea6407b80ac3ed8d6d5904ca053c7369c1ecd973f7e37`. The October 26 03:30 UTC query of the same 150 public identities returned **three unmaintained-package matches**, with no remaining match for the updated anyhow/Tokio versions. The earlier five-match result above is historical. See [native build procedure](docs/NATIVE_BUILD.md).

Final native follow-up validation: **314 Python tests, 34 JavaScript tests, 36 workflow UI cases and 31 protection UI cases passed**. The complete verifier passed again with the final .2 native artifact, including eight-rule Falco dry-run, 91-file packaging and isolated install/remove. Two clean builds at the same canonical `/build/native` path produced identical archive SHA-256 `d64d617b24a56d93bbfcf680582e49fbecee869741bb3699350cedfb812ddf5d`; library SHA-256 `9935296a6dd5b0395833055a84dcfa527d630c241532a0e90afc6ca055cb5bd1`. Different work paths did not reproduce identical bytes; fixed build paths and system/compiler inputs are required. This is local repeatability, not an independent rebuild.

The initial follow-up suite failed one SBOM assertion that still expected fork .1; it was updated to .2 and all 314 tests passed. The final artifact also corrects the library's internal version label. Source logic and BPF instructions were otherwise retained. The final advisory re-query at **2026-10-26 03:35 UTC** again returned only the three maintenance advisories. Public evidence excludes workstation details, logs and reports.

## Remaining blockers and triage

| Priority / owner | Gate | Next evidence required |
|---|---|---|
| P1 release tester | Candidate updates resolve the two anyhow/Tokio advisory matches; exact-binary fresh-machine acceptance remains. | Repeat the separate-machine matrix before a new native release. No application exploit or complete dependency clearance is claimed. |
| P1 release tester | Fresh Quattro install/reboot/update/removal and authenticated native lifecycle **NOT RUN**. | Execute VM-01 through VM-10 on a separate disposable machine, preserving original release and unrelated services. |
| P1 native maintainer | Independent reproducible native rebuild, complete linked/transitive SBOM and licensing remain incomplete. | The local recipe now pins the compiler identity and isolates inputs; obtain an independent rebuild, inspect third-party notices and Falco/system dependency closure. Do not equate deterministic tar packaging with native provenance. |
| P2 dependency maintainer | bincode, paste and proc-macro-error are flagged unmaintained. | Review upstream migration options and build/feature compatibility; do not blindly replace lock entries. |
| P2 UI tester | Smaller displays, alternate font scaling, multi-monitor and accessibility/resource extremes not established. | Separate-machine UI matrix; current real-click acceptance is 1020×700 plus existing fixture cases. |
| Maintainer/reviewer | PR review, new version/release decision and later marketplace snapshot review. | Review this feature branch and its own CI. Do not merge/tag/deploy or claim the new snapshot is verified automatically. |

During the initial isolated review, `tools/verify_native_protection.py --run` and `tools/verify_onaccess_native.py --run` were **not executed**: they require live enabled sensors and create native detections. `tools/verify_installed.py` was covered through synthetic installed-audit tests, not aimed at the owner's live plugin. Reboot, prevention, real provider requests and production service acceptance were not performed. Their VM procedures are prepared, not counted as passes. Owner workstation evidence is private and is not included in this public report.

Known limitations remain: same-user/root/kernel compromise, shared-kernel sandbox defects, parser/engine vulnerabilities, bounded detection and event loss, incomplete software/advisory coverage, best-effort redaction, and externally controlled AI clients. See [security review](SECURITY_REVIEW.md) and [supply-chain detail](docs/SUPPLY_CHAIN_REVIEW.md).

## Recommended next steps

Review and merge only through the feature PR after its checks pass; decide the next version separately. Resolve native advisory disposition and perform the separate-machine matrix before expanding assurance claims. Obtain independent security/licensing review. Approve current launch copy only after confirming what version actually ships. Keep szdsecurity.com, cloud agents and other services untouched until a separate explicit task authorizes them.

## Optional Falco rule maintenance — October 26 remediation

The candidate now supports separately authenticated, **off-by-default** host-rule
updates. Installation, a plugin update and existing ClamAV consent do not enable
its timer. The maintainer code gate is open for this tested candidate; customer
consent is still required. No host sensor, host timer, customer machine, website,
release tag or protected branch was changed during this remediation.

### Verified fixes and evidence

- Bundled a rules-only falcoctl `0.14.2-ironclad.1` build using Go 1.27.3,
  Cosign 3.1.4 and Rekor 1.5.5. Removed driver/registry-management commands and
  credential discovery from the download path. Missing signature policy and
  verification bypass are refused. Mandatory digest claims use Cosign's in-toto
  verifier for v3 bundles and simple verifier for legacy signatures.
- Fixed the default-index bug discovered by the negative issuer test: the worker
  explicitly selects its local policy, and the compiled downloader refuses any
  remote-index fallback. Correctly signed content cannot substitute an arbitrary
  configured issuer/workflow policy.
- Two local offline builds reproduced the same binary and archive. Exact input
  and output hashes, patch/locks, audit commands and limitations are recorded in
  [downloader provenance](docs/FALCO_DOWNLOADER_BUILD.md). All 159 recorded Go
  modules have collected notices. This is not independent provenance or legal
  certification.
- Final `govulncheck@v1.9.0` source and exact-binary scans: **zero affected symbols,
  zero vulnerable imported packages**. One module-level OpenPGP advisory remains
  for unused packages in `x/crypto`; it is documented, not suppressed. Existing
  Falco/native dependency limitations and KRSI unmaintained-package triage remain.
- Deterministic CycloneDX inventory: **335 components**, schema 1.6 validation
  passed; binary hashes and embedded locks/patches are checked. The inventory
  remains incomplete for the separate Falco engine and exact native link graph.
- Full local verifier: **330 Python tests, 34 JavaScript tests, 36 workflow UI
  cases, 32 protection UI cases passed**, plus QML lint, policy compilation,
  reproducible **97-file** packaging, and fixture install/remove. UI authentication
  releases the overlay and restores it afterward; cancellation grants no consent.
  A closed maintainer gate still permits disabling an already-enabled timer.
- Publication pattern/path checks passed for **168 source files**, including the
  nested native archives. This is a bounded privacy check, not universal secret
  detection. Raw machine evidence and credentials remain excluded from Git.

### Executed disposable-guest acceptance

A signed official Arch cloud image was verified with the Arch Boxes signing key
and run in a disposable KVM guest. QEMU was privately extracted from verified
packages; no host OS-package installation or host reboot occurred. This guest is
headless Arch, **not full Omarchy Quattro desktop acceptance**.

`tools/verify_falco_rules_native.py --confirm-disposable-vm` passed **11 checks**:

1. Refuse an unconsented refresh without restarting the sensor.
2. Real systemd service verifies/downloads rules and observes healthy live metrics.
3. An unchanged generation does not restart monitoring.
4. Missing local policy fails closed.
5. Wrong workflow identity is rejected before activation.
6. Wrong issuer is rejected before activation.
7. Verification bypass is rejected before activation.
8. Invalid rules fail compilation before activation.
9. An injected health failure causes actual service restarts and successful rollback.
10. A pending transaction recovers the prior healthy generation.
11. Disable retains current rules and monitoring while stopping scheduled updates.

The signed snapshot supplies **13 additional host rules**, with 12 disabled or
unsupported rules excluded; the existing eight Ironclad rules remain. A harmless
self-`PTRACE_TRACEME` fixture produced the upstream `PTRACE anti-debug attempt`
alert with only rule identity, severity, time, application and event type retained.
A guarded capacity test filled the private scratch filesystem, observed `ENOSPC`
at the 32 MiB limit and confirmed unmount/cleanup. A separate sandbox probe
verified UID 65534, zero effective capabilities, no home,
no host state/desktop mounts and no leaked directory descriptors. That UID maps to
host root in the new user namespace; it is not a distinct host service account.
The worker additionally installs an inherited socket-family/io_uring seccomp filter
to deny local Unix/Netlink/packet socket authority. A real child-process regression
checks denial, IPv4 availability and filter inheritance across exec.

A guest-only reboot changed its boot ID and passed the guarded boot check: explicit
consent, timer enablement, selected rules and fresh zero-drop monitoring survived.
The exact final package passed this check after a guest-only reboot; the kernel
was 7.2.11-arch1-1. Guarded native uninstall also passed: the owned sensor/updater
services stopped, the native helper was removed, and local evidence was retained.

### Failures found and addressed

The VM exposed staging ownership/mapping errors and systemd restrictions that
prevented namespace setup. Staging now stays root-private and is mounted through
a descriptor. Downloads/extraction use a 32 MiB private tmpfs; worker `/tmp` is
also capped at 32 MiB, with checked persistent output limits. The supervisor grants the mapping capability needed by the kernel;
worker capabilities remain empty. Incompatible outer `RestrictSUIDSGID` and
`ProtectKernelTunables` settings were removed; `NoNewPrivileges`, read-only host
mounts, separate namespaces and resource limits remain. These tradeoffs are
explicit in [the trust design](docs/FALCO_RULE_UPDATES.md).

Early downloads at a 50% CPU quota caused observed kernel drops in the small guest.
The updater now uses **10% of one CPU**; the final signed-refresh and live-health
checks passed without relaxing zero-drop activation checks. Monitoring retains
its existing 25% CPU / 512 MiB limits. Workload calibration is still required;
future drops remain visible as degraded coverage, never inferred safety.

Other failed intermediate runs included a v3/simple-claim mismatch, the remote
index bug, an authentication-panel restore failure, obsolete Go dependency API
combinations, and a native-fixture crash-loop-limit collision during rapid injected
restarts. Each was corrected and the relevant final checks rerun. The fixture resets
crash-loop counters between deliberate failure scenarios; production limits are
unchanged. The verifier's former 30-second suite limit was raised to 120 seconds
for the larger native inventory; ignored tool-cache symlinks are excluded by
validating the actual allowlisted release payload.

### Remaining review and next steps

- Review draft [PR #2](https://github.com/GingerRouxt/ironclad/pull/2), stacked on
  PR #1. Do not merge, tag or deploy from this development run. Repository issue
  triage on October 26 found no open issues; remaining work is recorded here.
- Run full Quattro desktop/Polkit acceptance, long-running legitimate workloads,
  false-positive/resource calibration and independent security/build review.
  Headless guest results and synthetic UI authentication are not substitutes.
- Review complete Falco native dependency/license closure and the existing KRSI
  maintenance findings. No scanner, signature feed or rule engine guarantees
  protection against all malware. Rule updates can create brief monitoring gaps;
  signed-but-poor rules and signed replay remain trust limitations.
- The branch prepares daily GitHub contracts and exact-binary vulnerability checks
  at **11:17 UTC** with read-only repository permissions. The schedule becomes
  active only after merge to the default branch and may be delayed by GitHub.
  It does not modify code, ship updates or autonomously innovate. No daily Codex
  development schedule is claimed to be active.
- Community Ironclad remains free. Core fleet integration remains a future,
  documented interface only; no cloud agent or unsolicited telemetry was added.
