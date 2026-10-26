# Ironclad post-launch status

Review date: **October 25, 2026 America/Chicago**; automated checks/advisory lookup continued into October 26 UTC. Scope: `GingerRouxt/ironclad`, baseline **0.2.36 / `73e2275b3bb8b83c3c7c72c570cd6adff1402779`**, branch `feat/post-launch-ironclad`. These are proposed changes, not a new release or deployment. Community Ironclad remains free and MIT licensed.

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

## Executed validation

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

The runtime-bearing changed files are bound by SHA-256: `ui0236/Workspace.qml` = `be8c1960669fc87bcc7e2899e78f4a50762576b17aaacddc9edd1400bcece773`; `packaging/manage.py` = `4cc9af8162d9159982f1364751193547abca0a6e9b037c10d17dd1c73a5f6653`; `tools/generate_sbom.py` = `018956d5fcdf1ed38514ac1c9ff2f7b24b32c2f99e1ea069c4add3d8607816f7`. Candidate archive hashes change with documentation; the final exact archive hash belongs in the PR/build evidence rather than recursively inside this packaged status file.

### Failures found and resolved

The first Bubblewrap harness could not preserve root-owned system-file identity and lacked a synthetic passwd record: 303 tests ran with 11 failures and 83 errors. These were harness failures, not evidence of 94 product regressions. Rootless-container setup initially lacked zstd and the manifest validator, blocked nested proc mounts, and used a non-executable loader fixture. Those prerequisites were corrected inside the disposable environment; source trust checks were not weakened. The corrected baseline Python suite passed all 303 tests.

The baseline workflow UI then reproduced a product layout failure: Cancel was at y=705 outside a 700-pixel window. A first fix exposed batch-review clipping at y=700. Both layouts were corrected and the complete candidate UI suites passed with strict real-click bounds. Baseline JavaScript/privacy/policy checks were already passing; completed work was reused.

## Remaining blockers and triage

| Priority / owner | Gate | Next evidence required |
|---|---|---|
| P1 native maintainer | anyhow 1.0.102 matches RUSTSEC-2026-0190; tokio 1.52.2 matches RUSTSEC-2026-0386. | Establish actual target/call reachability and documented remediation/disposition; rebuild changed binary with pinned toolchain, update embedded provenance and hashes together, then run exact-binary VM acceptance. No application exploit demonstrated here. |
| P1 release tester | Fresh Quattro install/reboot/update/removal and authenticated native lifecycle **NOT RUN**. | Execute VM-01 through VM-10 on a separate disposable machine, preserving original release and unrelated services. |
| P1 native maintainer | Independent reproducible native rebuild, complete linked/transitive SBOM and licensing remain incomplete. | Pin recorded Rust/toolchain and isolated public inputs, compare rebuilt bytes, inspect third-party notices and Falco/system dependency closure. Do not equate deterministic tar packaging with native provenance. |
| P2 dependency maintainer | bincode, paste and proc-macro-error are flagged unmaintained. | Review upstream migration options and build/feature compatibility; do not blindly replace lock entries. |
| P2 UI tester | Smaller displays, alternate font scaling, multi-monitor and accessibility/resource extremes not established. | Separate-machine UI matrix; current real-click acceptance is 1020×700 plus existing fixture cases. |
| Maintainer/reviewer | PR review, new version/release decision and later marketplace snapshot review. | Review this feature branch and its own CI. Do not merge/tag/deploy or claim the new snapshot is verified automatically. |

`tools/verify_native_protection.py --run` and `tools/verify_onaccess_native.py --run` were **not executed**: they require live enabled sensors and create native detections. `tools/verify_installed.py` was covered through synthetic installed-audit tests, not aimed at the owner's live plugin. Reboot, prevention, real provider requests and production service acceptance were not performed. Their VM procedures are prepared, not counted as passes.

Known limitations remain: same-user/root/kernel compromise, shared-kernel sandbox defects, parser/engine vulnerabilities, bounded detection and event loss, incomplete software/advisory coverage, best-effort redaction, and externally controlled AI clients. See [security review](SECURITY_REVIEW.md) and [supply-chain detail](docs/SUPPLY_CHAIN_REVIEW.md).

## Recommended next steps

Review and merge only through the feature PR after its checks pass; decide the next version separately. Resolve native advisory disposition and perform the separate-machine matrix before expanding assurance claims. Obtain independent security/licensing review. Approve current launch copy only after confirming what version actually ships. Keep szdsecurity.com, cloud agents and other services untouched until a separate explicit task authorizes them.
