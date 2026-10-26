# Changelog

## Unreleased — opt-in Falco host-rule maintenance

- Add separately authenticated, off-by-default official host-rule updates; ClamAV consent never enables them. Keep community protection free.
- Rebuild the downloader with patched dependencies and a smaller anonymous, rules-only interface; require signature, identity, transparency and artifact-digest checks. Include reproducible build inputs, dependency inventory and notices.
- Isolate parsing/compilation, retain private staging and atomically activate checked generations with rollback. Fix the systemd/namespace integration issues found in the disposable VM.
- Release the panel for OS authentication and restore it afterward. Preserve the ability to disable existing updates if the maintainer release gate is closed.
- Record executed VM and automated checks separately from pending full Quattro desktop acceptance. No marketplace release, host installation or automatic customer activation is included.

## Unreleased — native dependency follow-up

- Rebuild KRSI fork .2 with anyhow 1.0.103 and Tokio 1.53.3; preserve upstream BPF instructions and the existing reviewed source patches.
- Pin the Rust compiler identity, allowlist the build environment, and update native provenance, hashes, lock and partial SBOM together.
- Repeat dependency query: two unsoundness matches resolved; three unmaintained-package findings remain with scoped triage. No certification or complete dependency clearance is claimed.


## Unreleased — post-launch hardening

- Record marketplace publication and maintainer review of `73e2275` on October 25, 2026; clearly label the historical preview film.
- Keep GUI diagnostics local until an explicit AI action; a new scan does not reuse previous AI consent.
- Refuse copied-install removal while diagnostic scheduling units remain, including dangling links.
- Keep update approval/cancel controls visible by bounding long single and batch review text; UI fixtures reject clipped clicks.
- Add reproducible partial SBOM generation, a fresh-VM acceptance matrix, release/contributor checklists and optional future Core interface design.
- Keep community Ironclad free. No cloud agent, unsolicited telemetry, website deployment or release publication is included.

These proposed changes are not covered by the marketplace's earlier snapshot verification. See [post-launch status](POST_LAUNCH_STATUS.md) for executed checks and remaining gates.

## 0.2.36 beta

Initial public source candidate: Quick 90, Full 180 and Super Scan 420; all-check AI explanations and per-check follow-up; private gzip scan archives; reviewed software actions; optional Falco/KRSI monitoring; automatic Downloads ClamAV scanning and sandboxed one-off scans.

Published October 23, 2026 from `5b80ec2`; marketplace snapshot `73e2275` was published and maintainer-verified October 25. Publication preparation excludes private development records and rebuilds the bundled native library with anonymous build paths. Coverage and validation limitations are documented explicitly; deterministic packaging and marketplace verification are not independent security assurance.
