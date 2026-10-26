# Validation history and post-launch checks

## Native dependency follow-up

The final fork .2 candidate passed 314 Python tests (zero skips), 34 JavaScript tests, 36 workflow UI cases, 31 protection UI cases and the complete isolated verifier. Rust library tests passed seven with one upstream kernel-load test ignored. Two cold builds at the same canonical path produced identical native archives; different-path builds did not. See [native build procedure](docs/NATIVE_BUILD.md) and the status report for exact hashes and limits.

## Initial post-launch branch at e775ba9

The post-launch candidate passed 312 Python tests (zero skips), 34 JavaScript model tests, 36 workflow UI cases and 31 protection UI cases. The complete verifier passed manifest/QML/Ruff/systemd syntax checks, pinned eight-rule policy compilation, offline reports/baseline/AI-packet checks and isolated deterministic package/install/remove flows. The partial SBOM reproduced byte-for-byte and validated against CycloneDX 1.6; dependency advisory matches remain open, not cleared by these tests.

See [POST_LAUNCH_STATUS.md](POST_LAUNCH_STATUS.md) for exact evidence, baseline/harness failures, fixes, environment, separate-machine blockers and security limitations. No host install, service mutation, reboot, provider request or live native acceptance was performed in this pass. Human PR review remains separate.

## Historical public export — 0.2.36

The public export passed 299 Python tests and 34 JavaScript model tests, plus 35 real-process workflow UI cases and 31 protection UI cases. Four additional publication-privacy regression tests passed. These are automated contracts and synthetic workflows, not measured attack recall.

The complete verifier also passed root/extracted manifest validation, QML lint, Ruff, systemd unit validation, eight-rule compilation using the pinned Falco engine and rebuilt KRSI library, offline Full 180 diagnostics, three private report formats, baseline comparison, AI packet preparation, reproducible 78-file runtime packaging, and isolated install/Quick 90/software inventory/removal.

Publication checks inspect the exact export and nested archives for private build paths and credential markers. `.env` files are excluded and rejected. Historical workstation reports, local evidence and private development history are not distributed. Pattern checks do not guarantee detection of every possible secret.

The KRSI library was rebuilt with anonymous source/cache paths. Its pinned hashes changed; the release does not claim exact-binary privileged live-kernel acceptance of this rebuild. Earlier development native behavior and EICAR tests are distinct from current automated fixtures. Independent review, fresh-machine/reboot acceptance, native prevention acceptance, comprehensive dependency/SBOM review and general attack recall remain unverified.

Raw test logs and workstation observations stay private. No credentials, machine reports or personal paths are needed to reproduce synthetic tests.
