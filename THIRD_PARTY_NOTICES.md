Falco integration (0.2.33): Ironclad prepares the unmodified official dynamic Falco 0.45.1 binary, SHA-256 pinned in sensor_policy.py, after an explicit Enable action. Falco copyright The Falco Authors, Apache-2.0; license and upstream notices are included in the native component. Falco itself is downloaded separately, not included in the plugin archive. The eight-rule policy and supervisor are Ironclad code.

The plugin includes a pinned local KRSI 0.2.0-ironclad.1 library. KRSI and the Falco Rust SDK retain The Falco Authors' Apache-2.0 licensing. Aya/Aya-obj retain their MIT/Apache-2.0 licensing. The bundle contains build provenance, dependency lock, local source patches and 159 public license/notice files, copied into the native component. Upstream BPF instructions remain unchanged; ELF hook aliases, a small Aya call-relocation correction, scoped write extraction, lazy capture initialization, possible-CPU buffer sizing and reader-health metrics are local changes. The rebuild recipe and pinned source URLs are in tools/build_krsi_component.py. A comprehensive dependency/SBOM review remains incomplete. ClamAV continues to come from its separately licensed system package.

Optional ClamAV integration (0.2.17): ClamAV is separately installed, not bundled or redistributed in this plugin. Its own package provides its licenses and notices. Software advisory data comes from OSV (https://osv.dev); known-exploited evidence comes from CISA’s official catalog mirror (https://github.com/cisagov/kev-data). No proprietary detector or upstream implementation is copied.

# Dependency and provenance matrix

Original Python/QML: MIT; see LICENSE.
Python standard library/runtime: PSF license, not bundled. Qt Quick/Controls:
installed system dependency under Qt licensing, not bundled. Quickshell:
installed system dependency (LGPL-3.0), not bundled. Omarchy shell base types:
installed system dependency (MIT), not bundled. Linux command-line tools:
optional system dependencies, not redistributed; their absence is reported.
libseccomp: installed system library (LGPL-2.1), not bundled; used only for a
process-local IPv4/IPv6 socket restriction. No third-party Python package, icon, font, copied QML implementation or AI model is bundled. The KRSI library and rules-only falcoctl fork, with their dependencies, are the bundled native components described here. Upstream reference documents under
docs/upstream retain their original authorship and repository license; they
are development evidence, excluded from installed/release payload. No claim
of Omarchy endorsement. Master handoff supplied by the owner.

### Optional Falco rule updates

The optional native sensor package includes the bundled rules-only falcoctl fork
0.14.2-ironclad.1 (Apache-2.0, https://github.com/falcosecurity/falcoctl).
`ironclad/falcoctl-component.tar.gz` contains its source patch, locked Go modules,
build provenance, Go license and license/notice files for all 159 modules recorded
in its binary. The deterministic recipe is `tools/build_falcoctl_component.py`.
This collected notice inventory does not assert independent legal review.
The rule worker uses OS-provided PyYAML (MIT); tests pin PyYAML 6.0.3.
Official Falco rules are Apache-2.0: https://github.com/falcosecurity/rules.
Falco and the downloader are separate components; the timer does not upgrade engines.
