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
process-local IPv4/IPv6 socket restriction. No third-party Python package, icon, font, copied QML implementation or AI model is bundled. The KRSI library and its Rust dependencies are the bundled native exception described above. Upstream reference documents under
docs/upstream retain their original authorship and repository license; they
are development evidence, excluded from installed/release payload. No claim
of Omarchy endorsement. Master handoff supplied by the owner.

### Optional Falco rule updates

The optional native sensor package additionally extracts falcoctl 0.14.2
(Apache-2.0, https://github.com/falcosecurity/falcoctl) from the pinned Falco archive.
The rule worker uses the OS-provided PyYAML package (MIT); tests pin PyYAML 6.0.3.
Official Falco rules are Apache-2.0: https://github.com/falcosecurity/rules.
Full transitive falcoctl licensing review is a release gate, not a completed claim.
