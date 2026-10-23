### Repository URL

https://github.com/GingerRouxt/ironclad

### Category

System

### Tags

security, system, quickshell

### Suggest a missing tag

_No response_

### Maintainer notes

ZDS Ironclad 0.2.36 beta by Zero Day Security: local 90/180/420 diagnostic profiles, optional Falco/KRSI behavior monitoring, ClamAV Downloads and one-off file scans, and explanations through an existing signed-in agent. Website: https://szdsecurity.com/.

Requires Omarchy Quattro, Python 3.12+ and libseccomp. Native monitoring targets x86_64. Optional dependencies and exact install/removal steps are documented in the README and docs/INSTALL.md and docs/UNINSTALL.md. Installing the widget does not enable privileged services or recurring downloads. Optional setup and supported system actions require explicit review and OS authentication. GUI scans request AI explanations through an available signed-in provider; disclosures and limits are in docs/PRIVACY.md.

MIT original code; Falco/KRSI and bundled Rust notices are documented in THIRD_PARTY_NOTICES.md. ClamAV is separately installed. Images use the project's own supplied branding and synthetic UI fixtures. Existing user configuration is not overwritten by the file installer.

Validation: 299 Python tests, 34 model tests, 66 real-process UI cases, four additional publication-privacy regressions, manifest/QML/lint/systemd checks, pinned Falco policy compilation, and isolated reproducible package/install/remove flows passed. Workstation evidence and private build paths are excluded. Independent review, fresh-machine/reboot acceptance, complete dependency/SBOM review, native prevention acceptance and exact-binary privileged live acceptance of the privacy-only KRSI rebuild remain outstanding. This is a beta with bounded detection coverage, not security certification. Privileged/network/AI capabilities warrant maintainer review and manual setup labeling.

### Submission checklist

- [x] The repository is public and contains installation and removal instructions.
- [x] I have documented the plugin license and any external dependencies.
- [x] I confirm that I own or have permission to submit this plugin and its preview assets.
- [x] The plugin does not overwrite user configuration without explicit consent.
- [x] I understand that approval is for listing and is not a security review.
