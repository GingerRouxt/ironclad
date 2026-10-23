<p align="center">
  <img src="assets/brand/hero.png" alt="Ironclad — Your machine. Your call. Local-first security for Omarchy." width="100%">
</p>

> **BETA — 0.2.36.** Installable source with explicit coverage limits. Marketplace approval is pending; this is not security certification.

<p align="center">
  <strong>Know what needs attention. Understand why. Choose what happens next.</strong><br>
  A security companion built for the Omarchy desktop.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-96b8ec?style=flat-square&amp;labelColor=151e2d" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/platform-Omarchy-96b8ec?style=flat-square&amp;labelColor=151e2d" alt="Built for Omarchy">
  <img src="https://img.shields.io/badge/status-beta-e7bc79?style=flat-square&amp;labelColor=151e2d" alt="Beta">
</p>

<p align="center">
  <a href="#watch-the-preview">Watch</a> ·
  <a href="#inside-ironclad">Explore</a> ·
  <a href="#see-it-in-action">Screenshots</a> ·
  <a href="#get-ironclad">Release status</a> ·
  <a href="docs/ROADMAP.md">Roadmap</a> ·
  <a href="CONTRIBUTING.md">Contribute</a> ·
  <a href="https://szdsecurity.com/">Zero Day Security ↗</a>
</p>

---

## Security that makes sense on your desktop

Ironclad brings system findings, behavior monitoring, automatic Downloads malware scanning, one-off file scans, software checks, and AI explanations into one desktop panel. Findings come with context and a next step you can review.

**You stay in control.** Review an observation, ignore it when appropriate, or choose a supported action. Ironclad does not automatically delete your files, quarantine applications, or execute AI suggestions.

## Watch the preview

https://github.com/user-attachments/assets/f65ab5a7-105f-4f9a-9671-d90e7fe9a603

A 73-second walkthrough of the development build on the real Omarchy desktop. The film predates this beta; its coming-soon wording describes the preview stage. Current installation instructions are below.

## See it in action

<a href="assets/screenshots/overview.png"><img src="assets/screenshots/overview.png" alt="Ironclad Overview showing a synthetic scan, prioritized findings, and protection status" width="100%"></a>

<p align="center"><sub>The real QML interface, rendered with synthetic fixtures. Example findings and software versions are illustrative; these images do not report a real machine's security state.</sub></p>

<details>
<summary><strong>Open the AI advisor preview</strong></summary>
<br>
<img src="assets/screenshots/advisor.png" alt="Ironclad AI advisor with a distinctly colored example answer and reviewed next steps" width="100%">

The preview uses a fixture response. No AI request was made to create this screenshot.
</details>

## Inside Ironclad

| Surface | What you get |
| :--- | :--- |
| **Overview** | A clear starting point: scan results, protection health, and the next things to review. |
| **Diagnostics** | Quick 90, Full 180, and Super Scan 420: distinct checks with evidence, explicit coverage limits, and Ignore / Restore controls. |
| **Protection** | Falco behavior monitoring, separate automatic Downloads and one-off ClamAV scanning controls, and signature maintenance. |
| **Software** | Supported tool inventory, advisory checks, and reviewed update paths. |
| **AI advisor** | Every selected diagnostic check can receive an explanation, with progress and individual follow-up through your existing supported agent. AI does not execute changes. |
| **Activity** | Local action records and reports. A rescan clears the old display and privately gzip-archives the previous snapshot and completed AI explanations. |

## Local first. Explicit choices.

- **Built around your machine.** Review findings and supported actions from the Omarchy desktop.
- **Optional components are visible.** Monitoring, malware scanning, maintenance, and AI have their own setup and status.
- **AI is optional.** It can use your existing Codex or Claude Code account, subject to that provider's limits. Selected, redacted context is sent to the chosen provider when you request assistance.
- **Evidence before action.** AI answers explain or propose; they do not execute changes on their own.

Local-first does not mean every optional feature is offline. Advisory lookups, protection updates, and AI requests require network access when used.

## Get Ironclad

Requires **Omarchy Quattro, Python 3.12+ and libseccomp**. Native monitoring currently targets **x86_64**. Optional ClamAV, Bubblewrap, polkit and supported agent dependencies are documented in [installation](docs/INSTALL.md).

```sh
omarchy plugin add https://github.com/GingerRouxt/ironclad.git --enable
```

Review optional engines and maintenance in Protection; installing the widget does not enable them. GUI scans request explanations through an available signed-in agent and send bounded redacted findings to its provider. Read [privacy](docs/PRIVACY.md) first.

**Update:** `omarchy plugin update com.zerodaysecurity.ironclad`.

**Remove:** first disable maintenance and remove the optional native components using the [removal instructions](docs/UNINSTALL.md), then run `omarchy plugin remove com.zerodaysecurity.ironclad`. Local user data is retained.

See [test results](TEST_RESULTS.md), [security review scope](SECURITY_REVIEW.md), [license notices](THIRD_PARTY_NOTICES.md) and [release process](docs/RELEASING.md). Fresh-machine/reboot testing and independent review remain outstanding.

## What protection means here

Ironclad combines focused checks and optional detection engines. It is not a guarantee that a machine is malware-free. Behavior rules cover selected activity. Automatic scanning shown in the development build scans and alerts on accessed files inside Downloads; it does not block or delete files in that mode. One-off scans cover the file you choose. Software checks cover supported inventory and available advisory data. Catalog totals include observations and explicit unavailable/not-applicable outcomes; they are not a security score. A missing or unhealthy engine must be treated as a coverage gap.

Read the [security policy](SECURITY.md) for reporting guidance. Learn about the underlying tools in the official [Falco documentation](https://falco.org/docs/) and [ClamAV documentation](https://docs.clamav.net/).

## Built with the community

Useful bug reports, clear documentation, accessible UI feedback, and reproducible test cases all help. Start with [contributing](CONTRIBUTING.md).

## From Zero Day Security

<p align="center">
  <img src="assets/brand/saint-zero-day.png" alt="Saint Zero Day facing forward, with a cyan halo and illuminated armor" width="280">
  &nbsp;
  <img src="assets/brand/saint-zero-day-gold.png" alt="Saint Zero Day with a gold halo, cyan armor, and SaintZeroDay lettering" width="280">
</p>

<p align="center"><strong>SAINT ZERO DAY</strong><br>Your machine. Your call.<br><br><a href="https://szdsecurity.com/"><strong>Visit Zero Day Security — szdsecurity.com ↗</strong></a></p>

Ironclad is a Zero Day Security project, built for Omarchy. Saint Zero Day is the character behind the brand.

Built on the work of the [Omarchy](https://omarchy.org/) community, with behavior monitoring from [Falco](https://falco.org/) and malware scanning from [ClamAV](https://www.clamav.net/).

---

<p align="center"><strong>IRONCLAD</strong><br><sub>Your machine. Your call. · <a href="LICENSE">MIT licensed</a></sub></p>
