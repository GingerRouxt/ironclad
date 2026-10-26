# Install Ironclad beta

Requires Omarchy Quattro, Python 3.12 or newer, and Linux libseccomp. The native Falco/KRSI component currently targets x86_64. Other platforms have not passed native acceptance.

```sh
omarchy plugin add https://github.com/GingerRouxt/ironclad.git --enable
```

Installation adds the user plugin. It does not enable privileged detection engines or recurring downloads. Open Ironclad from the bar and choose Quick 90, Full 180, or Super Scan 420. Published 0.2.36 automatically requests AI explanations through an available signed-in Codex or Claude Code client. The proposed post-launch fix keeps scans local until **Explain all checks** or another explicit AI action; check the installed revision rather than assuming the fix has shipped. Provider limits and processing policies apply. See [privacy](PRIVACY.md).

Optional dependencies: ClamAV for malware scanning, Bubblewrap for mandatory one-off scan isolation, polkit and Arch package tools for reviewed privileged setup, and a supported signed-in AI CLI for explanations. Falco is downloaded from its official publisher only after explicit monitoring setup; a pinned KRSI library is bundled with its notices. Missing requirements are reported, not silently installed.

Use Protection to review and authenticate each optional component. The OS may reuse cached administrator authorization; review the action even when there is no fresh password prompt. Downloads alert-only scanning and prevention are separate modes. Prevention has fixture coverage but has not passed live prevention acceptance. Check actual engine health after setup.

Update a git-managed installation:

```sh
omarchy plugin update com.zerodaysecurity.ironclad
```

Updates follow the repository branch. Plugin updates do not silently replace root components. Review any separate sensor update in Protection. Existing copied development installs are not git-managed; preserve the plugin folder and state before a deliberate migration. Do not overwrite shell configuration. A reboot is not required. If a copied development update still displays old controls after `omarchy-shell shell rescanPlugins`, finish or cancel any authentication operation, then use `omarchy restart shell` to clear the observed QML cache. This briefly reloads the bar and panels; it does not reboot or close your applications. Verify the displayed controls afterward.

An alternative archive install uses `sh packaging/install.sh --dry-run`, then `--apply`. It refuses an existing destination and creates only owned plugin files. Enable that copied plugin separately with the Omarchy plugin manager. See [removal](UNINSTALL.md).

## Optional Falco rule updates — unreleased candidate

On the feature-branch candidate, first review the monitoring component installation
or update in Protection and authenticate it. Monitoring must already be active.
Then open **Protection → Updates → Enable Falco rule updates…** and authenticate
that separate choice. The timer downloads signed official host rules every six
hours, with jitter; an accepted changed generation briefly restarts monitoring.
ClamAV signature consent does not enable this feature. Neither the plugin install
nor the monitoring component install turns this timer on.

To stop future downloads, choose **Turn off Falco rule updates**. Current rules
remain installed; stopping monitoring separately prevents rule activation. Check
both update status and monitoring health. This updates detection rules, not the
Falco engine, the OS or customer files. See [trust and limitations](FALCO_RULE_UPDATES.md)
and [executed acceptance](../POST_LAUNCH_STATUS.md). This candidate has not been
merged, released or covered by the original marketplace verification.

## Record and verify what you installed

The marketplace's October 25 verification covers `73e2275`, while the original `v0.2.36` release archive was built from `5b80ec2`. Git installation follows current upstream; it does not pin the marketplace snapshot. Record the installed Git commit and manifest version. Do not infer maintainer verification of later commits.

For an archive, download the archive, checksum and release manifest from the same [release](https://github.com/GingerRouxt/ironclad/releases/tag/v0.2.36), check `sha256sum -c zds-ironclad-0.2.36.tar.gz.sha256`, and compare the manifest's source commit. A checksum from the same source detects byte differences; it is not an independent signature. Review archive paths and included notices before extraction into a new directory.

Follow [fresh-VM acceptance](ACCEPTANCE_TESTS.md) before relying on optional native behavior. Community Ironclad is free; an external AI account may have its own costs. No Core account, fleet enrollment or telemetry is required.
