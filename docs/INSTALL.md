# Install Ironclad beta

Requires Omarchy Quattro, Python 3.12 or newer, and Linux libseccomp. The native Falco/KRSI component currently targets x86_64. Other platforms have not passed native acceptance.

```sh
omarchy plugin add https://github.com/GingerRouxt/ironclad.git --enable
```

Installation adds the user plugin. It does not enable privileged detection engines or recurring downloads. Open Ironclad from the bar and choose Quick 90, Full 180, or Super Scan 420. The GUI automatically requests explanations through an available signed-in Codex or Claude Code client; provider limits and processing policies apply. See [privacy](PRIVACY.md).

Optional dependencies: ClamAV for malware scanning, Bubblewrap for mandatory one-off scan isolation, polkit and Arch package tools for reviewed privileged setup, and a supported signed-in AI CLI for explanations. Falco is downloaded from its official publisher only after explicit monitoring setup; a pinned KRSI library is bundled with its notices. Missing requirements are reported, not silently installed.

Use Protection to review and authenticate each optional component. Downloads alert-only scanning and prevention are separate modes. Prevention has fixture coverage but has not passed live prevention acceptance. Check actual engine health after setup.

Update a git-managed installation:

```sh
omarchy plugin update com.zerodaysecurity.ironclad
```

Updates follow the repository branch. Plugin updates do not silently replace root components. Review any separate sensor update in Protection. Existing copied development installs are not git-managed; preserve the plugin folder and state before a deliberate migration. Do not overwrite shell configuration or restart the desktop to install this plugin.

An alternative archive install uses `sh packaging/install.sh --dry-run`, then `--apply`. It refuses an existing destination and creates only owned plugin files. Enable that copied plugin separately with the Omarchy plugin manager. See [removal](UNINSTALL.md).
