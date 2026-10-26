# Release process

Follow the [step-by-step release checklist](RELEASE_CHECKLIST.md), [VM acceptance matrix](ACCEPTANCE_TESTS.md) and [current evidence](../POST_LAUNCH_STATUS.md). Published 0.2.36 assets are immutable; post-launch fixes require a new reviewed release, not replacement under the existing tag.

Use mise for pinned runtimes and uv for Python. Run the complete verifier with a PySide6 interpreter, inspect coverage and test limits, and review the exact files intended for publication. Never publish local evidence, credentials, personal machine reports or private development history, including to private repositories.

```sh
mise exec -- uv run --offline python tools/verify.py --ui-python /path/to/ui-python
mise exec -- uv run --offline python tools/prepare_release.py --require-clean --output dist/candidate
```

The builder uses a strict runtime allowlist and deterministic archives. The candidate includes the archive, SHA-256 sidecar and release manifest tied to a clean source commit. Checksums establish expected bytes, not signed provenance or security certification.

Native rebuilds must remap both source and dependency-cache paths, reject private path strings, retain third-party notices, and update the pinned archive/library hashes. Policy compilation is unprivileged; live kernel and service acceptance is separate and must never be inferred from compilation.

Publish beta limitations honestly. Fresh-machine/reboot acceptance, independent review and complete static dependency/SBOM review remain outstanding. Do not upload private evidence to demonstrate tests. Keep a sanitized summary instead.

Marketplace publication and maintainer verification completed October 25, 2026 for `73e2275`. Later revisions require their own review under the [official publishing guide](https://plugins.omarchy.org/publish.html); listing is not security certification. Git updates follow the default branch and do not silently upgrade privileged components. See [install](INSTALL.md) and [remove](UNINSTALL.md).
