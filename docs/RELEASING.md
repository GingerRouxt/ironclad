# Release process

Use mise for pinned runtimes and uv for Python. Run the complete verifier with a PySide6 interpreter, inspect coverage and test limits, and review the exact files intended for publication. Never publish local evidence, credentials, personal machine reports or private development history, including to private repositories.

```sh
mise exec -- uv run --offline python tools/verify.py --ui-python /path/to/ui-python
mise exec -- uv run --offline python tools/prepare_release.py --require-clean --tag v0.2.36 --output dist/candidate
```

The builder uses a strict runtime allowlist and deterministic archives. The candidate includes the archive, SHA-256 sidecar and release manifest tied to a clean source commit. Checksums establish expected bytes, not signed provenance or security certification.

Native rebuilds must remap both source and dependency-cache paths, reject private path strings, retain third-party notices, and update the pinned archive/library hashes. Policy compilation is unprivileged; live kernel and service acceptance is separate and must never be inferred from compilation.

Publish beta limitations honestly. Fresh-machine/reboot acceptance, independent review and complete static dependency/SBOM review remain outstanding. Do not upload private evidence to demonstrate tests. Keep a sanitized summary instead.

Marketplace submission follows the [official publishing guide](https://plugins.omarchy.org/publish.html). Listing needs maintainer approval and is not a security certification. Git updates follow the default branch and do not silently upgrade privileged components. See [install](INSTALL.md) and [remove](UNINSTALL.md).
