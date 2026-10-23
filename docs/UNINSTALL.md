# Remove Ironclad

Before removing the controls:

1. Turn off automatic protection updates in Protection.
2. Stop automatic malware scanning, review the action, and authenticate. Remove the separately installed `ironclad-antimalware` package through your package manager after reviewing the transaction.
3. Use Protection to remove the native sensor and authenticate the scoped removal.
4. Disable any optional diagnostic schedule you enabled.

For git-managed installations:

```sh
omarchy plugin remove com.zerodaysecurity.ironclad
```

For a copied archive installation, preview `sh packaging/uninstall.sh --dry-run`, then use `--apply`. The file uninstaller refuses modified files, extra files, unsafe links, and remaining native components or maintenance units. Preserve and review a refused installation; do not force recursive deletion.

User scan history, gzip archives, action receipts, exported reports, signatures, and detection records are retained. ClamAV is a separate shared package and is not automatically removed. Deleting retained data is a separate user decision.
