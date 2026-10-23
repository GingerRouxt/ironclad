# Architecture

The root manifest loads `ui0236/Dashboard.qml` inside the existing Omarchy shell. The Python standard-library engine runs as a bounded, unprivileged child. The companion handles explicit networking, AI and reviewed action workflows separately from offline collectors.

The diagnostic catalog defines 90/180/420 nested profiles with stable IDs. Outcomes distinguish observed, unavailable and not applicable from security passes. Storage uses private directories, directory-fd validation, locks and atomic writes. Reports escape untrusted text.

Optional privileged components use narrow authenticated helpers and separate namespaced services. Falco/KRSI provides selected behavior detections; ClamAV provides separate Downloads and one-off scans. One-off scans require Bubblewrap isolation and sealed input. Root components are not automatically installed with the widget.

AI outputs never enter executable action paths. User-approved actions use fixed plans, expiry, revalidation and receipts. No runtime dependency on ZDS Core or private business services exists. See [threat model](THREAT_MODEL.md) and [coverage](DETECTION_COVERAGE.md).
