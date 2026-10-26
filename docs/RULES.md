# Overview, detection coverage and release preparation

Current status: 0.2.36 is published; the marketplace verified snapshot `73e2275` on October 25, 2026. The following implementation notes originated with 0.2.24 and describe the retained design, not a pending publication.

Overview is now a separate compact status/action page; Diagnostics retains full
findings, filters, explanations, Ignore/Restore and evidence. Overview shows
monitoring, signature age and maintenance warnings, plus at most three unignored
findings ranked by severity; review clears stale filters and opens exact details.

The custom Falco policy expands from five to eight categories: user startup,
audit-policy and local account-database write-opens join the existing categories.
Normal administration is explicitly identified as a possible cause. No new
automatic blocking, retained sensitive fields or generated-rule installation.
Behavior matrices and pinned-engine compilation are separate validation gates;
coverage limitations are documented in docs/DETECTION_COVERAGE.md.

README now describes the prepared public install/update/removal path. Candidate
builder emits a deterministic archive, checksum and manifest with source dirty
state and component pins, refusing conflicts. Pinned-action CI builds review
artifacts only; it does not publish. Source and release 0.2.36 are public, and
marketplace review is complete for its exact snapshot. See docs/RELEASING.md.

# Deterministic rules and false-positive boundaries

ASLR full randomization: proc value 2. CPU advisory: 1-minute load > 1.5 *
logical processors (load includes waiting tasks, not pure CPU utilization).
Available memory advisory: MemAvailable <10% of MemTotal; no cache subtraction.
Root filesystem attention: available blocks <10% or free inodes <5%; critical
space: <3%. Btrfs inode totals may be unavailable and are not division-by-zero.
World-writable home: mode & 0002; ACLs are not evaluated and other home modes
are not classified as unsafe by policy. Home action only removes that bit.
Wildcard sockets: low-severity review, not internet reachability. Failed unit
counts: review context, never auto-disable essential Omarchy services. Docker
group membership: medium advisory for host-level authority, not compromise.
Setuid presence and deleted executables are inventory facts; legitimate package
upgrades/default tools are not automatically marked malware. Foreign packages
are absent from configured sync DBs; this does not prove AUR origin or risk.
Kernel ptrace/log restrictions have developer tradeoffs, no automatic tuning.
Missing data, permissions or tools produce unavailable with low confidence.
No CVEs are manufactured, and no trustworthy-feed freshness is inferred.
