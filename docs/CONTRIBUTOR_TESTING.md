# Contributor testing checklist

- Start from the intended branch and read existing tests. State the problem, before/after behavior and affected version. Use synthetic accounts, files and model answers.
- Run Python contracts, JavaScript contracts and publication checks with the commands in [release checklist](RELEASE_CHECKLIST.md). Use mise/uv; no arbitrary dependency install hooks or copied third-party shell payloads.
- UI changes: exercise both real-child-process fixture verifiers at their original window dimensions. Click actual visible controls; do not replace mouse interaction with direct signal calls to conceal clipping. Test long text, unavailable states, decline/cancel, new scan and stale response rejection.
- AI changes: a diagnostic scan/rescan must issue zero provider requests before explicit AI action. Do not put private paths, selected files, secrets or action authority into prompts. Treat outputs as untrusted text; independently authorize typed actions. Provider-client flags are not an OS sandbox against a compromised client.
- Files/install/remove: test changed files, extra files, traversal, symlinks including dangling links, wrong owner, receipt mismatch and remaining units. Preserve user data and shared dependencies; never silently escalate or clean up uncertain files.
- Detection changes: add positive, negative and legitimate-workload cases; compile with the pinned Falco binary. Keep unsupported coverage and event loss explicit. Run real kernel/ClamAV/reboot tests only on a separate disposable system.
- Dependency changes: regenerate and inspect the SBOM, validate checksums and licenses, review new network/privileged surfaces and record vulnerability-query scope. Do not claim every locked crate is linked into the runtime binary.
- Record every executed command, counts, exit status, skips, environment limitations and source revision. Do not copy historical test totals into a new claim.
- Submit a focused PR; do not publish live services, change websites, submit private reports or introduce cloud enrollment/telemetry as part of a contributor test.

For the optional Falco rule updater, use the guarded disposable-VM procedure in
[acceptance tests](ACCEPTANCE_TESTS.md). The downloader's own pinned build recipe
and advisory limitations are in [build provenance](FALCO_DOWNLOADER_BUILD.md).
Local `tools/verify.py` validates the allowlisted release payload, excluding ignored
developer tool caches. The expanded native inventory gives the Python test suite
a 120-second budget. Never relax security assertions merely to meet that budget.
