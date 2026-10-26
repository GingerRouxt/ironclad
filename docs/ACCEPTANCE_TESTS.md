# Fresh-VM acceptance matrix

Status: prepared, **not executed on a fresh VM**. A container, mocked helper, rule compilation or existing workstation is not a substitute. Use a disposable x86_64 Omarchy Quattro VM or a separate test machine with console access and a pre-install snapshot. Never run the reboot, package/service, kernel-event or removal scenarios on the maintainer's working desktop.

Record UTC time, Omarchy release, kernel, architecture, Python, filesystem, source commit, manifest version, artifact hashes and test result. Use a synthetic account without provider logins, private files or production network access. Capture sanitized evidence only. Every row starts `NOT RUN` until observed; record `FAIL` and exact symptoms instead of treating unavailable features as passes.

| ID | Procedure on disposable machine | Acceptance evidence |
|---|---|---|
| VM-01 | Snapshot clean Quattro; record baseline plugin inventory, Ironclad units/packages and listening sockets. Install using the documented Git command after recording upstream commit. | Manifest validates; widget loads without shell configuration replacement or manual desktop restart. No native package, timer, provider call, Core enrollment or telemetry starts from installation alone. |
| VM-02 | With network disabled, run Quick 90, Full 180, Super Scan 420. Exercise Overview, Diagnostics and Software at 1020×700 and smaller supported screen layouts. | Counts match profiles; unavailable checks remain explicit; controls remain reachable; baseline and reports work. On the proposed fix, completed scans and rescans make zero AI requests. |
| VM-03 | Test missing AI client, then a synthetic client that records calls and returns fixture answers; click Explain and cancel. | No call before explicit action; only intended redacted fields, bounded output and known check IDs; no executable model actions. No real provider login needed. A real provider smoke test is a separate owner-authorized test. |
| VM-04 | Decline sensor setup; then review and authenticate setup from pinned artifact bytes. Compare installed Falco/KRSI hashes and policy with `release-manifest.json` and bundled `build-info.json`. | Decline changes nothing. Accepted setup installs only named package/helper/polkit/unit files. Hash mismatch fails closed. Record authorization caching, engine health and reduced-coverage states. |
| VM-05 | Use `tools/verify_native_protection.py --help`, review source and run its bounded synthetic workload on the VM only. Exercise supported positive, negative and legitimate-administration policy cases. | Actual events reach the bounded feed; unrelated processes survive; known gaps remain explicit. This is exact-binary live acceptance, not attack-recall measurement. Do not change TPM, boot LSM or io_uring configuration merely to make a test pass. |
| VM-06 | Enable alert-only Downloads scanning through explicit setup; use the harmless standard antivirus test fixture, then stop/remove it. Review `tools/verify_onaccess_native.py` before VM use. | Alert without deletion/quarantine; outside-scope file untouched; stale engine and signature errors visible. Prevention is a separate opt-in test, never inferred from alert-only success. |
| VM-07 | Enable each optional diagnostic/protection-update timer separately, reboot the VM, inspect unit state and one scheduled execution; disable and reboot again. | Only explicitly selected jobs persist; disabled jobs stay disabled; logs contain no credentials, raw sensitive arguments or document contents. No upload of reports. Capture failures and rollback behavior. |
| VM-08 | Test Git update and copied-archive update separately, with modified/extra files and prior state. Review pending privileged update but decline it. | Git provenance recorded; modified files preserved or safely refused; no silent privileged engine replacement; historical state preserved. Source update alone is not native acceptance. |
| VM-09 | Disable schedules, remove optional native components through reviewed helpers/package transactions, then remove plugin. Reboot. | No owned running process, timer, service, polkit action or helper remains. ClamAV/shared dependencies and unrelated services retained. User reports/history/signatures retained unless separately requested. |
| VM-10 | Repeat copied-install removal with remaining schedule units, broken links, changed files, unsafe receipt and extra files. | Refuses without deleting controls or user data. After safe explicit cleanup, uninstall/reinstall succeeds. |

## Native provenance gate

The shipped KRSI library is a patched local fork, not the unmodified upstream binary. Read its embedded source URLs, SDK commit, patches, Cargo.lock, BPF digest and recorded Rust compiler. Independently reproduce in a credential-free disposable builder with pinned toolchain, public input checksums and locked dependencies; compare artifacts, explain differences and retain licenses. The current recipe's ambient Rust selection is not a reproducibility guarantee. A matching source archive hash does not authenticate its publisher or prove safe live kernel behavior.

The original release is `v0.2.36` / `5b80ec2`; marketplace review is `73e2275`. Test the exact candidate intended for a later release. Never overwrite the original release assets with new bytes under the same tag.

## Result template

```text
Test ID / date UTC:
Machine: disposable VM, synthetic account
Omarchy / kernel / architecture:
Source commit / version / SHA-256:
Command or UI actions:
Expected / observed:
PASS / FAIL / NOT RUN:
Sanitized evidence reference:
Cleanup and reboot outcome:
Remaining limitation:
```

Production services, websites, email, cloud APIs and the maintainer's host are outside this acceptance plan. Do not publish raw workstation logs or snapshots.
