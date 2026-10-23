# Privacy

Normal diagnostic scans are local, bounded, read-only and unprivileged. They read system metadata and fixed security controls, not user documents, credentials, process arguments, browser profiles or application databases. The engine blocks new Internet sockets with a process-local libseccomp guard; this is not a full sandbox.

There is no telemetry, analytics, registration, crash uploader or automatic report submission. Reports redact common identifiers, escape HTML and use private files. Unknown private strings cannot be universally recognized: review reports before sharing them.

## AI and network use

Completed GUI scans automatically request explanations for all selected checks through an available signed-in Codex or Claude Code client. Questions and bounded, redacted findings go to that provider. Provider account limits, charges, retention and processing policies apply. Stop AI cancels the local request; remote processing may take time to stop. CLI diagnostics do not invoke AI. The AI has no authority to approve or execute actions. One-off file contents, selected paths, detection feeds and private action history are excluded from AI context.

Software/advisory refresh is an explicit network action. Supported package names and versions are sent to OSV; configured tool sources and the public CISA catalog are queried. Optional protection setup and maintenance download official engines, signatures and release metadata. Installation alone enables none of these recurring jobs.

## Local storage and sensors

Ignore/Restore preferences, scans, action receipts and reports stay local. Every new GUI scan privately gzip-archives the previous snapshot and completed explanations before clearing it, even when optional saved history is off. Archives are not automatically pruned or uploaded. An archive failure blocks the new scan and preserves the previous snapshot for retry.

Falco inspects system-wide kernel activity and may internally observe arguments. Ironclad retains a bounded local feed with known rule category, severity, time, application basename and event type, without raw arguments, full paths or file contents. Automatic ClamAV inspects accessed Downloads files locally; its detection feed includes a filename and detection name. Acknowledgment does not clean or delete a file.

Same-user, root and kernel compromise remain outside the privacy boundary. See [threat model](THREAT_MODEL.md), [automatic scanning](AUTOMATIC_MALWARE.md) and [AI integration](AI_INTEGRATION.md).
