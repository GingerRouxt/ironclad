# AI explanations

Ironclad uses an existing signed-in Codex or Claude Code CLI. No new provider key, browser login extraction, model download or Ironclad account is required. The client handles its own authentication. Detection exposes availability, not account identity.

The GUI requests explanations for every selected Quick 90, Full 180 or Super Scan 420 check, with risk-priority ordering, incremental progress and per-check follow-up. Responses must match the current scan and known check IDs. Missing or failed responses stay explicitly incomplete. New scans archive the old snapshot and completed answers locally and clear the display before starting.

Bounded redacted context and questions travel through stdin, not command arguments. CLI brief preparation is offline. GUI explanation and Ask agent actions send that context through the signed-in client's provider. Account limits and provider retention policies apply. Unknown private text cannot be universally redacted.

Adapters restrict tools, extensions, execution, session persistence and network search where supported. Codex runs in an ephemeral read-only session; Claude uses restricted mode and empty tools/MCP. Enterprise client policies may differ. These flags are not OS isolation from a compromised client.

Answers are plain text and cannot authorize repairs, updates or rules. Reviewed action executors accept only fixed registered operations with independent user approval. Official Falco/ClamAV references and the exact bundled rule policy help explain coverage; they are reviewed bundled references, not live web browsing. Custom rules remain drafts for review.

Cancellation targets only the owned request. Temporary inputs and outputs are private and bounded. Provider-side processing may take time to stop. See [privacy](PRIVACY.md).
