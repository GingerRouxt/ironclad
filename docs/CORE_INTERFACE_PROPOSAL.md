# Optional future ZDS Core integration — design only

No connector, daemon, enrollment, endpoint, automatic upload or remote-control path is implemented or authorized here. Core API availability has not been verified. Community Ironclad remains free, independent and fully usable without Core.

## Existing local boundary

`engine.py report --format json --output PATH` exports the existing diagnostic model from local state; inspect CLI help for `--state`. `ironclad/model.py` defines schema version `1.0`, check IDs, status, severity, confidence and evidence; `ironclad/reports.py` serializes reports and `storage.export` writes private files. Redaction is best effort. Existing full reports can contain context unsuitable for fleet transfer; do not treat them as automatically approved uploads. AI responses and commands are not a fleet action interface.

## Proposed first interface: owner-reviewed file import

Prefer a user-created, inspected file imported manually into Core. A future adapter would transform selected checks into a separately versioned envelope, not upload the current report wholesale:

```json
{
  "schema": "zds.ironclad.fleet-summary/1",
  "product_version": "example",
  "source_revision": "reviewed revision",
  "observed_at": "2026-10-25T00:00:00Z",
  "asset_alias": "owner-chosen non-identifying alias",
  "profile": "quick",
  "checks": [{"check_id": "example.check", "status": "unavailable", "severity": "info", "confidence": "low"}],
  "coverage_limits": ["example: native sensor not enabled"]
}
```

This is an illustrative proposed contract, not a current export format. Define bounded size/count, UTF-8 normalization, closed field/type/status allowlists, schema-version rejection, duplicate/stale import behavior and tenant binding before implementation. Include unavailable/error outcomes rather than converting absence to passing. Exclude usernames, hostname, IP/MAC addresses, raw paths/arguments, file contents, evidence text, AI prompts/answers, credentials and local receipts by default. An asset alias is owner-selected; never derive a persistent machine identifier silently.

## If transport is later explicitly approved

Specify an authenticated, tenant-scoped HTTPS import endpoint in a separate Core design review. No real endpoint is promised by this document. Use least-privilege, import-only credentials stored outside source; disclose exact data, destination, purpose, retention and provider before opt-in. Add manual preview, bounded retries, offline queue limits, visible last-send state, revocation and deletion semantics. No background schedule or startup unit by default. Opt-out must stop future sends and explain that remote deletion is a distinct operation.

Core input is untrusted. It must not inherit shell, filesystem, network, secrets or approval authority on the desktop. A future action protocol would need a typed default-deny allowlist, locally regenerated plan digest, freshness and explicit local review; model text or remote scripts never qualify. No command execution, remote policy installation or self-update is included in the proposed import-only design.

## Gates before any implementation

1. Explicit owner authorization for the exact integration and data flow.
2. Reviewed schema and migration/version contract, supported Core endpoint and tenant authorization tests.
3. Threat model for cross-tenant access, replay, forged/stale records, parser limits, leakage and credential rotation.
4. Contract tests using synthetic files and an isolated local service; no production credentials.
5. Privacy/retention/deletion and licensing review; confirm the community edition remains free with no mandatory account.
6. Separate reviewed PR and separate deployment approval. No cloud agent or telemetry may be inferred from this proposal.
