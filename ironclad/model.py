"""Bounded, typed result contract and conservative shareable-text policy."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import getpass
import ipaddress
import json
import os
import re
import socket

STATES = {"pass", "attention", "critical", "unavailable", "error", "not_applicable", "observed"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


def now():
    return datetime.now(timezone.utc).isoformat()


def redact(value):
    text = str(value)[:16384]
    for identity in (os.path.expanduser("~"), socket.gethostname(), getpass.getuser()):
        if identity and len(identity) > 1:
            text = text.replace(identity, "[private]")
    text = re.sub(r"(?i)(token|password|secret|api[_-]?key|authorization)\s*[:=]\s*\S+", r"\1=[redacted]", text)
    text = re.sub(r"/(?:home|mnt|media|run/media)/[^\s,;]*", "[path]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[ip]", text)
    # Address-like tokens; do not retain scoped IPv6 identifiers.
    def ipv6(match):
        token = match.group(0)
        try:
            ipaddress.ip_address(token.split('%')[0])
            return "[ip]"
        except ValueError:
            return token
    text = re.sub(r"[0-9a-fA-F]*:[0-9a-fA-F:%._-]+", ipv6, text)
    text = "".join(c if c in '\n\t' or ord(c) >= 32 else '�' for c in text)
    return text[:2048]


@dataclass
class Evidence:
    source: str
    value: str
    observed_at: str = field(default_factory=now)


@dataclass
class Check:
    check_id: str
    status: str
    severity: str
    summary: str
    evidence: list[Evidence]
    confidence: str = "high"
    permissions: list[str] = field(default_factory=lambda: ["unprivileged"])
    remediation_action_ids: list[str] = field(default_factory=list)
    documentation_url: str | None = None
    collector_version: str = "1"
    elapsed_ms: float = 0
    dependency_status: str = "available"
    score: None = None
    recommendation: str = "Review the evidence in platform context; no automatic changes."
    reversibility: str = "Read-only observation; no host changes."
    remediation_steps: list[str] = field(default_factory=list)
    verification: str = ""

    def __post_init__(self):
        if not re.fullmatch(r"[a-z][a-z0-9_.]{1,100}", self.check_id):
            raise ValueError("invalid check id")
        if self.status not in STATES or self.severity not in SEVERITIES:
            raise ValueError("invalid classification")
        if self.confidence not in {"high", "medium", "low"}:
            raise ValueError("invalid confidence")
        self.summary = redact(self.summary)
        self.recommendation = redact(self.recommendation)
        self.evidence = [Evidence(redact(e.source), redact(e.value), e.observed_at) for e in self.evidence[:16]]
        if not self.remediation_steps:
            from .guidance import instructions
            self.remediation_steps, default_verification = instructions(self.check_id, self.status)
            self.verification = self.verification or default_verification
        if not isinstance(self.remediation_steps, list) or len(self.remediation_steps) > 5 or any(not isinstance(s, str) or len(s) > 512 for s in self.remediation_steps) or not isinstance(self.verification, str) or len(self.verification) > 512:
            raise ValueError('invalid remediation guidance')
        self.remediation_steps = [redact(s) for s in self.remediation_steps]
        self.verification = redact(self.verification)

    def dict(self):
        return asdict(self)


def validate_scan(scan):
    """Reject malformed cached data without exposing raw values in exceptions."""
    try:
        if not isinstance(scan, dict) or scan.get("schema_version") != "1.0":
            raise ValueError("unsupported schema")
        from uuid import UUID
        UUID(scan["scan_id"])
        if datetime.fromisoformat(scan["collected_at"]).tzinfo is None:
            raise ValueError("timestamp timezone required")
        if not isinstance(scan.get("host"), dict) or not isinstance(scan.get("checks"), list) or len(scan["checks"]) > 512:
            raise ValueError("invalid result bounds")
        ids = set()
        for c in scan["checks"]:
            if not isinstance(c, dict) or not isinstance(c.get("check_id"), str) or c["check_id"] in ids:
                raise ValueError("duplicate or invalid check")
            ids.add(c["check_id"])
            if not isinstance(c['summary'], str) or len(c['summary']) > 2048 or not isinstance(c['evidence'], list) or len(c['evidence']) > 16:
                raise ValueError("invalid field bounds")
            for e in c['evidence']:
                if not isinstance(e, dict) or any(not isinstance(e[k], str) or len(e[k]) > 2048 for k in ('source','value','observed_at')):
                    raise ValueError("invalid evidence")
                if datetime.fromisoformat(e['observed_at']).tzinfo is None:
                    raise ValueError("invalid evidence timestamp")
            if c.get('documentation_url') is not None and (not isinstance(c['documentation_url'],str) or not c['documentation_url'].startswith('https://')):
                raise ValueError('unsupported documentation URL')
            for name in ('permissions', 'remediation_action_ids'):
                if not isinstance(c[name], list) or len(c[name]) > 16 or any(not isinstance(v,str) or len(v)>128 for v in c[name]):
                    raise ValueError('invalid contract list')
            if not isinstance(c['elapsed_ms'], (int,float)) or not 0 <= c['elapsed_ms'] <= 60000:
                raise ValueError('invalid duration')
            Check(**{**c, "evidence": [Evidence(**e) for e in c["evidence"]]})
        if len(json.dumps(scan, allow_nan=False).encode()) > 2097152:
            raise ValueError("result too large")
        return scan
    except (KeyError, TypeError, AttributeError, OverflowError):
        raise ValueError("invalid scan contract") from None
