#!/usr/bin/env python3
"""Check publishable files and nested tar archives without printing matched data."""
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
DENIED = {'.env', '.local-evidence', '.venv', '__pycache__', 'MASTER_SPEC.md',
          'HANDOFF_NEXT.md', 'AGENTS.md', 'SECURITY_AUDIT_2026-10-22.md'}
PATTERNS = {
    'private-key': rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    'github-token': rb'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}',
    'aws-access-key': rb'AKIA[A-Z0-9]{16}',
    'provider-key': rb'(?<![A-Za-z0-9_-])sk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}',
}


def inspect(name, body, private_paths=(), depth=0):
    findings = []
    parts = Path(name).parts
    if any(part in DENIED or part.startswith('.env.') for part in parts):
        findings.append((name, 'excluded-file'))
    for label, pattern in PATTERNS.items():
        if re.search(pattern, body):
            findings.append((name, label))
    if any(value and value in body for value in private_paths):
        findings.append((name, 'private-path'))
    if name.endswith(('.tar.gz', '.tgz')):
        if depth >= 3:
            return findings + [(name, 'archive-depth')]
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
                total = 0
                for index, member in enumerate(archive):
                    total += member.size
                    if index >= 20000 or total > 134217728 or not member.isfile():
                        return findings + [(name, 'unsafe-archive')]
                    if member.uname or member.gname or member.name.startswith('/') or '..' in Path(member.name).parts:
                        findings.append((name, 'archive-metadata'))
                    findings.extend(inspect(name + '/' + member.name,
                                            archive.extractfile(member).read(), private_paths, depth + 1))
        except (tarfile.TarError, OSError):
            findings.append((name, 'invalid-archive'))
    return findings


def main():
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().split('\0')
    findings = []
    names = sorted(set(filter(None, names)))
    private_paths = (str(Path.home()).encode(), str(ROOT).encode())
    for name in names:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            findings.append((name, 'unsafe-file'))
        else:
            findings.extend(inspect(name, path.read_bytes(), private_paths))
    print(json.dumps({'passed': not findings, 'files': len(names), 'findings': findings,
                      'scope': 'Pattern and path checks; not universal secret detection.'}))
    return int(bool(findings))


if __name__ == '__main__':
    raise SystemExit(main())
