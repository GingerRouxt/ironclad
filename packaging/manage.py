#!/usr/bin/python3
"""Reviewed user-owned file installation; no packages, services or shell mutation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from ironclad.storage import open_dir, private_dir

ID = 'com.zerodaysecurity.ironclad'
FILES = ['zds-ironclad', 'companion.py', 'packaging/manage.py', 'packaging/install.sh', 'packaging/uninstall.sh', 'ui0237/State.js', 'ui0237/Design.js', 'ui0237/NavIcon.qml', 'ui0237/BodyText.qml', 'ui0237/ControlButton.qml', 'ui0237/Dashboard.qml', 'ui0237/Workspace.qml', 'ui0237/Protection.qml', 'ui0237/Monitoring.qml', 'ui0237/AutomaticMalware.qml', 'ui0237/Overview.qml', 'ironclad/FALCO-LICENSE', 'ironclad/krsi-component.tar.gz', 'ironclad/falcoctl-component.tar.gz', 'manifest.json', 'BarWidget.qml', 'Panel.qml', 'engine.py', 'README.md', 'LICENSE', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md', 'TEST_RESULTS.md', 'SECURITY_REVIEW.md']
FILES += ['ironclad/'+p.name for p in sorted((SOURCE/'ironclad').glob('*.py'))]
FILES += ['POST_LAUNCH_STATUS.md', 'CONTRIBUTING.md']
FILES += ['docs/'+name for name in ('INSTALL.md', 'CHECK_CATALOG.md', 'AUTOMATIC_MALWARE.md', 'UNINSTALL.md', 'PRIVACY.md', 'PROTECTION_UPDATES.md', 'FALCO_RULE_UPDATES.md', 'FALCO_DOWNLOADER_BUILD.md', 'DETECTION_COVERAGE.md', 'RELEASING.md', 'FEATURES.md', 'ARCHITECTURE.md', 'THREAT_MODEL.md', 'RULES.md', 'AI_INTEGRATION.md', 'BUSINESS.md', 'ACCEPTANCE_TESTS.md', 'RELEASE_CHECKLIST.md', 'CONTRIBUTOR_TESTING.md', 'CORE_INTERFACE_PROPOSAL.md', 'LANDING_PAGE_BRIEF.md', 'SUPPLY_CHAIN_REVIEW.md', 'NATIVE_BUILD.md')]
FILES += ['docs/'+name for name in ('ROADMAP.md', 'LAUNCH_ANNOUNCEMENT.md', 'ironclad-build-inventory.cdx.json', 'dependency-advisories.json')]


def digest(data): return hashlib.sha256(data).hexdigest()


def payload():
    data = {}
    for name in FILES:
        p = SOURCE/name
        if p.is_symlink() or not p.is_file(): raise ValueError('missing or unsafe source payload')
        data[name] = p.read_bytes()
    return data


def target_path(root): return Path(root)/'omarchy/plugins'/ID


def install(root):
    data = payload()
    parent = target_path(root).parent
    parentfd = open_dir(parent, create=True)
    info = os.fstat(parentfd)
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        os.close(parentfd)
        raise ValueError('plugin parent must be owned by caller and not group/world writable')
    destfd = None
    try:
        # Exclusive directory creation: never overwrite an existing plugin.
        os.mkdir(ID, 0o700, dir_fd=parentfd)
        destfd = os.open(ID, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parentfd)
        for directory in ('ironclad', 'docs', 'ui0237', 'packaging'):
            os.mkdir(directory,0o700,dir_fd=destfd)
        for name, body in data.items():
            parts=name.split('/')
            fd=destfd
            if len(parts)==2: fd=os.open(parts[0],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=destfd)
            try:
                filefd=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700 if name == 'zds-ironclad' else 0o600,dir_fd=fd)
                with os.fdopen(filefd,'wb') as f: f.write(body)
            finally:
                if fd!=destfd: os.close(fd)
        receipt={'schema':1,'id':ID,'files':{name:digest(body) for name,body in data.items()}}
        filefd=os.open('.ironclad-install.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=destfd)
        with os.fdopen(filefd,'w') as f: json.dump(receipt,f)
    finally:
        if destfd is not None: os.close(destfd)
        os.close(parentfd)
    return target_path(root)


def remove(root):
    if Path(root)==Path.home()/'.config':
        if Path('/usr/lib/ironclad/antimalware-helper').exists():
            raise ValueError('remove the automatic malware component before removing its controls')
        from ironclad.protection_updates import UNITS, unit_directory
        if any((unit_directory()/name).exists() or (unit_directory()/name).is_symlink() for name in UNITS):
            raise ValueError('turn off automatic protection updates in Protection before removing the plugin')
        from ironclad import scheduling
        if any((scheduling.unit_directory()/name).exists() or (scheduling.unit_directory()/name).is_symlink() for name in scheduling.UNITS):
            raise ValueError('disable the diagnostic schedule and remove its owned units before removing the plugin')
    dest=target_path(root)
    if Path(root)==Path.home()/'.config' and Path('/usr/lib/ironclad/sensor-helper').exists():
        raise ValueError('remove the embedded sensor through Protection before removing its controls')
    destfd=private_dir(dest)
    try:
        receiptfd=os.open('.ironclad-install.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=destfd)
        with os.fdopen(receiptfd) as f: receipt=json.loads(f.read(65536))
        if receipt.get('schema')!=1 or receipt.get('id')!=ID or not isinstance(receipt.get('files'),dict): raise ValueError('invalid receipt')
        # Strict names from installed source allowlist; modified, extra and linked files stop removal.
        if set(receipt['files'])!=set(FILES): raise ValueError('unexpected inventory')
        expected=set(FILES)|{'.ironclad-install.json'}
        actual=set()
        for p in dest.rglob('*'):
            if p.is_symlink(): raise ValueError('symlink in installation')
            if p.is_file(): actual.add(p.relative_to(dest).as_posix())
            elif p.relative_to(dest).as_posix() not in {'ironclad','docs','ui0237','packaging'}: raise ValueError('unexpected directory')
        if actual!=expected: raise ValueError('installation contains user additions; preserve and review')
        for name in FILES:
            p=dest/name
            meta=p.stat()
            if meta.st_uid!=os.getuid() or meta.st_nlink!=1 or digest(p.read_bytes())!=receipt['files'][name]:
                raise ValueError('modified installation; preserve and review')
        # All files are in owner-only directories. Same-UID malicious actors are outside this boundary.
        for name in FILES: (dest/name).unlink()
        (dest/'.ironclad-install.json').unlink()
        for directory in ('ironclad','docs','ui0237','packaging'): (dest/directory).rmdir()
    finally: os.close(destfd)
    dest.rmdir()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path.home()/'.config',help='configuration root; use a temporary path for fixture tests')
    p.add_argument('--apply',action='store_true',help='explicitly perform the printed local file operation')
    p.add_argument('--remove',action='store_true')
    p.add_argument('--dry-run',action='store_true')
    a=p.parse_args()
    print(('Remove owned unchanged files from ' if a.remove else 'Install files only to ')+str(target_path(a.root)))
    print('No shell enablement, packages, service changes or user data removal. Existing destinations refused.')
    if not a.apply or a.dry_run: return 0
    if os.geteuid()==0: raise ValueError('unprivileged user required')
    remove(a.root) if a.remove else install(a.root)
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,ValueError):
        print('Installation operation refused or incomplete; preserve destination and inspect docs. No automatic cleanup.',file=sys.stderr)
        raise SystemExit(2)
