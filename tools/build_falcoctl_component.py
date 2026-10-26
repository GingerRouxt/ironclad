#!/usr/bin/env python3
"""Rebuild the pinned rules-only downloader in an isolated, credential-free workspace."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_URL = 'https://codeload.github.com/falcosecurity/falcoctl/tar.gz/refs/tags/v0.14.2'
SOURCE_SHA = '2ac3bd90913933e7fb6f9a722e1b8999dedaaab158c1ea073405d28c491112c1'
VERSION = '0.14.2-ironclad.1'
GO_VERSION = 'go1.27.3'
BUILD_DATE = '2026-10-26T00:00:00Z'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--work-directory', type=Path, required=True)
    parser.add_argument('--go-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fetch-dependencies', action='store_true', help='Allow public module downloads; builds remain offline')
    args = parser.parse_args()
    body = args.source_archive.read_bytes()
    if sha(body) != SOURCE_SHA:
        raise ValueError('upstream source digest mismatch')
    work = args.work_directory.resolve()
    work.mkdir(parents=True, exist_ok=True)
    source = work / 'source'
    source.mkdir()  # Never overwrite a previous build or run imported setup scripts.
    with tarfile.open(fileobj=io.BytesIO(body)) as archive:
        total = 0
        for entry in archive:
            parts = Path(entry.name).parts
            total += entry.size
            if not parts or parts[0] != 'falcoctl-0.14.2' or '..' in parts or total > 32 * 1024 * 1024:
                raise ValueError('unsafe source archive')
            if entry.isdir():
                continue
            if not entry.isfile():
                raise ValueError('source links are not permitted')
            dest = source.joinpath(*parts[1:])
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open('xb') as stream:
                stream.write(archive.extractfile(entry).read())
    # This patch is maintained and reviewed in this repository, not fetched instructions.
    subprocess.run(['/usr/bin/patch', '--batch', '--fuzz=0', '-p1', '-i', str(ROOT / 'tools/falcoctl-rules-only.patch')], cwd=source, check=True)
    for name in ('go.mod', 'go.sum'):
        (source / name).write_bytes((ROOT / ('tools/falcoctl-' + name)).read_bytes())
    go = args.go_directory.resolve()
    prefix = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
              '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
              '--ro-bind', str(go), '/toolchain', '--bind', str(work), '/build', '--tmpfs', '/tmp',
              '--proc', '/proc', '--dev', '/dev', '--clearenv', '--setenv', 'PATH', '/toolchain/bin:/usr/bin',
              '--setenv', 'HOME', '/build/home', '--setenv', 'GOPATH', '/build/gopath',
              '--setenv', 'GOMODCACHE', '/build/modcache', '--setenv', 'GOCACHE', '/build/cache',
              '--setenv', 'GOTOOLCHAIN', 'local', '--setenv', 'CGO_ENABLED', '0',
              '--setenv', 'GOMAXPROCS', '2', '--setenv', 'GOFLAGS', '-p=2', '--chdir', '/build/source']

    def run(command, network=False):
        options = []
        if network:
            options += ['--share-net']
            for name in ('/etc/ssl', '/etc/ca-certificates', '/etc/resolv.conf', '/etc/hosts'):
                if Path(name).exists():
                    options += ['--ro-bind', name, name]
        else:
            options += ['--setenv', 'GOPROXY', 'off', '--setenv', 'GOSUMDB', 'off']
        return subprocess.check_output(prefix + options + ['/toolchain/bin/go'] + command, timeout=900)

    if run(['version']).decode().split()[2] != GO_VERSION:
        raise ValueError('use the pinned Go toolchain through mise')
    if args.fetch_dependencies:
        run(['mod', 'download'], network=True)
    run(['mod', 'verify'])
    flags = '-w -buildid= -X github.com/falcosecurity/falcoctl/cmd/version.semVersion=' + VERSION + ' -X github.com/falcosecurity/falcoctl/cmd/version.buildDate=' + BUILD_DATE
    command = ['build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=' + flags]
    run(command + ['-o', '/build/falcoctl', '.'])
    run(command + ['-o', '/build/falcoctl-second', '.'])
    binary = (work / 'falcoctl').read_bytes()
    if binary != (work / 'falcoctl-second').read_bytes():
        raise ValueError('repeat build did not reproduce identical bytes')
    build_info = run(['version', '-m', '/build/falcoctl']).decode()
    modules = []
    for line in build_info.splitlines():
        fields = line.split()
        if fields and fields[0] == 'dep':
            modules.append(dict(path=fields[1], version=fields[2], sum=fields[3] if len(fields)>3 else None))
        elif fields and fields[0] == '=>':
            previous=modules.pop()
            modules.append(dict(path=fields[1], version=fields[2], sum=fields[3], replaces=previous))
    contents = {'falcoctl': binary, 'go-build-info.txt': build_info.encode(),
                'go.mod': (source / 'go.mod').read_bytes(), 'go.sum': (source / 'go.sum').read_bytes(),
                'ironclad.patch': (ROOT / 'tools/falcoctl-rules-only.patch').read_bytes(),
                'licenses/falcoctl/LICENSE': (source / 'LICENSE').read_bytes()}
    # Include license/notice files from each module recorded in the binary.
    missing = []
    for module in modules:
        escaped = ''.join('!' + c.lower() if c.isupper() else c for c in module['path'])
        folder = work / 'modcache' / (escaped + '@' + module['version'])
        notices = [p for p in folder.rglob('*') if p.is_file() and not p.is_symlink()
                   and p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS', 'PATENTS'))]
        if not notices:
            missing.append(module['path'])
        for notice in sorted(notices):
            value = notice.read_bytes()
            if len(value) > 1024 * 1024:
                raise ValueError('oversized license')
            contents['licenses/' + module['path'] + '@' + module['version'] + '/' + notice.relative_to(folder).as_posix()] = value
    contents['licenses/Go/LICENSE'] = (go / 'LICENSE').read_bytes()
    info = dict(version=VERSION, source_url=SOURCE_URL, source_sha256=SOURCE_SHA,
                toolchain=GO_VERSION, binary_sha256=sha(binary), modules=modules,
                missing_module_notices=missing, repeated_build_identical=True,
                inputs={name: sha(contents[name]) for name in ('go.mod', 'go.sum', 'ironclad.patch')})
    contents['build-info.json'] = (json.dumps(info, sort_keys=True, indent=2) + '\n').encode()
    with args.output.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w') as archive:
        for name, value in sorted(contents.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(value)
            entry.mode = 0o755 if name == 'falcoctl' else 0o644
            archive.addfile(entry, io.BytesIO(value))
    print(json.dumps(dict(binary_sha256=sha(binary), archive_sha256=sha(args.output.read_bytes()), modules=len(modules), missing_module_notices=missing), sort_keys=True))


if __name__ == '__main__':
    main()
