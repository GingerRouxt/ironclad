#!/usr/bin/env python3
"""Generate a partial CycloneDX source/build inventory offline, without imports or builds."""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_SOURCE = 8 * 1024 * 1024
MAX_EXPANDED = 16 * 1024 * 1024


def sha(body):
    return hashlib.sha256(body).hexdigest()


def read(root, name):
    path = root / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE:
        raise ValueError('unsafe or oversized inventory source: ' + name)
    with path.open('rb') as stream:
        body = stream.read(MAX_SOURCE + 1)
    if len(body) > MAX_SOURCE:
        raise ValueError('oversized inventory source: ' + name)
    return body


def literals(body, names):
    """Read selected assignments as data; never import target Python modules."""
    result = {}
    for node in ast.parse(body).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in names:
                if target.id in result:
                    raise ValueError('duplicate provenance constant')
                result[target.id] = ast.literal_eval(node.value)
    if set(result) != set(names):
        raise ValueError('missing provenance constant')
    return result


def members(body):
    """Read bounded regular members, without extracting native code or links."""
    if len(body) > MAX_SOURCE:
        raise ValueError('native archive too large')
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for entry in archive:
            parts = PurePosixPath(entry.name).parts
            total += entry.size
            if (len(result) >= 512 or not entry.isfile() or entry.size < 0
                    or entry.size > 4 * 1024 * 1024 or total > MAX_EXPANDED
                    or not parts or entry.name.startswith('/') or '..' in parts
                    or entry.name in result or '\\' in entry.name
                    or str(PurePosixPath(entry.name)) != entry.name):
                raise ValueError('unsafe native archive member')
            with archive.extractfile(entry) as stream:
                value = stream.read(entry.size + 1)
            if len(value) != entry.size:
                raise ValueError('native archive size mismatch')
            result[entry.name] = value
    return result


def props(**values):
    return [{'name': 'ironclad:' + name.replace('_', '-'), 'value': str(value)}
            for name, value in sorted(values.items())]


def native_inventory(root):
    pins = literals(read(root, 'ironclad/sensor_policy.py'),
                    {'FALCO_VERSION', 'ARCHIVE_URL', 'ARCHIVE_SHA', 'ENGINE_SHA',
                     'KRSI_VERSION', 'KRSI_ARCHIVE_SHA', 'KRSI_SHA'})
    recipe = literals(read(root, 'tools/build_krsi_component.py'), {'INPUTS', 'BPF_SHA'})
    body = read(root, 'ironclad/krsi-component.tar.gz')
    if sha(body) != pins['KRSI_ARCHIVE_SHA']:
        raise ValueError('native archive pin mismatch')
    files = members(body)
    required = {'libkrsi.so', 'build-info.json', 'Cargo.lock',
                'ironclad.patch', 'aya-obj-aliases.patch'}
    if not required <= files.keys() or any(
            name not in required and not name.startswith('licenses/') for name in files):
        raise ValueError('unexpected native inventory')
    info = json.loads(files['build-info.json'])
    if (info.get('version') != pins['KRSI_VERSION'] or info.get('schema') != '4.5.0'
            or info.get('library_sha256') != pins['KRSI_SHA']
            or sha(files['libkrsi.so']) != pins['KRSI_SHA']
            or info.get('upstream_release') is not False
            or info.get('bpf_sha256') != recipe['BPF_SHA']):
        raise ValueError('native provenance identity mismatch')
    expected_inputs = {name: {'url': value[0], 'sha256': value[1]}
                       for name, value in recipe['INPUTS'].items()}
    if info.get('inputs') != expected_inputs:
        raise ValueError('native source inputs mismatch')
    for embedded, source, digest in (
            ('Cargo.lock', 'tools/krsi-Cargo.lock', 'lock_sha256'),
            ('ironclad.patch', 'tools/krsi-ironclad.patch', 'patch_sha256'),
            ('aya-obj-aliases.patch', 'tools/aya-obj-aliases.patch', 'loader_patch_sha256')):
        if files[embedded] != read(root, source) or sha(files[embedded]) != info.get(digest):
            raise ValueError('embedded provenance differs from source: ' + embedded)
    return pins, info, files


def cargo_inventory(body):
    packages = tomllib.loads(body.decode())['package']
    if len(packages) > 4096:
        raise ValueError('Cargo inventory limit')
    refs = {}
    by_name = {}
    components = []
    for package in packages:
        name, version = package['name'], package['version']
        if not all(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.+-]+', value)
                   for value in (name, version)):
            raise ValueError('invalid Cargo package identity')
        key = (name, version)
        if key in refs:
            raise ValueError('ambiguous Cargo identity')
        registry = package.get('source') == REGISTRY
        if package.get('source') and not registry:
            raise ValueError('unrecognized Cargo source')
        ref = ('cargo-registry:' if registry else 'cargo-local:') + name + '@' + version
        refs[key] = ref
        by_name.setdefault(name, []).append(key)
        item = {'type': 'library', 'bom-ref': ref, 'name': name, 'version': version,
                'properties': props(inventory='locked-build-input; linked runtime membership unknown',
                                    source=REGISTRY if registry else 'local/patched workspace source')}
        if registry:
            checksum = package.get('checksum', '')
            if not isinstance(checksum, str) or not HEX.fullmatch(checksum):
                raise ValueError('registry checksum missing or malformed')
            item['purl'] = 'pkg:cargo/' + quote(name, safe='') + '@' + quote(version, safe='')
            item['hashes'] = [{'alg': 'SHA-256', 'content': checksum}]
            item['properties'] += props(hash_subject='registry crate archive, not linked library')
        else:
            item['properties'] += props(identity='local source; no unmodified registry purl asserted')
        components.append(item)
    dependencies = []
    for package in packages:
        targets = []
        for dependency in package.get('dependencies', []):
            parts = dependency.split()
            if len(parts) == 1 and len(by_name.get(parts[0], [])) == 1:
                key = by_name[parts[0]][0]
            elif len(parts) == 2:
                key = tuple(parts)
            else:
                raise ValueError('unresolved Cargo dependency identity')
            if key not in refs:
                raise ValueError('missing Cargo dependency')
            targets.append(refs[key])
        dependencies.append({'ref': refs[(package['name'], package['version'])],
                             'dependsOn': sorted(set(targets))})
    return components, dependencies


def generate(root=ROOT):
    root = Path(root)
    project = tomllib.loads(read(root, 'pyproject.toml').decode())['project']
    manifest = json.loads(read(root, 'manifest.json'))
    if project['version'] != manifest['version']:
        raise ValueError('project version mismatch')
    if project.get('dependencies') != []:
        raise ValueError('Python runtime dependencies changed; extend inventory before release')
    pins, info, files = native_inventory(root)
    components, dependencies = cargo_inventory(files['Cargo.lock'])
    krsi_versions = [item['version'] for item in components
                     if item['name'] == 'krsi' and item['bom-ref'].startswith('cargo-local:')]
    if len(krsi_versions) != 1:
        raise ValueError('missing or ambiguous local KRSI package')
    native_ref = 'ironclad:bundled-krsi'
    components.append({
        'type': 'library', 'bom-ref': native_ref, 'name': 'KRSI Ironclad fork',
        'version': pins['KRSI_VERSION'],
        'hashes': [{'alg': 'SHA-256', 'content': pins['KRSI_SHA']}],
        'properties': props(inventory='bundled libkrsi.so', archive_sha256=pins['KRSI_ARCHIVE_SHA'],
                            build_info_sha256=sha(files['build-info.json']),
                            cargo_lock_sha256=info['lock_sha256'],
                            toolchain_recorded=info['toolchain'],
                            provenance='self-recorded, not signed or independently reproduced',
                            cargo_package_version=krsi_versions[0] + '; separate from native fork version',
                            notice_files=sum(name.startswith('licenses/') for name in files))})
    components.append({
        'type': 'application', 'bom-ref': 'ironclad:optional-falco', 'name': 'Falco',
        'version': pins['FALCO_VERSION'], 'scope': 'optional',
        'hashes': [{'alg': 'SHA-256', 'content': pins['ENGINE_SHA']}],
        'externalReferences': [{'type': 'distribution', 'url': pins['ARCHIVE_URL']}],
        'properties': props(inventory='optional downloaded engine; not bundled',
                            archive_sha256=pins['ARCHIVE_SHA'],
                            limitations='transitive/native dependency inventory incomplete')})
    controller=literals(read(root,'ironclad/falco_rules.py'),{'FALCOCTL_SHA'})
    components.append({'type':'application','bom-ref':'ironclad:optional-falcoctl','name':'falcoctl',
                       'version':'0.14.2','scope':'optional',
                       'hashes':[{'alg':'SHA-256','content':controller['FALCOCTL_SHA']}],
                       'externalReferences':[{'type':'distribution','url':pins['ARCHIVE_URL']}],
                       'properties':props(inventory='optional pinned rule downloader; extracted from Falco archive',
                                          limitations='Go transitive dependency and license closure incomplete')})
    components.append({'type':'library','bom-ref':'test:PyYAML','name':'PyYAML','version':'6.0.3',
                       'scope':'excluded','purl':'pkg:pypi/pyyaml@6.0.3',
                       'properties':props(inventory='locked rule-worker test dependency; runtime uses OS python-yaml')})
    # These names are requirements in THIRD_PARTY_NOTICES.md and docs/INSTALL.md,
    # not observations of the workstation or invented installed versions.
    for name in ('Python', 'Qt Quick/Controls', 'Quickshell', 'Omarchy', 'libseccomp',
                 'ClamAV', 'Bubblewrap', 'polkit', 'systemd', 'PyYAML'):
        item = {'type': 'framework' if name in ('Qt Quick/Controls', 'Quickshell')
                else 'application', 'bom-ref': 'external:' + name, 'name': name,
                'properties': props(inventory='external requirement; not bundled',
                                    version='not observed; host inventory excluded')}
        if name in ('ClamAV', 'Bubblewrap', 'polkit'):
            item['scope'] = 'optional'
            item['properties'] += props(usage='required only for corresponding optional protection/setup feature')
        components.append(item)
    for line in read(root, 'tools/ui-requirements.txt').decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)', line.strip())
        if not match:
            raise ValueError('unsupported GUI test dependency syntax')
        name, version = match.groups()
        components.append({'type': 'library', 'bom-ref': 'test:' + name, 'name': name,
                           'version': version, 'scope': 'excluded',
                           'purl': 'pkg:pypi/' + name.lower().replace('_', '-') + '@' + version,
                           'properties': props(inventory='GUI acceptance test only; not runtime')})
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'metadata': {
            'component': {'type': 'application', 'bom-ref': 'ironclad:project',
                          'name': project['name'], 'version': project['version'],
                          'licenses': [{'license': {'id': 'MIT'}}]},
            'properties': props(
                inventory='partial source/build inventory; offline and deterministic',
                python_runtime_dependencies='none declared',
                dependency_graph='Cargo.lock resolution only; not target/features or linked-runtime graph',
                omissions='Falco and falcoctl transitive dependencies, system versions, exact native link graph, '
                          'full license review, vulnerability/advisory scan, signature verification',
                security='No vulnerability clearance or security certification is asserted',
                inputs_sha256=json.dumps({name: sha(read(root, name)) for name in (
                    'pyproject.toml', 'manifest.json', 'tools/krsi-Cargo.lock',
                    'tools/ui-requirements.txt', 'ironclad/sensor_policy.py',
                    'tools/build_krsi_component.py','ironclad/falco_rules.py','uv.lock')}, sort_keys=True))},
        'components': sorted(components, key=lambda item: item['bom-ref']),
        'dependencies': sorted(dependencies, key=lambda item: item['ref']),
        'compositions': [{'aggregate': 'incomplete', 'assemblies': ['ironclad:project', native_ref]}],
    }


def encode(document):
    return (json.dumps(document, sort_keys=True, indent=2) + '\n').encode()


def write_output(path, body):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('refuse linked SBOM destination')
    if path.exists():
        if not path.is_file() or path.stat().st_size != len(body) or path.read_bytes() != body:
            raise ValueError('existing SBOM differs; choose a new destination')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='existing parent directory; refuses conflicting output')
    args = parser.parse_args()
    body = encode(generate())
    if args.output:
        write_output(args.output, body)
        print(json.dumps({'sha256': sha(body), 'bytes': len(body), 'scope': 'partial inventory'}))
    else:
        print(body.decode(), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
