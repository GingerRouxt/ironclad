import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

from tools import generate_sbom as sbom


class SbomTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('pyproject.toml', 'manifest.json', 'ironclad/sensor_policy.py',
                     'ironclad/krsi-component.tar.gz', 'tools/build_krsi_component.py',
                     'tools/krsi-Cargo.lock', 'tools/krsi-ironclad.patch',
                     'tools/aya-obj-aliases.patch', 'tools/ui-requirements.txt'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sbom.ROOT / name, target)

    def test_deterministic_inventory_preserves_local_identity_and_limits(self):
        document = sbom.generate(self.root)
        self.assertEqual(sbom.encode(document), sbom.encode(sbom.generate(self.root)))
        self.assertEqual(document['bomFormat'], 'CycloneDX')
        self.assertEqual(document['compositions'][0]['aggregate'], 'incomplete')
        components = {item['bom-ref']: item for item in document['components']}
        local = [item for ref, item in components.items() if ref.startswith('cargo-local:')]
        self.assertTrue(local)
        self.assertTrue(all('purl' not in item for item in local))
        self.assertIn('cargo-local:aya-obj@0.2.1', components)
        self.assertIn('cargo-local:krsi@0.1.0', components)
        self.assertEqual(components['ironclad:bundled-krsi']['version'], '0.2.0-ironclad.2')
        registry = [item for ref, item in components.items() if ref.startswith('cargo-registry:')]
        self.assertTrue(all(item['hashes'][0]['alg'] == 'SHA-256' for item in registry))
        self.assertEqual(components['test:shiboken6']['scope'], 'excluded')
        self.assertEqual(components['ironclad:optional-falco']['scope'], 'optional')
        self.assertNotIn('version', components['external:ClamAV'])
        self.assertTrue(all(edge['ref'] in components and all(
            ref in components for ref in edge['dependsOn']) for edge in document['dependencies']))
        self.assertNotIn(str(self.root), sbom.encode(document).decode())

    def test_source_lock_and_patch_drift_fail_closed(self):
        for name in ('tools/krsi-Cargo.lock', 'tools/krsi-ironclad.patch',
                     'tools/aya-obj-aliases.patch'):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                with self.assertRaisesRegex(ValueError, 'embedded provenance differs'):
                    sbom.generate(self.root)
                path.write_bytes(original)

    def test_archive_pin_and_library_pin_drift_are_refused(self):
        path = self.root / 'ironclad/sensor_policy.py'
        original = path.read_text()
        for field in ('KRSI_ARCHIVE_SHA', 'KRSI_SHA'):
            with self.subTest(field=field):
                value = sbom.literals(original, {field})[field]
                path.write_text(original.replace(value, '0' * 64))
                with self.assertRaises(ValueError):
                    sbom.generate(self.root)
        path.write_text(original)

    def test_new_python_dependency_cannot_be_silently_omitted(self):
        path = self.root / 'pyproject.toml'
        path.write_text(path.read_text().replace('dependencies = []', 'dependencies = ["example==1.0"]'))
        with self.assertRaisesRegex(ValueError, 'Python runtime dependencies changed'):
            sbom.generate(self.root)

    def test_literal_reader_never_executes_source(self):
        body = b'raise RuntimeError("must not run")\nPIN = "value"\n'
        self.assertEqual(sbom.literals(body, {'PIN'}), {'PIN': 'value'})
        with self.assertRaises(ValueError):
            sbom.literals(b'PIN = str(1)', {'PIN'})

    def test_native_archive_links_traversal_and_duplicates_refused(self):
        for case in ('link', 'traversal', 'duplicate'):
            with self.subTest(case=case):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
                    entry = tarfile.TarInfo('../outside' if case == 'traversal' else 'file')
                    if case == 'link':
                        entry.type = tarfile.SYMTYPE
                        entry.linkname = 'outside'
                    archive.addfile(entry)
                    if case == 'duplicate':
                        archive.addfile(entry)
                with self.assertRaises(ValueError):
                    sbom.members(buffer.getvalue())

    def test_missing_registry_checksum_and_dependency_are_refused(self):
        for contents in (
                '[[package]]\nname="x"\nversion="1"\nsource="' + sbom.REGISTRY + '"\n',
                '[[package]]\nname="x"\nversion="1"\ndependencies=["missing"]\n'):
            with self.subTest(contents=contents):
                with self.assertRaises(ValueError):
                    sbom.cargo_inventory(contents.encode())

    def test_output_refuses_conflicts_and_links(self):
        path = self.root / 'sbom.json'
        body = sbom.encode({'fixture': True})
        sbom.write_output(path, body)
        sbom.write_output(path, body)
        self.assertEqual(json.loads(path.read_bytes()), {'fixture': True})
        with self.assertRaises(ValueError):
            sbom.write_output(path, b'changed')
        link = self.root / 'linked.json'
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            sbom.write_output(link, body)
        self.assertEqual(path.read_bytes(), body)
