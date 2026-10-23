import importlib.util
import io
from pathlib import Path
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publication', ROOT / 'tools/verify_publication.py')
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationPrivacyTests(unittest.TestCase):
    def test_env_files_are_rejected_even_when_empty(self):
        for name in ('.env', 'nested/.env.production', 'nested/.env.local'):
            self.assertIn((name, 'excluded-file'), publication.inspect(name, b''))

    def test_nested_native_archive_private_path_is_rejected(self):
        buffer = io.BytesIO()
        body = b'ELF diagnostic string /private-build-user/cache/source.rs'
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            member = tarfile.TarInfo('libexample.so')
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        self.assertIn(('component.tar.gz/libexample.so', 'private-path'),
                      publication.inspect('component.tar.gz', buffer.getvalue(), (b'/private-build-user',)))

    def test_synthetic_credential_marker_is_rejected_without_echoing_it(self):
        marker = b'gh' + b'p_' + b'A' * 36
        result = publication.inspect('config.json', marker)
        self.assertEqual(result, [('config.json', 'github-token')])

    def test_anonymous_build_paths_are_allowed(self):
        self.assertEqual(publication.inspect('library.so', b'/cargo-cache/source.rs /ironclad-build/source.rs',
                                             (b'/private-build-user',)), [])
