"""Native builder must not inherit executable hooks or credentials."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_builder', ROOT / 'tools/build_krsi_component.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildEnvironmentTests(unittest.TestCase):
    def test_host_hooks_and_secrets_are_not_inherited(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            with patch.dict(os.environ, {'RUSTC_WRAPPER': '/untrusted/hook',
                                         'CARGO_REGISTRY_TOKEN': 'fixture-secret',
                                         'LD_PRELOAD': '/untrusted/library'}), \
                    patch.object(builder.subprocess, 'check_output', return_value=builder.RUSTC_VERSION + '\n') as compiler:
                env = builder.build_environment(work, work / 'cache', work / 'rust', work / 'bpf')
            for key in ('RUSTC_WRAPPER', 'CARGO_REGISTRY_TOKEN', 'LD_PRELOAD'):
                self.assertNotIn(key, env)
                self.assertNotIn(key, compiler.call_args.kwargs['env'])
            self.assertEqual(env['CARGO_BUILD_JOBS'], '2')
            self.assertTrue((work / 'home').is_dir())

    def test_unexpected_compiler_fails_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            with patch.object(builder.subprocess, 'check_output', return_value='rustc unexpected\n'):
                with self.assertRaisesRegex(ValueError, 'unexpected Rust compiler'):
                    builder.build_environment(work, work / 'cache', work / 'rust', work / 'bpf')
            self.assertFalse((work / 'home').exists())


if __name__ == '__main__':
    unittest.main()
