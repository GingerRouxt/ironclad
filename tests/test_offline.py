from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from ironclad import offline

ROOT=Path(__file__).resolve().parents[1]


class OfflineTests(unittest.TestCase):
    def test_guard_blocks_internet_sockets(self):
        code='''from ironclad.offline import restrict
import socket
restrict()
for family in (socket.AF_INET,socket.AF_INET6):
 try:
  socket.socket(family,socket.SOCK_STREAM)
 except PermissionError:
  pass
 else:
  raise SystemExit('Internet socket not blocked')
a,b=socket.socketpair(); a.send(b'local'); assert b.recv(5)==b'local'
print('IPv4/IPv6 blocked; Unix IPC works')
'''
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT,capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_descendant_inherits_guard(self):
        child="import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
        code=f'from ironclad.offline import restrict; import subprocess,sys; restrict(); r=subprocess.run([sys.executable,"-c",{child!r}],capture_output=True); assert r.returncode!=0 and b"PermissionError" in r.stderr'
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_unsupported_fails_closed(self):
        with patch('ironclad.offline.platform.machine',return_value='unknown-cpu'):
            with self.assertRaises(ValueError): offline.restrict()
    def test_library_missing_fails_closed(self):
        with patch('ironclad.offline.Path.resolve',side_effect=FileNotFoundError()):
            with self.assertRaises(OSError): offline.restrict()

    def test_console_entrypoint_fails_closed(self):
        from io import StringIO
        from ironclad.cli import entrypoint
        with patch('ironclad.offline.restrict',side_effect=OSError()), patch('ironclad.cli.main') as handler, patch('sys.stderr',StringIO()):
            self.assertEqual(entrypoint(),2); handler.assert_not_called()
    def test_checkout_launcher_ignores_pythonpath(self):
        import json
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            marker=Path(d)/'marker'
            (Path(d)/'sitecustomize.py').write_text('import os; open(os.environ["MARKER"],"w").write("injected")')
            env={**os.environ,'PYTHONPATH':d,'MARKER':str(marker)}
            result=subprocess.run([str(ROOT/'zds-ironclad'),'doctor'],cwd=d,env=env,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr); self.assertTrue(json.loads(result.stdout)['network_guard']); self.assertFalse(marker.exists())
