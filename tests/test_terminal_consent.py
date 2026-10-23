import errno
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]


class TerminalConsentTests(unittest.TestCase):
    def run_consent(self,approve):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); home=root/'home'; home.mkdir(); home.chmod(0o702)
            code='''import sys
from pathlib import Path
from ironclad import actions
from ironclad.offline import restrict
from ironclad.cli import main
restrict()
actions.account_home=lambda:Path(sys.argv[1])
raise SystemExit(main(['--state',sys.argv[2],'action','apply','home.remove_world_write']))
'''
            master,slave=pty.openpty()
            proc=subprocess.Popen([sys.executable,'-B','-c',code,str(home),str(root/'state')],cwd=ROOT,stdin=slave,stdout=slave,stderr=slave,close_fds=True)
            os.close(slave); data=b''; sent=False; deadline=time.monotonic()+8
            try:
                while time.monotonic()<deadline:
                    ready,_,_=select.select([master],[],[],.1)
                    if ready:
                        try: chunk=os.read(master,8192)
                        except OSError as e:
                            if e.errno==errno.EIO: break
                            raise
                        if not chunk: break
                        data+=chunk
                        match=re.search(rb"Type 'APPLY ([0-9a-f]{12})'",data)
                        if match and not sent:
                            os.write(master,(b'APPLY '+match[1] if approve else b'NO')+b'\n'); sent=True
                    if proc.poll() is not None and not ready: break
                self.assertTrue(sent,'consent prompt missing')
                code=proc.wait(timeout=2)
                self.assertEqual(code,0 if approve else 2,data.decode(errors='replace'))
                self.assertEqual(home.stat().st_mode&0o777,0o700 if approve else 0o702)
                if approve: self.assertIn(b'"applied": true',data)
            finally:
                if proc.poll() is None: proc.kill(); proc.wait()
                os.close(master)
    def test_real_terminal_accepts_exact_plan(self): self.run_consent(True)
    def test_real_terminal_decline_keeps_permissions(self): self.run_consent(False)
