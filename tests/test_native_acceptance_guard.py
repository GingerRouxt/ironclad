"""Exercise safety stops without stopping real desktop processes or exhausting RAM."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('native_acceptance',Path(__file__).resolve().parents[1]/'tools/verify_native_protection.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def fixture(self,root,pid,name,parent,start=100,state='S'):
        path=root/str(pid);path.mkdir(exist_ok=True)
        fields=[state,str(parent)]+['0']*17+[str(start)]
        (path/'stat').write_text(f'{pid} ({name}) '+ ' '.join(fields))

    def test_unrelated_codex_exit_does_not_abort_active_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.fixture(root,30,'bash',20);self.fixture(root,20,'codex',1)
            self.fixture(root,40,'codex',1)
            watched=guard.codex_ancestors(30,root)
            self.assertEqual([p['pid'] for p in watched],[20])
            (root/'40/stat').unlink()
            self.assertEqual(guard.missing_processes(watched,root),[])
            (root/'20/stat').unlink()
            self.assertEqual(guard.missing_processes(watched,root),[20])

    def test_pid_reuse_and_zombie_are_not_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root,20,'codex',1)
            watched=guard.codex_ancestors(20,root)
            self.fixture(root,20,'codex',1,start=200)
            self.assertEqual(guard.missing_processes(watched,root),[20])
            self.fixture(root,20,'codex',1,state='Z')
            self.assertEqual(guard.missing_processes(watched,root),[20])

    def test_each_guard_reason_and_failed_sample_are_saved(self):
        for alive,memory,reason in [(False,8*1024**3,'active Codex'),(True,1024**3,'available memory')]:
            sample={'codex_alive':alive,'available_bytes':memory}
            failure=guard.guard_failure(sample);self.assertIn(reason,failure)
            with tempfile.TemporaryDirectory() as tmp:
                target=Path(tmp)/'evidence/result.json'
                guard.save_result(target,{'passed':False,'failure':failure,'samples':[sample]})
                self.assertEqual(json.loads(target.read_text())['samples'],[sample])
        self.assertIsNone(guard.guard_failure({'codex_alive':True,'available_bytes':3*1024**3}))

    def test_preexisting_sensor_drops_refuse_workload_even_when_running(self):
        with self.assertRaisesRegex(RuntimeError,'clean current metrics'):
            guard.require_healthy_start({'state':'degraded','monitoring':True},True,8*1024**3)
        guard.require_healthy_start({'state':'monitoring','monitoring':True},True,8*1024**3)
        with self.assertRaisesRegex(RuntimeError,'5 GiB'):
            guard.require_healthy_start({'state':'monitoring','monitoring':True},True,3*1024**3)
