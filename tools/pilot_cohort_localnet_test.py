import os
import ast
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pilot_cohort_localnet import burst,overlap,NAMES,EXPECTED,PROJECT
from wallet_release import create,encode,read


class BurstTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()/'burst'
        self.jobs=[dict(id=n,amount=50000,recipient='original') for n in NAMES]
    def test_two_parallel_jobs_all_ten_durable_and_repeat_does_not_pay(self):
        barrier=threading.Barrier(2);lock=threading.Lock();calls=[]
        def task(job):
            with lock:calls.append(job['id'])
            if job['id'] in NAMES[:2]:barrier.wait(timeout=5)
            time.sleep(.01);return dict(signature=job['id'])
        result=burst(self.root,self.jobs,2,task)
        self.assertEqual(len(result),10);self.assertEqual(overlap(result),2);self.assertEqual(len(calls),10)
        self.assertEqual(burst(self.root,self.jobs,2,lambda _:self.fail('completed payment repeated')),result)
    def test_error_after_side_effect_is_not_repeated_without_original_resolution(self):
        calls=[]
        def failed(job):calls.append(job);raise ValueError('reply lost')
        with self.assertRaisesRegex(ValueError,'reply lost'):burst(self.root,self.jobs[:1],1,failed)
        with self.assertRaisesRegex(ValueError,'uncertain original'):burst(self.root,self.jobs[:1],1,failed)
        self.assertEqual(len(calls),1);self.assertTrue((self.root/(NAMES[0]+'-started.json')).exists())
    def test_explicit_idempotent_admission_retry_reuses_exact_original_marker(self):
        self.root.mkdir(mode=0o700);path=self.root/(NAMES[0]+'-started.json');create(path,encode(self.jobs[0]))
        original=read(path,4096,secret=True)
        value=burst(self.root,self.jobs[:1],1,lambda _:dict(claim_id='original'),idempotent=True)
        self.assertEqual(value[NAMES[0]]['result']['claim_id'],'original');self.assertEqual(read(path,4096,secret=True),original)
        other=Path(self.tmp.name).resolve()/'other';other.mkdir(mode=0o700);create(other/(NAMES[0]+'-started.json'),encode(dict(self.jobs[0],recipient='changed')))
        with self.assertRaises(ValueError):burst(other,self.jobs[:1],1,lambda _:self.fail('changed admission repeated'),idempotent=True)
    def test_changed_recipient_duplicate_unknown_id_and_worker_bounds_refused(self):
        burst(self.root,self.jobs[:1],1,lambda _:dict(signature='original'))
        with self.assertRaisesRegex(ValueError,'identity changed'):burst(self.root,[dict(self.jobs[0],recipient='other')],1,lambda _:self.fail('paid'))
        for jobs,workers in ((self.jobs[:1]*2,1),([dict(id='../other')],1),(self.jobs,0),(self.jobs,True),(self.jobs,11)):
            with self.assertRaises(ValueError):burst(self.root,jobs,workers,lambda _:self.fail('paid'))
    def test_real_sigkill_after_start_commit_preserves_original_and_refuses_replay(self):
        script='''import os,signal,sys
from pathlib import Path
from pilot_cohort_localnet import burst,NAMES
def die(job):os.kill(os.getpid(),signal.SIGKILL)
burst(Path(sys.argv[1]),[dict(id=NAMES[0],amount=50000,recipient='original')],1,die)
'''
        child=subprocess.run([sys.executable,'-B','-c',script,str(self.root)],cwd=PROJECT/'tools',capture_output=True,timeout=15)
        self.assertEqual(child.returncode,-9)
        original=read(self.root/(NAMES[0]+'-started.json'),4096,secret=True)
        with self.assertRaisesRegex(ValueError,'uncertain original'):burst(self.root,self.jobs[:1],1,lambda _:self.fail('paid'))
        self.assertEqual(original,read(self.root/(NAMES[0]+'-started.json'),4096,secret=True))
    def test_other_original_jobs_finish_and_are_preserved_when_one_reply_fails(self):
        def task(job):
            if job['id']==NAMES[1]:raise ValueError('failure')
            return dict(signature=job['id'])
        with self.assertRaises(ValueError):burst(self.root,self.jobs,2,task)
        self.assertEqual(len(list(self.root.glob('*-done.json'))),9)
        with self.assertRaises(ValueError):burst(self.root,self.jobs,2,lambda _:self.fail('original task repeated'))
    def test_ring_preserves_total_and_accounts_for_prior_accepted_payment(self):
        self.assertEqual(sum(EXPECTED.values()),10000000)
        actual=EXPECTED.copy()
        for i,n in enumerate(NAMES):actual[n]-=50000;actual[NAMES[(i+1)%10]]+=50000
        self.assertEqual(actual,EXPECTED)
    def test_group_cleanup_accepts_only_freshly_empty_darwin_permission_race(self):
        from pilot_runtime_localnet import PilotHost
        host=PilotHost(PROJECT/'.data/p46a',self.root,None,None)
        child=SimpleNamespace(pid=98765,poll=lambda:-9);host.host=child
        row=f'98765 {os.getuid()} S\n'
        with patch('pilot_runtime_localnet.subprocess.check_output',side_effect=[row,'']),patch('pilot_runtime_localnet.os.killpg',side_effect=PermissionError):
            host.stop_host()
        self.assertIsNone(host.host)
        host.host=child
        with patch('pilot_runtime_localnet.subprocess.check_output',return_value=row),patch('pilot_runtime_localnet.os.killpg',side_effect=PermissionError):
            with self.assertRaises(PermissionError):host.stop_host()
        host.host=child
        with patch('pilot_runtime_localnet.subprocess.check_output',return_value=f'98765 {os.getuid()+1} S\n'),patch('pilot_runtime_localnet.os.killpg') as kill:
            with self.assertRaises(RuntimeError):host.stop_host()
            kill.assert_not_called()
    def test_worker_diagnostics_preserve_real_exit_and_never_log_password_input(self):
        import pilot_runtime as runtime
        tree=ast.parse((PROJECT/'tools/pilot_cohort_localnet.py').read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='CohortRun')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='start_host')
        script=next(n.value.value for n in method.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='script' for t in n.targets))
        executable=Path(self.tmp.name)/'native-faucet';executable.write_text('#!/bin/sh\ncat >/dev/null\nprintf "progress"\nprintf "fixture-error" >&2\nexit 7\n');executable.chmod(0o700)
        diagnostic=Path(self.tmp.name)/'error.json';original=subprocess.Popen;observed=[]
        def supervise(root,binding,duration):
            self.assertEqual(duration,1800)
            child=subprocess.Popen([str(executable),'tick'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            observed.append(child.communicate(input='never-log-fixture-password'));self.assertEqual(child.returncode,7)
        try:
            with patch.object(runtime,'supervise',side_effect=supervise),patch.object(sys,'argv',['fixture',str(self.root),'original-binding',str(diagnostic)]):exec(script,{})
        finally:subprocess.Popen=original
        self.assertEqual(observed,[('progress','fixture-error')])
        raw=read(diagnostic,4096,secret=True);self.assertIn(b'fixture-error',raw);self.assertNotIn(b'never-log-fixture-password',raw)


if __name__=='__main__':unittest.main()
