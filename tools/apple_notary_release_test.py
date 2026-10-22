import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import apple_notary_release as n
from wallet_release import atomic,encode,sha

ID='1f33be4d-a12e-49df-9712-082b36ab9394'
OTHER='2f33be4d-a12e-49df-9712-082b36ab9394'


class NotaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='zolana081-notary-',dir='/private/tmp');self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.source=self.base/'original.dmg';self.source.write_bytes(b'fixture-only unsigned image');self.source.chmod(0o600)
        self.receipt=dict(image_sha256=sha(self.source.read_bytes()),image_bytes=self.source.stat().st_size,team_identifier='ABCDE12345',certificate_sha1='A'*40,image_identifier='dev.example.zolana.image')
        self.root=self.base/'notary';self.calls=[];self.status='Accepted';self.log_digest=self.receipt['image_sha256'];self.fail=None;self.bad_job=False;self.missing_digest=False
        self.provider=lambda:(self.source,self.receipt)
        n.initialize(self.root,self.base/'prepared','a'*64,'reviewed-notary-profile',self.runner,self.provider)
    def runner(self,argv,timeout):
        self.calls.append((list(argv),timeout))
        if self.fail and self.fail in argv:raise subprocess.TimeoutExpired(argv,timeout)
        action=argv[2] if argv[0]=='/usr/bin/xcrun' else 'assess'
        if argv[1]=='notarytool':
            if action=='submit':value=dict(id=ID,message='fixture acknowledged')
            elif action=='info':value=dict(id=ID,status=self.status,name='submitted.dmg')
            else:
                value=dict(jobId=OTHER if self.bad_job else ID,status=self.status,archiveFilename='submitted.dmg',sha256=self.log_digest)
                if self.missing_digest:value.pop('sha256')
            return subprocess.CompletedProcess(argv,0,encode(value),b'')
        if argv[1]=='stapler' and action=='staple':
            path=Path(argv[-1]);path.write_bytes(path.read_bytes()+b'fixture-ticket')
        return subprocess.CompletedProcess(argv,0,b'',b'')
    def opened(self):return n.NotaryRelease(self.root,self.runner,self.provider)
    def accepted(self):
        with self.opened_context() as value:value.submit();value.check()
    def opened_context(self):
        from contextlib import contextmanager
        @contextmanager
        def open_one():
            value=self.opened()
            try:yield value
            finally:value.close()
        return open_one()
    def test_successful_fixture_never_claims_apple_approval_and_preserves_submitted_bytes(self):
        self.accepted();original=(self.root/'submitted.dmg').read_bytes()
        with self.opened_context() as value:
            value.staple();result=value.assess()
            self.assertEqual(result['phase'],'assessed')
            for field in ('notarized','ticket_validated','gatekeeper_local','release_ready','network_commands_executed'):self.assertIs(result[field],False)
            self.assertEqual(result['evidence_kind'],'local-fixture');self.assertFalse(result['external_device_tested'])
        self.assertEqual((self.root/'submitted.dmg').read_bytes(),original);self.assertEqual(self.source.read_bytes(),original)
        submit=[v[0] for v in self.calls if 'submit' in v[0]][0]
        self.assertNotIn('--wait',submit);self.assertNotIn('--force',submit);self.assertIn('--keychain-profile',submit)
    def test_submit_timeout_is_durable_unknown_and_reopen_refuses_resubmission(self):
        self.fail='submit'
        with self.opened_context() as value,self.assertRaises(subprocess.TimeoutExpired):value.submit()
        with self.opened_context() as value:
            self.assertEqual(value.state['phase'],'submission_unknown')
            with self.assertRaisesRegex(ValueError,'reconcile'):value.submit()
        self.assertEqual(sum('submit' in argv for argv,_ in self.calls),1)
    def test_explicit_unknown_reconciliation_requires_exact_apple_log_sha_and_uuid(self):
        self.fail='submit'
        with self.opened_context() as value,self.assertRaises(subprocess.TimeoutExpired):value.submit()
        self.fail=None
        for wrong in ('digest','job','missing'):
            self.log_digest='b'*64 if wrong=='digest' else self.receipt['image_sha256'];self.bad_job=wrong=='job';self.missing_digest=wrong=='missing'
            with self.opened_context() as value,self.assertRaises(ValueError):value.reconcile(ID)
            self.assertEqual(json.loads((self.root/'state.json').read_text())['phase'],'submission_unknown')
        self.bad_job=False;self.missing_digest=False;self.log_digest=self.receipt['image_sha256']
        with self.opened_context() as value:self.assertEqual(value.reconcile(ID)['phase'],'accepted')
    def test_info_accepted_does_not_skip_hash_checked_log_and_retry_does_not_reupload(self):
        with self.opened_context() as value:value.submit()
        self.fail='log'
        with self.opened_context() as value,self.assertRaises(subprocess.TimeoutExpired):value.check()
        state=json.loads((self.root/'state.json').read_text());self.assertEqual(state['phase'],'awaiting_log');self.assertFalse(state['notarized'])
        self.fail=None
        with self.opened_context() as value:self.assertEqual(value.check()['phase'],'accepted')
        self.assertEqual(sum('submit' in argv for argv,_ in self.calls),1)
    def test_normal_bound_submission_can_use_official_short_log_without_digest_but_unknown_cannot(self):
        self.missing_digest=True
        with self.opened_context() as value:value.submit();self.assertEqual(value.check()['phase'],'accepted')
    def test_rejection_stays_rejected_and_cannot_be_stapled_or_resubmitted(self):
        self.status='Invalid'
        with self.opened_context() as value:
            value.submit();self.assertEqual(value.check()['phase'],'rejected')
        with self.opened_context() as value:
            with self.assertRaises(ValueError):value.staple()
            with self.assertRaises(ValueError):value.submit()
    def test_staple_failure_retains_copy_and_retry_uses_new_copy_same_uuid(self):
        self.accepted();self.fail='staple'
        with self.opened_context() as value,self.assertRaises(subprocess.TimeoutExpired):value.staple()
        first=json.loads((self.root/'state.json').read_text())['staple_attempt'];self.fail=None
        with self.opened_context() as value:value.staple();self.assertNotEqual(value.state['staple_attempt'],first);self.assertEqual(value.state['submission_id'],ID)
        self.assertEqual(len(list((self.root/'attempts').iterdir())),2)
    def test_interrupted_staple_after_result_revalidates_original_copy(self):
        self.accepted()
        def stop(phase):
            if phase=='staple_result':raise RuntimeError('fixture parent interrupted')
        with self.opened_context() as value,self.assertRaises(RuntimeError):value.staple(stop)
        attempt=json.loads((self.root/'state.json').read_text())['staple_attempt']
        with self.opened_context() as value:value.staple();self.assertEqual(value.state['staple_attempt'],attempt)
    def test_assessment_failure_preserves_ticket_and_repeated_explicit_check_is_same_image(self):
        self.accepted()
        with self.opened_context() as value:value.staple()
        self.fail='--assess'
        with self.opened_context() as value,self.assertRaises(subprocess.TimeoutExpired):value.assess()
        state=json.loads((self.root/'state.json').read_text());self.assertEqual(state['phase'],'assessment_failed');original=state['stapled_sha256'];self.fail=None
        with self.opened_context() as value:value.assess();self.assertEqual(value.state['stapled_sha256'],original)
    def test_changed_source_frozen_submission_log_and_stapled_image_fail_closed(self):
        with self.opened_context() as value:value.submit()
        old=self.source.read_bytes();self.source.write_bytes(old+b'changed')
        with self.assertRaises(ValueError):self.opened()
        self.source.write_bytes(old);self.acceptance_without_submit()
        with self.opened_context() as value:value.staple();path=self.root/'attempts'/value.state['staple_attempt']/'Zolana-Wallet.dmg';path.write_bytes(b'tampered')
        with self.opened_context() as value,self.assertRaises(ValueError):value.assess()
        state=json.loads((self.root/'state.json').read_text());log=self.root/'logs'/(state['log_sha256']+'.json');log.write_bytes(encode(dict(jobId=OTHER,status='Accepted',archiveFilename='submitted.dmg')))
        with self.assertRaises(ValueError):self.opened()
    def acceptance_without_submit(self):
        with self.opened_context() as value:value.check()
    def test_config_change_partial_init_and_fixture_promotion_are_rejected(self):
        with self.assertRaises(ValueError):n.initialize(self.root,self.base/'prepared','a'*64,'reviewed-notary-profile',self.runner,self.provider)
        with self.assertRaises(ValueError):n.NotaryRelease(self.root)
        state=json.loads((self.root/'state.json').read_text());state['notarized']=True;atomic(self.root/'state.json',state)
        with self.assertRaises(ValueError):self.opened()
    def test_semantically_similar_log_bytes_cannot_replace_recorded_evidence(self):
        self.accepted();state=json.loads((self.root/'state.json').read_text());path=self.root/'logs'/(state['log_sha256']+'.json')
        value=json.loads(path.read_text());value['extra']='changed evidence';path.write_bytes(encode(value))
        with self.assertRaisesRegex(ValueError,'log bytes changed'):self.opened()
    def test_actual_image_verifier_receives_explicit_leaf_certificate_pin(self):
        with self.opened_context() as value:
            value.fixture=False
            with patch('wallet_apple_release.signature') as verify:
                value.verify_image(self.source)
                verify.assert_called_once_with(self.source,self.receipt['image_identifier'],self.receipt['team_identifier'],runtime=False,certificate=self.receipt['certificate_sha1'])
    def test_prepared_requires_real_developer_id_mode_after_actual_verifier(self):
        receipt={**self.receipt,'format':'zolana-apple-developer-id-preparation-v1','mode':'ad-hoc','developer_id_used':False,'notarized':False,'release_ready':False}
        with patch('wallet_apple_release.verify_prepared',return_value=(self.source,receipt)) as verify:
            with self.assertRaisesRegex(ValueError,'Developer ID'):n.prepared(self.base/'prepared','a'*64)
            verify.assert_called_once_with(self.base/'prepared','a'*64)
    def test_concurrent_operation_and_uncertain_storage_require_original_restart(self):
        value=self.opened()
        try:
            with self.assertRaises(BlockingIOError):self.opened()
            real=atomic
            def uncertain(path,data):real(path,data);raise OSError('uncertain fsync')
            with patch.object(n,'atomic',side_effect=uncertain),self.assertRaises(OSError):value.submit()
        finally:value.close()
        with self.opened_context() as value:self.assertEqual(value.state['phase'],'submission_unknown')
    def test_command_guard_refuses_passwords_shell_force_wait_and_arbitrary_executables(self):
        with patch.object(subprocess,'run') as run:
            for argv in (['sh','-c','anything'],['/usr/bin/xcrun','notarytool','submit','/tmp/x.dmg','--password','secret'],['/usr/bin/xcrun','notarytool','submit','/tmp/x.dmg','--keychain-profile','x','--output-format','json','--wait'],['/usr/sbin/spctl','--global-disable']):
                with self.assertRaises(ValueError):n.apple_command(argv)
            run.assert_not_called()
        for value in ('','--password','../other','x\nother','x'*129):
            with self.assertRaises(ValueError):n.profile(value)
    def test_actual_test_child_sigkill_after_intent_reopens_unknown(self):
        script=self.base/'crash-child.py'
        source=Path(n.__file__).resolve().parent
        script.write_text("import sys,time\nfrom pathlib import Path\nsys.path.insert(0,"+repr(str(source))+")\nimport apple_notary_release as n\nroot=Path(sys.argv[1]);src=Path(sys.argv[2]);receipt=n.decode(n.read(root/'fixture-receipt.json',4096,True))\ndef runner(*args):raise RuntimeError('upload must never start')\nx=n.NotaryRelease(root,runner,lambda:(src,receipt))\ndef hook(phase):\n (root/'intent-reached').write_text(phase)\n time.sleep(20)\nx.submit(hook)\n")
        (self.root/'fixture-receipt.json').write_bytes(encode(self.receipt));(self.root/'fixture-receipt.json').chmod(0o600)
        child=subprocess.Popen([__import__('sys').executable,'-I','-B',str(script),str(self.root),str(self.source)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            end=time.monotonic()+5
            while not (self.root/'intent-reached').exists() and time.monotonic()<end and child.poll() is None:time.sleep(.01)
            self.assertTrue((self.root/'intent-reached').exists());child.kill();child.wait(timeout=5);self.assertEqual(child.returncode,-signal.SIGKILL)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
            child.communicate()
        with self.opened_context() as value:
            self.assertEqual(value.state['phase'],'submission_unknown')
            with self.assertRaises(ValueError):value.submit()
    def test_submit_uuid_is_durable_before_poll_even_when_process_boundary_interrupts(self):
        def stop(phase):
            if phase=='submission_result':raise RuntimeError('fixture process boundary')
        with self.opened_context() as value,self.assertRaises(RuntimeError):value.submit(stop)
        self.assertEqual(json.loads((self.root/'submit-result.json').read_text())['id'],ID)
        with self.opened_context() as value:
            self.assertEqual(value.state['phase'],'submission_unknown')
            with self.assertRaises(ValueError):value.submit()
            self.assertEqual(value.reconcile(ID)['phase'],'accepted')
        self.assertEqual(sum('submit' in argv for argv,_ in self.calls),1)


if __name__=='__main__':unittest.main()
