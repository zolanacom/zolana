import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tester_gateway_recovery import packaged,stage_journals,fingerprint,files


class PackagedGatewayTests(unittest.TestCase):
    def test_acceptance_cannot_launch_a_send_or_redeem_an_invitation(self):
        with patch('tester_gateway_recovery.subprocess.run') as run:
            for action in ('send','withdraw','fund','join','create','restore'):
                with self.subTest(action=action),self.assertRaisesRegex(ValueError,'cannot submit'):
                    packaged(Path('/package'),Path('/client'),{'action':action})
            run.assert_not_called()

    def test_isolated_worker_refuses_checkout_runtime_and_keeps_password_off_argv(self):
        bundle=Path('/private/tmp/extracted/native-wallet');state=Path('/private/tmp/client')
        response={'returncode':0,'stdout':json.dumps({'runtime':'/checkout/tools/wallet_ui.py','binary':str(bundle/'bin/native-wallet')}),'stderr':''}
        with patch('tester_gateway_recovery.subprocess.run',return_value=type('Done',(),response)()) as run:
            with self.assertRaisesRegex(ValueError,'extracted runtime'):packaged(bundle,state,{'action':'resolve','password':'private test password'})
            args=run.call_args.args[0]
            self.assertIn('-I',args);self.assertIn('-B',args)
            self.assertNotIn('private test password',' '.join(args))
            self.assertEqual(json.loads(run.call_args.kwargs['input'])['password'],'private test password')
            self.assertEqual(run.call_args.kwargs['cwd'],'/private/tmp')

    def fixture(self,root):
        source=root/'source';source.mkdir();client=root/'client';(client/'wallet-ui').mkdir(parents=True)
        evidence=root/'evidence';evidence.mkdir()
        pending=b'{"signature":"original-signed-payment"}';stage=b'{"fee_cap":123,"authority":"original"}'
        (source/'ack-loss-022.pending.original.json').write_bytes(pending)
        (source/'ack-loss-022.staging.original.json').write_bytes(stage)
        record={'phase':'passed','signature':'original-signed-payment','pending_sha256':fingerprint(pending),'staging_sha256':fingerprint(stage)}
        (source/'ack-loss-022.json').write_text(json.dumps(record))
        return source,client,evidence,pending,stage

    def test_journal_injection_reuses_exact_identity_and_never_changes_source(self):
        with tempfile.TemporaryDirectory() as name:
            source,client,evidence,pending,stage=self.fixture(Path(name));before=files(source)
            self.assertEqual(stage_journals(client,source,evidence),'original-signed-payment')
            self.assertEqual((client/'wallet-ui/wallet.json.pending.json').read_bytes(),pending)
            self.assertEqual((client/'wallet-ui/wallet.json.staging.json').read_bytes(),stage)
            self.assertEqual(files(source),before)
            self.assertTrue(json.loads((evidence/'journal-injection.json').read_text())['fault_injection_only'])
            with self.assertRaisesRegex(ValueError,'unknown payment'):stage_journals(client,source,evidence)
            self.assertEqual((client/'wallet-ui/wallet.json.pending.json').read_bytes(),pending)

    def test_changed_saved_journal_is_rejected_before_either_file_is_written(self):
        with tempfile.TemporaryDirectory() as name:
            source,client,evidence,pending,stage=self.fixture(Path(name))
            (source/'ack-loss-022.staging.original.json').write_bytes(b'changed authority or fee cap')
            with self.assertRaisesRegex(ValueError,'original journal differs'):stage_journals(client,source,evidence)
            self.assertEqual(list((client/'wallet-ui').iterdir()),[])
            self.assertFalse((evidence/'journal-injection.json').exists())


if __name__=='__main__':unittest.main()
