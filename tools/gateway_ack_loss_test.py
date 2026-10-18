import json
import os
from pathlib import Path
import tempfile
import secrets
import shutil
import unittest
from unittest.mock import patch,Mock
from gateway_ack_loss import atomic,read,Channel,admission_identity,desktop,fingerprint,desktop_recover_held


class AckCoordinationTests(unittest.TestCase):
    def directory(self):
        root=Path('/private/tmp')/('native-ack-loss-022-'+secrets.token_hex(16));root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree,root)
        return root

    def test_atomic_private_messages_reject_symlinks_unsafe_modes_and_added_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'message.json';atomic(path,{'phase':'ready'})
            self.assertEqual(read(path,os.getuid()),{'phase':'ready'})
            path.chmod(0o644)
            with self.assertRaises(ValueError):read(path,os.getuid())
            path.chmod(0o600);link=root/'link';link.symlink_to(path)
            with self.assertRaises(OSError):read(link,os.getuid())
            atomic(path,{'data':'a'*16385})
            with self.assertRaises(ValueError):read(path,os.getuid())

    def test_nonce_and_peer_failure_cannot_be_mistaken_for_a_ready_signal(self):
        root=self.directory();channel=Channel(root,os.getuid())
        channel.send('response','ready');self.assertEqual(channel.wait('response','ready',.1)['nonce'],channel.nonce)
        atomic(root/'response.json',{'nonce':'other','phase':'ready'})
        with self.assertRaisesRegex(ValueError,'nonce changed'):channel.wait('response','ready',.1)
        channel.send('response','error',reason='original journal retained')
        with self.assertRaisesRegex(RuntimeError,'original journal retained'):channel.wait('response','ready',.1)

    def test_admission_comparison_preserves_authorities_while_allowing_charged_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'admission.json'
            state={'policy':{'rpc_limit':2000},'invitations':[{'id':'original','revoked':False,'member':{'claim':'original claim','rpc':{'count':3},'faucet':{'count':2}}}]}
            path.write_text(json.dumps(state));before=admission_identity(path)
            state['invitations'][0]['member']['rpc']['count']=7;path.write_text(json.dumps(state))
            self.assertEqual(admission_identity(path),before)
            state['invitations'][0]['revoked']=True;path.write_text(json.dumps(state))
            self.assertNotEqual(admission_identity(path),before)

    def test_existing_experiment_refuses_to_launch_another_signing_client(self):
        root=self.directory()
        with tempfile.TemporaryDirectory() as directory:
            evidence=Path(directory);(evidence/'ack-loss-022.json').write_text('{}')
            with patch('service_wallet_acceptance.Acceptance',return_value=Mock()),patch('gateway_ack_loss.subprocess.Popen') as launch:
                with self.assertRaisesRegex(ValueError,'never resend'):desktop(root,evidence)
                launch.assert_not_called()

    def test_authentication_wait_resume_cannot_repeat_a_started_send(self):
        root=self.directory()
        with tempfile.TemporaryDirectory() as directory:
            evidence=Path(directory);atomic(evidence/'ack-loss-022.json',{'phase':'send_started'})
            with patch('service_wallet_acceptance.Acceptance',return_value=Mock()),patch('gateway_ack_loss.subprocess.Popen') as launch:
                with self.assertRaisesRegex(ValueError,'no payment retry permitted'):desktop(root,evidence,True)
                launch.assert_not_called()

    def test_held_recovery_refuses_wrong_phase_or_changed_original_journal_before_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence=Path(directory);wallet=evidence/'wallet';pending=Path(str(wallet)+'.pending.json');stage=Path(str(wallet)+'.staging.json')
            original=b'{"signature":"original"}';staging=b'{"authority":"original"}'
            (evidence/'ack-loss-022.pending.original.json').write_bytes(original)
            (evidence/'ack-loss-022.staging.original.json').write_bytes(staging)
            pending.write_bytes(original);stage.write_bytes(staging)
            app=Mock(clients={'alice':Mock(wallet=wallet)});app.fingerprints.return_value={'wallet':'original'}
            state={'phase':'client_stopped','pending_sha256':fingerprint(original),'staging_sha256':fingerprint(staging),'signature':'original','fingerprints':app.fingerprints()}
            channel=Mock()
            with patch('gateway_ack_loss.subprocess.Popen') as launch:
                for change in ('phase','pending','stage','fingerprints'):
                    current=dict(state)
                    if change=='phase':current['phase']='send_started'
                    if change=='pending':pending.write_bytes(b'changed')
                    if change=='stage':stage.write_bytes(b'changed')
                    if change=='fingerprints':current['fingerprints']={'wallet':'changed'}
                    with self.subTest(change=change),self.assertRaisesRegex(ValueError,'original|never resend'):
                        desktop_recover_held(channel,app,evidence/'ack-loss-022.json',current,evidence)
                    pending.write_bytes(original);stage.write_bytes(staging)
                channel.wait.assert_not_called();channel.send.assert_not_called();launch.assert_not_called()


if __name__=='__main__':unittest.main()
