import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch


class ServiceIngressTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        runtime=SimpleNamespace(ROOT=root,OPERATORS=root/'operators',BASE=root,LAB=root/'lab',WALLET=root/'wallet',
            ready=Mock(),load=Mock(),private=Mock(),save=Mock(),run_json=Mock(),rpc=Mock(),sponsor=Mock())
        spec=importlib.util.spec_from_file_location('isolated_ingress_under_test',Path(__file__).with_name('service_ingress.py'))
        self.app=importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,service_runtime=runtime):spec.loader.exec_module(self.app)
        self.config=dict(network=7,genesis_hash='genesis',program='program',pool='pool',pool_format='NPOOL003',recipient_withdrawals=True,
            key_mode='private-service',sponsor='never-export',roles={'treasury':'never-export'},rpc_access='never-export')
    def test_profile_exports_only_pinned_public_identity_and_invited_https_endpoints(self):
        profile=self.app.public_profile(self.config,'public test CA')
        self.assertTrue(profile['invite_required']);self.assertEqual(profile['key_mode'],'user-wallet-v1')
        self.assertEqual(profile['rpc'],{'transport':'https','url':'https://127.0.0.1:23898'})
        self.assertEqual(profile['faucet']['url'],'https://127.0.0.1:13780')
        self.assertEqual(profile['local_tls_ca_pem'],'public test CA')
        self.assertNotIn('never-export',json.dumps(profile))
        source=self.app.public_profile(self.config)
        self.assertNotIn('faucet',source);self.assertNotIn('invite_required',source)
        self.assertEqual(source['rpc']['url'],'http://127.0.0.1:23899')
    def test_interrupted_value_operation_never_resubmits_or_reinitializes(self):
        for phase in ('preparing','deposit_submitting','deposit_finalized','gas_submitting','gas_pending','admission_initializing'):
            self.app.STATE.write_text(json.dumps({'phase':phase}))
            with self.subTest(phase=phase),self.assertRaisesRegex(ValueError,'recover its original journals'):
                self.app.initialize()
            self.app.run_json.assert_not_called();self.app.private.assert_not_called()
    def test_existing_client_invitation_is_exported_without_reissuing_capacity(self):
        app=self.app
        app.PROFILE.write_text(json.dumps({'public':'profile'}))
        path=app.ROOT/'alice-desktop-invite.json';path.write_text(json.dumps({'invitation':'fixed original code','invite_id':'id'}))
        with patch.object(app,'check_ready'),patch.object(app,'faucet') as faucet:
            self.assertEqual(app.export_client('alice'),{'profile':{'public':'profile'},'invitation':'fixed original code','invite_id':'id'})
            faucet.assert_not_called()
            with self.assertRaises(ValueError):app.export_client('../operator')
    def test_listener_failure_closes_previously_bound_socket_before_starting_workers(self):
        app=self.app;server=Mock();faucet=Mock();gateway=SimpleNamespace(info={'faucet_audience':'https://127.0.0.1:13780','rpc_audience':'https://127.0.0.1:23898'})
        with patch.object(app,'check_ready'),patch.object(app,'Faucet',return_value=faucet),patch.object(app,'Gateway',return_value=gateway),patch.object(app,'listener',side_effect=[server,ValueError('TLS key invalid')]),patch.object(app.threading,'Thread') as thread:
            with self.assertRaisesRegex(ValueError,'TLS key invalid'):app.Ingress()
            server.server_close.assert_called_once();server.shutdown.assert_not_called()
            faucet.close.assert_called_once();thread.assert_not_called()
    def test_profile_mutation_refuses_startup_before_opening_ingress(self):
        app=self.app;app.PROFILE.write_text('{}')
        app.STATE.write_text(json.dumps({'phase':'ready','profile_sha256':hashlib.sha256(b'original').hexdigest()}))
        with patch.object(app,'listener') as listener,self.assertRaisesRegex(ValueError,'profile incomplete or changed'):
            app.Ingress()
        listener.assert_not_called()


if __name__=='__main__':unittest.main()
