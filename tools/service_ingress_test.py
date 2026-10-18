import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import os
import tempfile
import threading
import ssl
import urllib.request
import urllib.error
import base64
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

    def gate(self):
        app=self.app
        def private(path,raw):
            with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:stream.write(raw)
        app.private.side_effect=private
        def save(path,data):
            temporary=path.with_suffix('.new');private(temporary,json.dumps(data).encode());os.replace(temporary,path)
        app.save.side_effect=save
        app.arm_ack_gate('A'*88)
        gateway=object.__new__(app.FinalityGateGateway);gateway.gate_lock=threading.Lock();gateway.release=Mock()
        return app,gateway

    def test_only_exact_successful_finalized_signature_is_withheld_and_never_returned(self):
        app,gateway=self.gate()
        query=json.dumps({'method':'getSignatureStatuses','params':[['B'*88,'A'*88]]}).encode()
        for status in [None,{'confirmationStatus':'confirmed','err':None,'slot':10},{'confirmationStatus':'finalized','err':'failed','slot':10}]:
            response=json.dumps({'result':{'value':[{'confirmationStatus':'finalized','err':None,'slot':10},status]}}).encode()
            with patch.object(app.Gateway,'forward',return_value=response):self.assertEqual(gateway.forward(query),response)
            self.assertEqual(app.ack_gate()['phase'],'armed')
        response=json.dumps({'result':{'value':[None,{'confirmationStatus':'finalized','err':None,'slot':11}]}}).encode()
        with patch.object(app.Gateway,'forward',return_value=response):
            with self.assertRaisesRegex(OSError,'withheld the original'):gateway.forward(query)
            self.assertEqual(app.ack_gate()['response_sha256'],hashlib.sha256(response).hexdigest())
            self.assertEqual(app.ack_gate()['phase'],'held')
            self.assertEqual(gateway.forward(query),response)  # Restart/resolve does not rearm it.
        gateway.release.wait.assert_called_once_with(60)
        with self.assertRaisesRegex(ValueError,'already started'):app.arm_ack_gate('B'*88)

    def test_unsafe_private_gate_and_invalid_target_cannot_be_armed(self):
        app=self.app
        for target in ('0'*88,'A'*63,{},'A'*89):
            with self.assertRaises(ValueError):app.arm_ack_gate(target)
        app.ACK_GATE.symlink_to(app.ROOT/'missing')
        with self.assertRaises(ValueError):app.arm_ack_gate('A'*88)
        with self.assertRaises(OSError):app.ack_gate()

    def test_checkpoint_loads_private_rpc_routes_before_its_first_query(self):
        app,gateway=self.gate();gate=app.ack_gate();gate['phase']='held';app.save(app.ACK_GATE,gate)
        order=[]
        app.load.side_effect=lambda root:order.append(('load',root))
        def rpc(*args):
            self.assertEqual(order,[('load',app.ROOT)])
            return {'value':[{'confirmationStatus':'finalized','err':None}]}
        app.rpc.side_effect=rpc
        runtime=SimpleNamespace(canonical=lambda:{'pool':'unchanged'},slots=lambda:[10,10])
        with patch.dict(sys.modules,service_runtime=runtime):result=app.ack_checkpoint()
        self.assertEqual(result['signature'],'A'*88)
        self.assertEqual(result['native_state'],{'pool':'unchanged'})

    def test_unrelated_method_and_expired_gate_do_not_block(self):
        app,gateway=self.gate();gate=app.ack_gate();gate['expires_at']=0;app.save(app.ACK_GATE,gate)
        for method in ('getGenesisHash','getSignatureStatuses'):
            query=json.dumps({'method':method,'params':[['A'*88]]}).encode()
            response=json.dumps({'result':{'value':[{'confirmationStatus':'finalized','err':None,'slot':1}]}}).encode()
            with patch.object(app.Gateway,'forward',return_value=response):self.assertEqual(gateway.forward(query),response)
        gateway.release.wait.assert_not_called()

    def test_test_gateway_counts_broadcast_attempts_even_when_upstream_fails(self):
        app,gateway=self.gate();query=json.dumps({'method':'sendTransaction','params':['signed transaction']}).encode()
        result=json.dumps({'result':'C'*88}).encode()
        with patch.object(app.Gateway,'forward',return_value=result):self.assertEqual(gateway.forward(query),result)
        with patch.object(app.Gateway,'forward',side_effect=OSError('connection lost')):
            with self.assertRaises(OSError):gateway.forward(query)
        attempts=gateway.broadcasts()['attempts']
        self.assertEqual(len(attempts),2);self.assertEqual(attempts[0]['signature'],'C'*88)
        self.assertIsNone(attempts[1]['signature']);self.assertEqual(attempts[1]['request_sha256'],hashlib.sha256(query).hexdigest())

    def test_package_recovery_records_and_denies_broadcast_before_upstream(self):
        app=self.app;gateway=object.__new__(app.PackageRecoveryGateway)
        read=b'{"method":"getSignatureStatuses"}';send=b'{"method":"sendTransaction","params":["original or replacement"]}'
        with patch.object(app.Gateway,'forward',return_value=b'authentic upstream status') as forward:
            self.assertEqual(gateway.forward(read),b'authentic upstream status')
            forward.assert_called_once_with(read);forward.reset_mock()
            with self.assertRaisesRegex(ValueError,'must not broadcast'):gateway.forward(send)
            forward.assert_not_called()
            path,raw=app.private.call_args.args
            self.assertEqual(path,app.ROOT/'package-recovery-broadcast-attempt-023.json')
            self.assertTrue(json.loads(raw)['attempted'])
            self.assertEqual(json.loads(raw)['request_sha256'],hashlib.sha256(send).hexdigest())

    def test_authenticated_https_handler_never_leaks_the_selected_finalized_reply(self):
        from local_test_tls import create
        from service_tls import TLSServer,context
        from testnet_gateway import Handler
        app,gateway=self.gate();gateway.faucet=Mock()
        tls=app.ROOT/'tls';create(tls)
        server=TLSServer(('127.0.0.1',0),Handler,context(tls/'server.crt',tls/'server.key'))
        server.authority='127.0.0.1:'+str(server.server_address[1]);server.app=gateway
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        client_context=ssl.create_default_context(cafile=str(tls/'ca.crt'));client_context.verify_flags|=ssl.VERIFY_X509_STRICT
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=client_context))
        query=json.dumps({'jsonrpc':'2.0','id':1,'method':'getSignatureStatuses','params':[['A'*88]]}).encode()
        reply=json.dumps({'result':{'value':[{'confirmationStatus':'finalized','err':None,'slot':11}]}}).encode()
        try:
            with patch.object(app.Gateway,'forward',return_value=reply) as upstream:
                request=urllib.request.Request('https://'+server.authority,query,{'Content-Type':'application/json'})
                with self.assertRaises(urllib.error.HTTPError) as rejected:opener.open(request,timeout=5)
                self.assertEqual(rejected.exception.code,403);rejected.exception.close();upstream.assert_not_called()
                request.add_header('X-Testnet-Access',base64.urlsafe_b64encode(b'{"signature":"authorized test proof"}').decode())
                with self.assertRaises(urllib.error.HTTPError) as withheld:opener.open(request,timeout=5)
                self.assertEqual(withheld.exception.code,403)
                self.assertEqual(json.loads(withheld.exception.read()),{'error':'access_denied'});withheld.exception.close()
                self.assertEqual(app.ack_gate()['phase'],'held');upstream.assert_called_once()
        finally:server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':unittest.main()
