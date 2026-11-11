import base64
import gzip
import hashlib
import http.client
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
import urllib.error
import urllib.request
import unittest
from unittest.mock import patch

from testnet_gateway import (Handler, Gateway, history_slots, read_calls, batch_results,
                            HISTORY_PAGE, HistoryTooLarge, HISTORY_SIZE_CODE, HISTORY_SIZE_MESSAGE,
                            RELAY_CAPACITY_CODE, RELAY_CAPACITY_MESSAGE, accepts_history_gzip, history_encoding)
from shielded_relay import RelayCapacityError
from wallet_ui import WalletApp


class GatewayTests(unittest.TestCase):
    def request(self, body, access=None, headers=None, limit=False, authorize_limit=None, app_error=None, app_body=None,
                retained_count=0, bulk_ack=..., bulk_error=None, authorize_many=False, compact_headers_per_unit=16,
                raw_body=None):
        calls=[]
        self.last_forwarded = None
        class Faucet:
            def ingress(self, channel, peer, units=1):
                calls.append(('ingress',channel,peer) if units == 1 else ('ingress',channel,peer,units))
                if limit: raise ValueError('request quota exhausted')
            def command(self, command, data, extra=()):
                calls.append((command,data) if not extra else (command,data,extra))
                used=sum(1 if c[0]=='authorize' else int(c[2][1]) if c[0]=='authorize-many' else 0 for c in calls)
                if authorize_limit is not None and used > authorize_limit:
                    raise ValueError('request quota exhausted')
                if data!={'signature':'valid'}: raise ValueError('invalid proof')
                if command=='authorize-many':
                    if bulk_error is not None:raise bulk_error
                    return bulk_ack if bulk_ack is not ... else dict(authorized=True,units=int(extra[1]))
        class App:
            faucet=Faucet()
            def shielded(self, request, proof):
                calls.append(('shielded',request['method'],proof))
                if app_error is not None: raise app_error
                return app_body if app_body is not None else b'{"result":{"id":"original"}}'
            def read_batch(self, request, reads):
                calls.append(('reads',reads)); return json.dumps({'result':reads}).encode()
            def history_blocks(self, request, slots):
                calls.append(('history',slots))
                if app_error is not None:raise app_error
                return app_body if app_body is not None else json.dumps({'result':slots}).encode()
            def retained_history(self, request):
                calls.append(('retained',request['params'])); return b'{"result":null}'
            def retained_history_v2(self, request, deadline):
                calls.append(('retained-v2',request['params']))
                if app_error is not None:raise app_error
                return app_body if app_body is not None else b'{"result":null}', retained_count
            def retained_history_v3(self, request, deadline):
                calls.append(('retained-v3',request['params']))
                if app_error is not None:raise app_error
                return app_body if app_body is not None else b'{"result":null}', retained_count
            def canonical_history(self, request):
                calls.append(('canonical',request['params'])); return b'{"result":null}'
            def sync_snapshot(self, request, deadline):
                calls.append(('snapshot',request['params'],deadline))
                if app_error is not None:raise app_error
                return app_body if app_body is not None else b'{"result":null}'
            def forward(app, raw):
                self.last_forwarded = raw
                calls.append(('forward',json.loads(raw)))
                if app_error is not None:raise app_error
                return app_body if app_body is not None else b'{"jsonrpc":"2.0","id":1,"result":"genuine-upstream"}'
        handler=object.__new__(Handler)
        app=App();app.authorize_many=authorize_many;app.compact_headers_per_unit=compact_headers_per_unit
        handler.server=type('Server',(),dict(authority='127.0.0.1:18898',app=app))()
        handler.client_address=('127.0.0.1',3456); handler.path='/'
        raw = json.dumps(body).encode() if raw_body is None else raw_body
        handler.rfile=io.BytesIO(raw); handler.wfile=io.BytesIO()
        handler.headers=Message()
        for key,value in {'Host':'127.0.0.1:18898','Content-Type':'application/json','Content-Length':str(len(raw)), **(headers or {})}.items(): handler.headers[key]=value
        if access is not None: handler.headers['X-Testnet-Access']=access
        response=[]
        handler.send_response=lambda code:response.append(code)
        self.last_headers={}
        handler.send_header=lambda key,value:self.last_headers.__setitem__(key,value); handler.end_headers=lambda:None
        handler.do_POST()
        self.last_wire=handler.wfile.getvalue()
        decoded=gzip.decompress(self.last_wire) if self.last_headers.get('Content-Encoding')=='gzip' else self.last_wire
        return response[0],json.loads(decoded),calls

    def test_authorized_forwarding_preserves_the_original_rpc_body_bytes(self):
        header = base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        raw = b'{ "params" : [ "disposable-transaction" ], "method" : "sendTransaction", "id" : "original", "jsonrpc" : "2.0" }'
        code, _, calls = self.request(None, header, raw_body=raw)
        self.assertEqual(code, 200)
        self.assertEqual(self.last_forwarded, raw)
        self.assertEqual([call[0] for call in calls], ['ingress', 'authorize', 'forward'])
        code, _, calls = self.request(None, raw_body=raw)
        self.assertEqual(code, 403)
        self.assertIsNone(self.last_forwarded)
        self.assertFalse(any(call[0] == 'forward' for call in calls))

    def test_shielded_methods_require_fresh_authorization_and_never_forward_to_raw_rpc(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        for method in ('getShieldedFeeQuote','submitShieldedPayment','getShieldedPaymentStatus'):
            request=dict(jsonrpc='2.0',id=1,method=method,params=[])
            code,_,seen=self.request(request)
            self.assertEqual(code,403)
            self.assertFalse(any(s[0] in ('shielded','forward') for s in seen))
            code,_,seen=self.request(request,header)
            self.assertEqual(code,200)
            self.assertEqual([s[0] for s in seen],['ingress','authorize','shielded'])
            code,_,seen=self.request(request,header,authorize_limit=0)
            self.assertEqual(code,429)
            self.assertFalse(any(s[0] in ('shielded','forward') for s in seen))

    def test_capacity_error_is_an_exact_safe_rpc_error_after_normal_authorization(self):
        header = base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        gateway = object.__new__(Gateway)
        for scope in ('member', 'network'):
            for method in ('getShieldedFeeQuote', 'submitShieldedPayment'):
                seen = []
                class Relay:
                    def dispatch(self, method, params, member):
                        seen.append((method, params, member))
                        raise RelayCapacityError(scope)
                gateway.relay = Relay()
                request = dict(jsonrpc='2.0', id='original-id', method=method, params=[])
                payload = gateway.shielded(request, {'fee_address': 'private-member-fixture'})
                expected = dict(jsonrpc='2.0', id='original-id', error=dict(
                    code=-32040, message='Testnet private payment capacity reached', data=dict(scope=scope)))
                self.assertEqual(json.loads(payload), expected)
                self.assertEqual(RELAY_CAPACITY_CODE, -32040)
                self.assertEqual(RELAY_CAPACITY_MESSAGE, expected['error']['message'])
                self.assertEqual(seen, [(method, [], 'private-member-fixture')])
                code, body, calls = self.request(request, header, app_body=payload)
                self.assertEqual(code, 200)
                self.assertEqual(body, expected)
                self.assertEqual([call[0] for call in calls], ['ingress', 'authorize', 'shielded'])
                self.assertNotIn('Retry-After', self.last_headers)
                self.assertNotIn(b'private-member-fixture', payload)
                self.assertNotIn(b'quota exhausted', payload)

    def test_unrelated_relay_errors_keep_existing_refusal_behavior(self):
        gateway = object.__new__(Gateway)
        header = base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request = dict(jsonrpc='2.0', id=1, method='submitShieldedPayment', params=[])
        for error, status in ((ValueError('private unrelated detail'), 403),
                              (ValueError('request quota exhausted'), 429), (OSError('private file detail'), 403)):
            class Relay:
                def dispatch(self, *_):
                    raise error
            gateway.relay = Relay()
            with self.assertRaises(type(error)) as refusal:
                gateway.shielded(request, {'fee_address': 'private-member-fixture'})
            self.assertIs(refusal.exception, error)
            code, body, _ = self.request(request, header, app_error=error)
            self.assertEqual(code, status)
            self.assertEqual(body, {'error': 'request_limit' if status == 429 else 'access_denied'})

    def test_aggregate_is_read_only_bounded_and_each_read_consumes_authorization(self):
        calls=[dict(method='getFeeForMessage',params=['AAAA',{'commitment':'confirmed'}]),
               dict(method='getMinimumBalanceForRentExemption',params=[0])]
        request=dict(jsonrpc='2.0',id=1,method='getWalletReadBatch',params=[calls])
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        code,_,seen=self.request(request,header)
        self.assertEqual(code,200)
        self.assertEqual([s[0] for s in seen],['ingress','authorize','authorize','reads'])
        self.assertEqual(self.request(request)[0],403)
        code,_,seen=self.request(request,header,authorize_limit=1)
        self.assertEqual(code,429)
        self.assertFalse(any(s[0] in ('reads','forward') for s in seen))
        invalid=[[],calls*9,[dict(method='sendTransaction',params=['signed'])],
                 [dict(method='getBlock',params=[1])],[dict(calls[0],extra=1)],
                 [dict(method='getFeeForMessage',params=['?',{'commitment':'confirmed'}])],
                 [dict(method='getMinimumBalanceForRentExemption',params=[True])],
                 [dict(method='getSlot',params=[{'commitment':'processed'}])]]
        for value in invalid:
            code,_,seen=self.request(dict(request,params=[value]),header)
            self.assertEqual(code,403)
            self.assertFalse(any(s[0] in ('authorize','reads','forward') for s in seen))

    def test_aggregate_refuses_wrong_upstream_identity_error_partial_or_oversized_result(self):
        gateway=object.__new__(Gateway);seen=[]
        calls=[dict(method='getMinimumBalanceForRentExemption',params=[0]),dict(method='getLatestBlockhash',params=[{'commitment':'confirmed'}])]
        def forward(raw,timeout):
            self.assertGreater(timeout,0);self.assertLessEqual(timeout,15)
            query=json.loads(raw);seen.append(query)
            return json.dumps(dict(jsonrpc='2.0',id=query['id'],result={'value':5000 if query['method']=='getMinimumBalanceForRentExemption' else 5001})).encode()
        gateway.forward=forward
        result=json.loads(gateway.read_batch({'id':'original'},calls))
        self.assertEqual(result['id'],'original');self.assertEqual([r['request'] for r in result['result']],calls)
        self.assertEqual([r['result']['value'] for r in result['result']],[5000,5001])
        self.assertEqual(len(seen),2);self.assertEqual([q['method'] for q in seen],[r['method'] for r in calls])
        self.assertTrue(all(q['id']==0 for q in seen))
        good=[dict(jsonrpc='2.0',id=i,result=0) for i in range(2)]
        for response in [{},[],good[:1],good+[good[0]],
                         [dict(good[0],id=True),good[1]],[dict(good[0],id='0'),good[1]],
                         [good[0],good[0]],[dict(good[0],error=None),good[1]],
                         [dict(good[0],jsonrpc='1.0'),good[1]],[dict(good[0],result=None),good[1]],
                         [dict(good[0],result='x'*(1024*1024)),good[1]]]:
            gateway.forward=lambda raw,timeout:json.dumps(response).encode()
            with self.subTest(response_kind=type(response).__name__):
                with self.assertRaises(ValueError):gateway.read_batch({'id':1},calls)
        gateway.forward=forward
        with patch('testnet_gateway.time.monotonic',side_effect=[0,16]):
            with self.assertRaisesRegex(ValueError,'deadline'):gateway.read_batch({'id':1},calls)
        with self.assertRaisesRegex(ValueError,'only bounded wallet reads'):
            gateway.read_batch({'id':1},[dict(method='sendTransaction',params=['write'])])

    def test_public_genesis_and_member_rpc_are_charged_before_forwarding(self):
        genesis=dict(jsonrpc='2.0',id=1,method='getGenesisHash')
        code,_,calls=self.request(genesis,headers={'X-Forwarded-For':'attacker-controlled'})
        self.assertEqual(code,200); self.assertEqual(calls[0],('ingress','rpc','127.0.0.1'))
        self.assertEqual(self.request(dict(genesis, params=None))[0],200)
        request=dict(jsonrpc='2.0',id=1,method='sendTransaction',params=['signed-native-transaction'])
        code,_,calls=self.request(request)
        self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        code,_,calls=self.request(request,header)
        self.assertEqual(code,200); self.assertEqual([c[0] for c in calls],['ingress','authorize','forward'])
        code,_,calls=self.request(request,header,limit=True)
        self.assertEqual(code,429); self.assertEqual(len(calls),1)

    def test_malformed_envelopes_methods_headers_and_batches_never_reach_upstream(self):
        genesis=dict(jsonrpc='2.0',id=1,method='getGenesisHash')
        for request in [[], {}, dict(genesis,method={}), dict(genesis,method=[]), dict(genesis,id=True), dict(genesis,params={}), dict(genesis,method='getIdentity'),dict(genesis,extra='unbounded'),dict(genesis,id='x'*65)]:
            with self.subTest(request=request):
                code,_,calls=self.request(request)
                self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))
        for headers in [{'Host':'evil.invalid'},{'Origin':'http://evil.invalid'},{'Content-Length':'32769'},{'Transfer-Encoding':'chunked'},{'Content-Type':'text/plain'}]:
            code,_,calls=self.request(genesis,headers=headers)
            self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))
        for header in ['?', 'x'*3073, base64.urlsafe_b64encode(b'{}').decode()]:
            code,_,calls=self.request(dict(genesis,method='getBalance'),header)
            self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))

    def test_quota_wait_is_bounded_until_next_minute_and_denials_do_not_suggest_retry(self):
        request=dict(jsonrpc='2.0',id=1,method='getGenesisHash')
        for clock,expected in [(120,61),(179,2)]:
            with patch('testnet_gateway.time.time',return_value=clock):
                self.assertEqual(self.request(request,limit=True)[0],429)
                self.assertEqual(self.last_headers['Retry-After'],str(expected))
        self.assertEqual(self.request(dict(request,method='getIdentity'))[0],403)
        self.assertNotIn('Retry-After',self.last_headers)

    def test_history_reads_are_bounded_read_only_and_use_original_per_rpc_authorization(self):
        request=dict(jsonrpc='2.0',id=1,method='getWalletHistoryBlocks',params=[list(range(1,17))])
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        code,body,calls=self.request(request,header)
        self.assertEqual(code,200); self.assertEqual(body['result'],list(range(1,17)))
        self.assertEqual(calls[0],('ingress','rpc','127.0.0.1'))
        self.assertEqual(calls[1],('authorize',{'signature':'valid'}))
        self.assertEqual([c[0] for c in calls],['ingress','authorize','history'])
        code,_,calls=self.request(request,header,authorize_limit=0)
        self.assertEqual(code,429);self.assertFalse(any(c[0] in ('history','forward') for c in calls))
        for params in [None,[],[[]],[[0]],[[True]],[[1,1]],[[2,1]],[[2**64]],[[1.0]],[list(range(1,HISTORY_PAGE+2))],[[1],{'commitment':'processed'}]]:
            code,_,calls=self.request(dict(request,params=params),header)
            self.assertEqual(code,403);self.assertFalse(any(c[0] in ('forward','history') for c in calls))
        code,_,calls=self.request(request,None)
        self.assertEqual(code,403);self.assertFalse(any(c[0]=='history' for c in calls))

    def test_large_history_pages_preserve_every_original16_block_authorization_charge(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        for count in (1,16,17,32,33,255,256):
            with self.subTest(count=count):
                slots=list(range(1,count+1))
                request=dict(jsonrpc='2.0',id=1,method='getWalletHistoryBlocks',params=[slots])
                code,body,calls=self.request(request,header)
                self.assertEqual(code,200);self.assertEqual(body['result'],slots)
                self.assertEqual(len([c for c in calls if c[0]=='authorize']),(count+15)//16)
                self.assertEqual([c[0] for c in calls if c[0]!='authorize'],['ingress','history'])
        request=dict(jsonrpc='2.0',id=1,method='getWalletHistoryBlocks',params=[list(range(1,257))])
        code,_,calls=self.request(request,header,authorize_limit=15)
        self.assertEqual(code,429)
        self.assertEqual(len([c for c in calls if c[0]=='authorize']),16)
        self.assertFalse(any(c[0] in ('history','forward') for c in calls))
        # A large valid page still cannot turn an external JSON-RPC batch into
        # an admitted request or enlarge the separate small-read aggregator.
        code,_,calls=self.request([request],header)
        self.assertEqual(code,403);self.assertFalse(any(c[0]=='authorize' for c in calls))
        reads=[dict(method='getSlot',params=[{'commitment':'finalized'}])]*17
        code,_,calls=self.request(dict(request,method='getWalletReadBatch',params=[reads]),header)
        self.assertEqual(code,403);self.assertFalse(any(c[0] in ('authorize','reads','forward') for c in calls))

    def test_explicit_bulk_capability_keeps_history_and_read_units_with_one_debit(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        for count in (1,16,17,32,33,255,256):
            request=dict(jsonrpc='2.0',id=1,method='getWalletHistoryBlocks',params=[list(range(1,count+1))])
            units=(count+15)//16
            with self.subTest(method=request['method'],count=count):
                code,body,calls=self.request(request,header,authorize_many=True,authorize_limit=units)
                self.assertEqual(code,200);self.assertEqual(body['result'],request['params'][0])
                command='authorize-many' if units>1 else 'authorize'
                self.assertEqual([c[0] for c in calls],['ingress',command,'history'])
                if units>1:self.assertEqual(calls[1],(command,{'signature':'valid'},['--units',str(units)]))
                code,_,calls=self.request(request,header,authorize_many=True,authorize_limit=units-1)
                self.assertEqual(code,429);self.assertEqual([c[0] for c in calls],['ingress',command])
        for count in (1,2,15,16):
            reads=[dict(method='getSlot',params=[{'commitment':'finalized'}])]*count
            request=dict(jsonrpc='2.0',id=1,method='getWalletReadBatch',params=[reads])
            with self.subTest(method=request['method'],count=count):
                code,body,calls=self.request(request,header,authorize_many=True,authorize_limit=count)
                self.assertEqual(code,200);self.assertEqual(body['result'],reads)
                command='authorize-many' if count>1 else 'authorize'
                self.assertEqual([c[0] for c in calls],['ingress',command,'reads'])
                if count>1:self.assertEqual(calls[1],(command,{'signature':'valid'},['--units',str(count)]))
                code,_,calls=self.request(request,header,authorize_many=True,authorize_limit=count-1)
                self.assertEqual(code,429);self.assertFalse(any(c[0]=='reads' for c in calls))
        # Even a truthy value cannot silently opt an old caller into a new command.
        for capability in (False,None,0,1,'true'):
            code,_,calls=self.request(request,header,authorize_many=capability)
            self.assertEqual(code,200);self.assertEqual([c[0] for c in calls],['ingress']+['authorize']*16+['reads'])

    def test_bulk_authorization_denials_and_malformed_ack_never_expose_or_retry_reads(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        requests=[dict(jsonrpc='2.0',id=1,method='getWalletHistoryBlocks',params=[list(range(1,18))]),
                  dict(jsonrpc='2.0',id=1,method='getWalletReadBatch',params=[
                      [dict(method='getSlot',params=[{'commitment':'finalized'}])]*2])]
        invalid=(None,False,[],{}, {'authorized':False,'units':2},{'authorized':1,'units':2},
                 {'authorized':True,'units':1},{'authorized':True,'units':True},
                 {'authorized':True,'units':2.0},{'authorized':True,'units':'2'},{'authorized':True})
        failures=[dict(bulk_ack=ack) for ack in invalid]
        failures += [dict(bulk_error=ValueError(error)) for error in
                     ('request quota exhausted','revoked','membership expired','proof expired','invitation required','unknown faucet command')]
        for request in requests:
            for arguments in failures:
                with self.subTest(method=request['method'],arguments=arguments),patch('testnet_gateway.gzip.compress') as compress:
                    code,body,calls=self.request(request,header,authorize_many=True,
                        headers={'Accept-Encoding':'gzip'},**arguments)
                    self.assertEqual(code,429 if 'quota exhausted' in str(arguments) else 403)
                    self.assertNotIn('result',body);self.assertNotIn('jsonrpc',body)
                    self.assertEqual([c[0] for c in calls],['ingress','authorize-many'])
                    self.assertNotIn('Content-Encoding',self.last_headers);compress.assert_not_called()
            for access in (None,base64.urlsafe_b64encode(b'{"signature":"invalid"}').decode()):
                code,_,calls=self.request(request,access,authorize_many=True)
                self.assertEqual(code,403);self.assertFalse(any(c[0] in ('reads','history','forward') for c in calls))
        for invalid_request in ([requests[0]],dict(requests[0],params=[list(range(1,258))]),
                dict(requests[1],params=[requests[1]['params'][0]*9])):
            code,_,calls=self.request(invalid_request,header,authorize_many=True)
            self.assertEqual(code,403);self.assertEqual([c[0] for c in calls],['ingress'])

    def test_bulk_authorization_checks_deadline_before_and_after_exact_ack(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id=1,method='getWalletHistoryBlocks',params=[list(range(1,18))])
        for clock,expected in (([0,15],['ingress']),([0,1,15],['ingress','authorize-many'])):
            with self.subTest(clock=clock),patch('testnet_gateway.time.monotonic',side_effect=clock):
                code,body,calls=self.request(request,header,authorize_many=True)
                self.assertEqual(code,403);self.assertNotIn('result',body)
                self.assertEqual([c[0] for c in calls],expected)

    def test_only_explicit_authenticated_history_overflow_has_a_typed_retry_response(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id='original',method='getWalletHistoryBlocks',params=[list(range(1,18))])
        error=HistoryTooLarge(HISTORY_SIZE_MESSAGE)
        code,body,calls=self.request(request,header,app_error=error)
        self.assertEqual(code,200)
        self.assertEqual(body,dict(jsonrpc='2.0',id='original',error=dict(code=HISTORY_SIZE_CODE,message=HISTORY_SIZE_MESSAGE)))
        self.assertEqual([c[0] for c in calls],['ingress','authorize','authorize','history'])
        for changed,access,quota,expected in ((request,None,None,403),(request,header,1,429),
                (dict(request,params=[[0]]),header,None,403),
                (dict(request,method='getBlock',params=[]),header,None,403),
                (dict(request,method='getGenesisHash',params=[]),None,None,403)):
            code,body,_=self.request(changed,access,authorize_limit=quota,app_error=error)
            self.assertEqual(code,expected);self.assertNotIn('jsonrpc',body)
        for error in (ValueError('RPC response exceeds gateway limit'),ValueError('missing block'),
                      ValueError('wallet history/read deadline exceeded')):
            code,body,_=self.request(request,header,app_error=error)
            self.assertEqual(code,403);self.assertNotIn('jsonrpc',body)

    def test_retained_pages_require_original_authorization_and_never_rewrite_canonical_methods(self):
        request=dict(jsonrpc='2.0',id=1,method='getWalletRetainedHistory',params=[0,100,None])
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        self.assertEqual(self.request(request)[0],403)
        code,_,calls=self.request(request,header)
        self.assertEqual(code,200)
        self.assertEqual([c[0] for c in calls],['ingress','authorize','retained'])
        self.assertEqual(self.request(request,header,limit=True)[0],429)
        for params in [[],[0,100],[0,True,None],[-1,100,None],[0,100,'../file'],[0,100,{'segments':1,'sha256':'a'*64,'path':'outside'}]]:
            code,_,calls=self.request(dict(request,params=params),header)
            self.assertEqual(code,403);self.assertFalse(any(c[0]=='retained' for c in calls))
        for method in ['getBlocks','getBlock','getTransaction','getSignatureStatuses']:
            code,_,calls=self.request(dict(request,method=method,params=[]),header)
            self.assertEqual(code,200);self.assertEqual(calls[-1][0],'forward')

    def test_history_aggregation_fixes_encoding_finality_and_refuses_missing_or_oversized_blocks(self):
        gateway=object.__new__(Gateway);batches=[]
        def forward(raw,timeout=15):
            self.assertGreater(timeout,0);self.assertLessEqual(timeout,15)
            query=json.loads(raw);batches.append(query)
            return json.dumps({'jsonrpc':'2.0','id':query['id'],'result':{'transactions':[{'full':'proof-'+str(query['params'][0])}]}}).encode()
        gateway.forward=forward
        request=dict(id='same',method='getWalletHistoryBlocks')
        slots=list(range(1,17));result=json.loads(gateway.history_blocks(request,slots))
        self.assertEqual(result['id'],'same');self.assertEqual([b['slot'] for b in result['result']],slots)
        self.assertEqual([b['block']['transactions'][0]['full'] for b in result['result']],['proof-'+str(slot) for slot in slots])
        self.assertEqual(len(batches),16)
        for query in batches:
            self.assertEqual(query['id'],0);self.assertEqual(query['method'],'getBlock')
            self.assertEqual(query['params'][1],dict(encoding='base64',transactionDetails='full',rewards=False,commitment='finalized',maxSupportedTransactionVersion=0))
        for response in [[],[{'jsonrpc':'2.0','id':0,'result':None}],
                         [{'jsonrpc':'2.0','id':1,'result':{}}],
                         [{'jsonrpc':'2.0','id':0,'error':{'code':-1}}],
                         [{'jsonrpc':'2.0','id':0,'result':[]}],
                         [{'jsonrpc':'2.0','id':0,'result':{'data':'x'*(16*1024*1024)}}]]:
            gateway.forward=lambda raw,timeout=15:json.dumps(response).encode()
            with self.assertRaises(ValueError):gateway.history_blocks(request,[1])

    def test_history_uses_bounded_real_http_objects_and_preserves_every_full_transaction(self):
        observed=[];sizes=[]
        class Upstream(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']));sizes.append(len(raw));q=json.loads(raw)
                observed.append(q)
                body=json.dumps(dict(jsonrpc='2.0',id=q['id'],result=dict(parentSlot=q['params'][0]-1,
                    blockhash=str(q['params'][0]),previousBlockhash=str(q['params'][0]-1),
                    transactions=[dict(transaction=['entire-proof-ciphertext-'+str(q['params'][0]),'base64'],meta={'err':None})]))).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        server=HTTPServer(('127.0.0.1',0),Upstream);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            gateway=object.__new__(Gateway);gateway.operator=None;gateway.upstream='http://127.0.0.1:'+str(server.server_port)
            gateway.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            slots=list(range(100,100+HISTORY_PAGE));result=json.loads(gateway.history_blocks({'id':'outer'},slots))
            self.assertEqual(len(observed),HISTORY_PAGE)
            self.assertTrue(all(isinstance(query,dict) and query['id']==0 for query in observed))
            self.assertEqual([item['slot'] for item in result['result']],slots)
            self.assertEqual([item['block']['transactions'][0]['transaction'][0] for item in result['result']],
                ['entire-proof-ciphertext-'+str(slot) for slot in slots])
            self.assertLessEqual(sizes[0],48*1024)
            # Maximal u64 slots remain legal, with every complete original
            # object and full block retained in original order.
            observed.clear();sizes.clear();slots=list(range(2**64-HISTORY_PAGE,2**64))
            result=json.loads(gateway.history_blocks({'id':'u64'},slots))
            self.assertEqual(len(observed),HISTORY_PAGE)
            self.assertTrue(all(size<=48*1024 for size in sizes))
            self.assertTrue(all(query['id']==0 for query in observed))
            self.assertEqual([item['slot'] for item in result['result']],slots)
            self.assertEqual([item['block']['transactions'][0]['transaction'][0] for item in result['result']],
                ['entire-proof-ciphertext-'+str(slot) for slot in slots])
        finally:server.shutdown();server.server_close();thread.join(timeout=5)

    def test_upstream_batch_requires_exact_envelopes_ids_and_unambiguous_finite_json(self):
        good=[dict(jsonrpc='2.0',id=i,result={'blockhash':str(i)}) for i in range(3)]
        self.assertEqual(batch_results(json.dumps(good[::-1]).encode(),3),[r['result'] for r in good])
        malformed=[{},[],good[:2],good+[good[0]],[good[0],good[1],good[1]],
            [dict(good[0],id=True),*good[1:]],[dict(good[0],id=0.0),*good[1:]],
            [dict(good[0],id='0'),*good[1:]],[dict(good[0],id=3),*good[1:]],
            [dict(good[0],error=None),*good[1:]],[dict(good[0],extra=1),*good[1:]],
            [dict(good[0],result=None),*good[1:]],[dict(good[0],jsonrpc='1.0'),*good[1:]]]
        for value in malformed:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):batch_results(json.dumps(value).encode(),3)
        for raw in [b'[{"jsonrpc":"2.0","id":0,"id":1,"result":{}}]',
                    b'[{"jsonrpc":"2.0","id":0,"result":{"x":1,"x":2}}]',
                    b'[{"jsonrpc":"2.0","id":0,"result":NaN}]',b'not-json',b'[] trailing']:
            with self.assertRaises(ValueError):batch_results(raw,1)
        with self.assertRaisesRegex(ValueError,'exceeds gateway limit'):batch_results(b' '*(16*1024*1024+1),1)

    def test_large_upstream_batch_is_history_only_and_still_requires_exact_complete_ids(self):
        good=[dict(jsonrpc='2.0',id=i,result={'blockhash':str(i)}) for i in range(HISTORY_PAGE)]
        raw=json.dumps(good[::-1]).encode()
        with self.assertRaises(ValueError):batch_results(raw,HISTORY_PAGE)
        self.assertEqual(batch_results(raw,HISTORY_PAGE,max_count=HISTORY_PAGE),[v['result'] for v in good])
        for count,maximum in ((257,256),(17,16),(1,257),(1,True),(True,256)):
            with self.assertRaises(ValueError):batch_results(raw,count,max_count=maximum)
        for last in (dict(good[-1],id=254),dict(good[-1],id=256),dict(good[-1],id=255.0),
                     dict(good[-1],id=True),dict(good[-1],result=None),dict(good[-1],error=None)):
            with self.subTest(last=last):
                with self.assertRaises(ValueError):batch_results(json.dumps(good[:-1]+[last]).encode(),HISTORY_PAGE,max_count=HISTORY_PAGE)
        with self.assertRaises(ValueError):batch_results(json.dumps(good[:-1]).encode(),HISTORY_PAGE,max_count=HISTORY_PAGE)
        gateway=object.__new__(Gateway);seen=[]
        gateway.forward=lambda raw,timeout:seen.append(raw)
        history=[dict(method='getBlock',params=[i,{}]) for i in range(1,18)]
        read=dict(method='getSlot',params=[{'commitment':'finalized'}])
        for calls,mode in ((history,False),(history+[read],True),([read]*17,False),(history*16,True)):
            with self.assertRaises(ValueError):gateway._upstream_reads(calls,1e100,history=mode)
        self.assertEqual(seen,[])

    def test_single_history_keeps_one_deadline_and_one_aggregate_response_budget(self):
        gateway=object.__new__(Gateway);seen=[]
        def forward(raw,timeout):
            query=json.loads(raw);seen.append(query)
            return json.dumps(dict(jsonrpc='2.0',id=query['id'],result={'data':'x'*160})).encode()
        gateway.forward=forward;slots=list(range(2**64-HISTORY_PAGE,2**64))
        with patch('testnet_gateway.RESPONSE_LIMIT',32768):
            with self.assertRaises(HistoryTooLarge):gateway.history_blocks({'id':1},slots)
        self.assertGreater(len(seen),1);self.assertLess(len(seen),HISTORY_PAGE)
        self.assertTrue(all(query['id']==0 for query in seen))
        seen.clear()
        with patch('testnet_gateway.time.monotonic',side_effect=[0,1,2,3,16]):
            with self.assertRaisesRegex(ValueError,'deadline exceeded'):gateway.history_blocks({'id':1},slots)
        self.assertEqual(len(seen),1)

    def test_internal_http413_and_local_byte_overflow_are_typed_only_for_history(self):
        gateway=object.__new__(Gateway)
        def fail(code):
            def forward(raw,timeout):raise urllib.error.HTTPError('http://127.0.0.1:1',code,'upstream',{},None)
            return forward
        gateway.forward=fail(413)
        with self.assertRaises(HistoryTooLarge):gateway.history_blocks({'id':1},[1])
        calls=[dict(method='getSlot',params=[{'commitment':'finalized'}])]
        with self.assertRaises(urllib.error.HTTPError):gateway.read_batch({'id':1},calls)
        for code in (400,403,429,500):
            gateway.forward=fail(code)
            with self.assertRaises(urllib.error.HTTPError):gateway.history_blocks({'id':1},[1])
        gateway.forward=lambda raw,timeout:b' '*(16*1024*1024+1)
        with self.assertRaises(HistoryTooLarge):gateway.history_blocks({'id':1},[1])
        # A stale oversized result cannot disguise an expired15s deadline.
        gateway.forward=fail(413)
        with patch('testnet_gateway.time.monotonic',side_effect=[0,1,16]):
            with self.assertRaisesRegex(ValueError,'deadline exceeded'):gateway.history_blocks({'id':1},[1])

    def test_canonical_pages_use_original_invitation_and_quota_before_archive_access(self):
        request=dict(jsonrpc='2.0',id=1,method='getWalletCanonicalHistory',params=[0,100,None])
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        self.assertEqual(self.request(request)[0],403)
        code,_,calls=self.request(request,header)
        self.assertEqual(code,200)
        self.assertEqual([c[0] for c in calls],['ingress','authorize','canonical'])
        self.assertEqual(self.request(request,header,limit=True)[0],429)
        for params in [[],[0,100],[0,True,None],[1,100,None],[0,100,'http://evil'],[0,100,{'slot':100,'blockhash':'1'*32,'block_height':1,'url':'http://evil'}]]:
            code,_,calls=self.request(dict(request,params=params),header)
            self.assertEqual(code,403);self.assertFalse(any(c[0]=='canonical' for c in calls))

    def test_history_deadline_and_exact_escaped_response_limit(self):
        gateway=object.__new__(Gateway)
        gateway.forward=lambda raw,timeout:json.dumps({'jsonrpc':'2.0','id':0,'result':{'data':'x'*(16*1024*1024-200)}}).encode()
        with self.assertRaises(HistoryTooLarge):
            gateway.history_blocks({'id':'😀'*64},[1])
        calls=[]
        gateway.forward=lambda raw,timeout:calls.append(timeout) or b'{"jsonrpc":"2.0","id":0,"result":{}}'
        with patch('testnet_gateway.time.monotonic',side_effect=[0,1,16]):
            with self.assertRaisesRegex(ValueError,'deadline exceeded'):gateway.history_blocks({'id':1},[1,2])
        self.assertEqual(calls,[14])

    def test_gzip_negotiation_is_explicit_bounded_and_honors_exclusion(self):
        for values in (['gzip'],['GZip'],['gzip, br, deflate'],['br;q=1, gzip;q=0.001'],
                       [' gzip ; q=1.000 '],['gzip;q=1, *;q=0']):
            with self.subTest(values=values):self.assertTrue(accepts_history_gzip(values))
        for values in ([],[''],['br'],['*'],['gzip;q=0'],['gzip;q=0.000, *;q=1'],
                       ['gzip','br'],['gzip,gzip'],['gzip,gzip;q=0'],['gzip;q=0.1234'],
                       ['gzip;q=2'],['gzip;q=-1'],['gzip;q=NaN'],['gzip;level=1'],
                       ['gzip,'],['gzip\r\nInjected:yes'],['gzip'+(' '*1024)],['gziπ']):
            with self.subTest(values=values):self.assertFalse(accepts_history_gzip(values))

    def test_retained_v2_charges_actual_headers_atomically_before_compression(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id='same',method='getWalletRetainedHistoryV2',params=[0,5000,None])
        body=json.dumps(dict(jsonrpc='2.0',id='same',result={'public':'ciphertext'*300})).encode()
        for count in (0,1,16,17,33,4096):
            with self.subTest(count=count):
                code,value,calls=self.request(request,header,headers={'Accept-Encoding':'gzip'},
                    retained_count=count,app_body=body)
                self.assertEqual(code,200);self.assertEqual(value,json.loads(body))
                expected=['ingress','authorize','retained-v2']+(['authorize-many'] if count>16 else [])
                self.assertEqual([c[0] for c in calls],expected)
                if count>16:self.assertEqual(calls[-1],('authorize-many',{'signature':'valid'},['--units',str((count+15)//16-1)]))
                self.assertEqual(self.last_headers['Content-Encoding'],'gzip')
                self.assertEqual(self.last_headers['Vary'],'Accept-Encoding')
        code,_,calls=self.request(request,header,retained_count=4096,authorize_limit=255)
        self.assertEqual(code,429);self.assertEqual([c[0] for c in calls],['ingress','authorize','retained-v2','authorize-many'])
        self.assertNotIn('Content-Encoding',self.last_headers);self.assertNotIn('Vary',self.last_headers)
        # V1 has its original single debit and uncompressed response contract.
        code,_,calls=self.request(dict(request,method='getWalletRetainedHistory'),header,headers={'Accept-Encoding':'gzip'})
        self.assertEqual(code,200);self.assertEqual([c[0] for c in calls],['ingress','authorize','retained'])
        self.assertNotIn('Vary',self.last_headers)

    def test_explicit_compact_resource_pricing_counts_headers_and_uncompressed_bytes(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id=1,method='getWalletRetainedHistoryV2',params=[0,40000,None,32768])
        cases=[(count,32,max(1,(count+255)//256)) for count in (0,1,16,17,255,256,257,4096,16384,32768)]
        cases += [(1,size,(size+65535)//65536) for size in (65535,65536,65537,131072,131073,16*1024*1024)]
        prefix=b'{"result":"';suffix=b'"}'
        for count,size,units in cases:
            body=prefix+b'x'*(size-len(prefix)-len(suffix))+suffix
            for encoding in ('gzip','identity'):
                with self.subTest(count=count,size=size,encoding=encoding):
                    code,value,calls=self.request(request,header,retained_count=count,app_body=body,
                        headers={'Accept-Encoding':encoding},authorize_many=True,compact_headers_per_unit=256,
                        authorize_limit=units)
                    self.assertEqual(code,200);self.assertEqual(value,json.loads(body))
                    expected=['ingress','authorize','retained-v2']+(['authorize-many'] if units>1 else [])
                    self.assertEqual([c[0] for c in calls],expected)
                    if units>1:self.assertEqual(calls[-1],('authorize-many',{'signature':'valid'},['--units',str(units-1)]))
        # The legacy default keeps the exact original per16-header policy.
        code,_,calls=self.request(request,header,retained_count=4096)
        self.assertEqual(code,200);self.assertEqual(calls[-1][2],['--units','255'])

    def test_compact_resource_policy_preserves_denials_ack_and_bounds(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id=1,method='getWalletRetainedHistoryV2',params=[0,40000,None,32768])
        options=dict(authorize_many=True,compact_headers_per_unit=256,retained_count=32768)
        failures=[dict(authorize_limit=127),dict(bulk_error=ValueError('revoked')),
                  dict(bulk_error=ValueError('membership expired')),dict(bulk_error=ValueError('proof expired'))]
        failures += [dict(bulk_ack=ack) for ack in (None,{},False,{'authorized':1,'units':127},
                     {'authorized':True,'units':True},{'authorized':True,'units':127.0},
                     {'authorized':True,'units':128},{'authorized':False,'units':127})]
        for arguments in failures:
            with self.subTest(arguments=arguments),patch('testnet_gateway.gzip.compress') as compress:
                code,value,calls=self.request(request,header,headers={'Accept-Encoding':'gzip'},**options,**arguments)
                self.assertEqual(code,429 if 'authorize_limit' in arguments else 403)
                self.assertNotIn('result',value);self.assertEqual(calls[-1][2],['--units','127'])
                self.assertNotIn('Content-Encoding',self.last_headers);compress.assert_not_called()
        # A dense low-header response still needs its byte debit before exposure.
        code,_,calls=self.request(request,header,authorize_many=True,compact_headers_per_unit=256,
            retained_count=1,app_body=b'x'*65537,authorize_limit=1)
        self.assertEqual(code,429);self.assertEqual(calls[-1][2],['--units','1'])
        for body in (b'x'*(16*1024*1024+1),'not bytes'):
            with patch('testnet_gateway.gzip.compress') as compress:
                code,value,calls=self.request(request,header,app_body=body,**options)
                self.assertEqual(code,403);self.assertNotIn('result',value)
                self.assertFalse(any(c[0]=='authorize-many' for c in calls));compress.assert_not_called()
        for policy,capability in ((0,True),(17,True),(True,True),(256.0,True),(256,False),(256,1)):
            code,_,calls=self.request(request,header,compact_headers_per_unit=policy,authorize_many=capability,
                retained_count=32768)
            self.assertEqual(code,403);self.assertFalse(any(c[0]=='authorize-many' for c in calls))

    def test_compact_resource_policy_keeps_legacy_history_and_individual_read_costs(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        for method,params,units,action in (
                ('getWalletHistoryBlocks',[list(range(1,257))],16,'history'),
                ('getWalletReadBatch',[[dict(method='getSlot',params=[{'commitment':'finalized'}])]*16],16,'reads'),
                ('getWalletRetainedHistory',[0,40000,None],1,'retained')):
            request=dict(jsonrpc='2.0',id=1,method=method,params=params)
            code,_,calls=self.request(request,header,authorize_many=True,compact_headers_per_unit=256,authorize_limit=units)
            self.assertEqual(code,200)
            self.assertEqual([c[0] for c in calls],['ingress','authorize-many' if units>1 else 'authorize',action])
            if units>1:self.assertEqual(calls[1][2],['--units',str(units)])

    def test_retained_v2_denials_and_invalid_bulk_ack_never_return_or_compress_history(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id=1,method='getWalletRetainedHistoryV2',params=[0,5000,None])
        cases=[dict(access=None),dict(access=header,authorize_limit=0),
               dict(access=header,app_error=ValueError('unavailable')),
               dict(access=header,bulk_error=ValueError('revoked'))]
        cases += [dict(access=header,bulk_ack=ack) for ack in
                  ({},{'authorized':False,'units':1},{'authorized':True,'units':2},
                   {'authorized':True,'units':True},{'authorized':True},['authorized'])]
        for arguments in cases:
            with self.subTest(arguments=arguments),patch('testnet_gateway.gzip.compress') as compress:
                access=arguments.pop('access')
                code,value,calls=self.request(request,access,retained_count=17,
                    headers={'Accept-Encoding':'gzip'},app_body=b'x'*2000,**arguments)
                self.assertIn(code,(403,429));self.assertNotIn('result',value)
                self.assertNotIn('Vary',self.last_headers);compress.assert_not_called()
                if access is None or arguments.get('authorize_limit')==0:
                    self.assertFalse(any(c[0]=='retained-v2' for c in calls))
        for count in (True,-1,4097,'17'):
            code,_,calls=self.request(request,header,retained_count=count)
            self.assertEqual(code,403);self.assertFalse(any(c[0]=='authorize-many' for c in calls))
        for params in ([],[0,True,None],[0,1,{'segments':True,'sha256':'a'*64}]):
            code,_,calls=self.request(dict(request,params=params),header)
            self.assertEqual(code,403);self.assertFalse(any(c[0] in ('authorize','retained-v2') for c in calls))

    def test_retained_v2_shared_deadline_and_original_byte_limit_fail_closed(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id=1,method='getWalletRetainedHistoryV2',params=[0,5000,None])
        code,_,_=self.request(request,header,app_body=b'x'*(16*1024*1024+1))
        self.assertEqual(code,403);self.assertNotIn('Vary',self.last_headers)
        handler=object.__new__(Handler);handler.headers=Message();handler.headers['Accept-Encoding']='gzip'
        calls=[]
        class Faucet:
            def command(self,command,proof,extra):
                calls.append(command);return dict(authorized=True,units=1)
        class App:
            faucet=Faucet()
            def retained_history_v2(self,request,deadline):
                self.deadline=deadline;return b'x'*2000,17
        app=App();handler.server=type('Server',(),dict(app=app))()
        for clock,charged in (([16],False),([1,16],True),([1,2,16],True)):
            calls.clear()
            with patch('testnet_gateway.time.monotonic',side_effect=clock),patch('testnet_gateway.gzip.compress') as compress:
                with self.assertRaisesRegex(ValueError,'deadline'):handler.retained_v2(request,{'signature':'valid'},15)
                self.assertEqual(bool(calls),charged);self.assertEqual(app.deadline,15);compress.assert_not_called()

    def test_retained_v2_gateway_uses_counted_bounded_reader_and_no_history_is_null(self):
        gateway=object.__new__(Gateway);gateway.history=None
        request=dict(jsonrpc='2.0',id='same',method='getWalletRetainedHistoryV2',params=[0,5000,None])
        raw,count=gateway.retained_history_v2(request,123)
        self.assertEqual(json.loads(raw),dict(jsonrpc='2.0',id='same',result=None));self.assertEqual(count,0)
        class Reader:
            def page_counted(self,received,*,max_blocks,deadline):
                self.received=(received,max_blocks,deadline);return b'public-history',4096
        gateway.history=Reader()
        self.assertEqual(gateway.retained_history_v2(request,123),(b'public-history',4096))
        self.assertEqual(gateway.history.received,(request,4096,123))
        wide=dict(request,params=[0,20000,None,16384])
        self.assertEqual(gateway.retained_history_v2(wide,123),(b'public-history',4096))
        self.assertEqual(gateway.history.received,(dict(wide,params=wide['params'][:3]),16384,123))
        for bound in (True,4096,32769,'32768'):
            with self.assertRaisesRegex(ValueError,'explicit retained page bound'):
                gateway.retained_history_v2(dict(wide,params=[0,20000,None,bound]),123)

    def test_explicit_wide_page_preserves_weighted_quota_and_legacy_limit(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id=1,method='getWalletRetainedHistoryV2',params=[0,20000,None,32768])
        code,_,calls=self.request(request,header,retained_count=32768,authorize_limit=2048)
        self.assertEqual(code,200)
        self.assertEqual(calls[-1],('authorize-many',{'signature':'valid'},['--units','2047']))
        code,_,_=self.request(dict(request,params=request['params'][:3]),header,retained_count=32768)
        self.assertEqual(code,403)

    def test_real_http_retained_v2_preserves_full_page_billing_and_persistent_framing(self):
        from gateway_history import History
        from history_retention_test import NETWORK, archive, block, segment
        charged=[]
        class Faucet:
            def ingress(self,*args):charged.append('edge')
            def command(self,command,proof,extra=()):
                if proof!={'signature':'valid'}:raise ValueError('invalid test proof')
                if command=='authorize':charged.append(1);return {'authorized':True}
                if command!='authorize-many' or extra!=['--units','1']:raise ValueError('invalid debit')
                charged.append(1);return dict(authorized=True,units=1)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'history';root.mkdir(mode=0o700)
            records=[block(i) for i in range(1,21)];archive(root,[segment(root,records)])
            gateway=object.__new__(Gateway);gateway.faucet=Faucet();gateway.history=History(root,NETWORK)
            server=HTTPServer(('127.0.0.1',0),Handler);server.authority='127.0.0.1:'+str(server.server_port);server.app=gateway
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            request=dict(jsonrpc='2.0',id='same',method='getWalletRetainedHistoryV2',params=[0,20,None])
            headers={'Content-Type':'application/json','X-Testnet-Access':base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()}
            socket_number=None
            try:
                for method,accept,count in (('getWalletRetainedHistoryV2','gzip',20),
                        ('getWalletRetainedHistoryV2','gzip;q=0',20),('getWalletRetainedHistory','gzip',16)):
                    connection.request('POST','/',json.dumps(dict(request,method=method)),dict(headers,**{'Accept-Encoding':accept}))
                    response=connection.getresponse();wire=response.read()
                    encoded=method.endswith('V2') and accept=='gzip'
                    self.assertEqual(response.status,200)
                    self.assertEqual(response.getheader('Content-Encoding'),'gzip' if encoded else None)
                    self.assertEqual(int(response.getheader('Content-Length')),len(wire))
                    value=json.loads(gzip.decompress(wire) if encoded else wire)
                    self.assertEqual(value['id'],'same');self.assertEqual(value['result']['blocks'],records[:count])
                    self.assertEqual(response.getheader('Vary'),'Accept-Encoding' if method.endswith('V2') else None)
                    if socket_number is None:socket_number=connection.sock.fileno()
                    else:self.assertEqual(connection.sock.fileno(),socket_number)
                self.assertEqual(charged,['edge',1,1,'edge',1,1,'edge',1])
            finally:
                connection.close();server.shutdown();server.server_close();thread.join(timeout=5)

    def test_history_gzip_keeps_raw_bound_threshold_smaller_wire_and_deadline(self):
        raw=b'x'*1024
        with patch('testnet_gateway.gzip.compress',wraps=gzip.compress) as compress:
            wire,encoding=history_encoding(raw,True,1e100)
            compress.assert_called_once_with(raw,compresslevel=1,mtime=0)
        self.assertEqual(encoding,'gzip');self.assertEqual(gzip.decompress(wire),raw)
        self.assertLess(len(wire),len(raw));self.assertEqual(wire[4:8],b'\0'*4)
        noise=b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(128))
        self.assertGreaterEqual(len(gzip.compress(noise,compresslevel=1,mtime=0)),len(noise))
        for body,accepted in ((noise,True),(b'x'*1023,True),(raw,False)):
            wire,encoding=history_encoding(body,accepted,1e100)
            self.assertIs(wire,body);self.assertIsNone(encoding)
        with patch('testnet_gateway.gzip.compress') as compress:
            with self.assertRaises(HistoryTooLarge):history_encoding(b'x'*(16*1024*1024+1),True,1e100)
            compress.assert_not_called()
        with patch('testnet_gateway.time.monotonic',side_effect=[1,16]):
            with self.assertRaisesRegex(ValueError,'deadline exceeded'):history_encoding(raw,True,15)

    def test_gzip_only_changes_successful_history_and_never_auth_quotas_or_errors(self):
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request=dict(jsonrpc='2.0',id=1,method='getWalletHistoryBlocks',params=[list(range(1,18))])
        body=json.dumps(dict(jsonrpc='2.0',id=1,result=[dict(slot=i,block={'complete':'proof-ciphertext'*100}) for i in range(1,18)])).encode()
        for accept,encoded in ((None,False),('gzip',True),('gzip;q=0',False),('gzip, gzip;q=0',False)):
            headers={} if accept is None else {'Accept-Encoding':accept}
            code,result,calls=self.request(request,header,headers=headers,app_body=body)
            self.assertEqual(code,200);self.assertEqual(result,json.loads(body))
            self.assertEqual(self.last_headers.get('Content-Encoding'), 'gzip' if encoded else None)
            self.assertEqual(self.last_headers['Vary'],'Accept-Encoding')
            self.assertEqual(int(self.last_headers['Content-Length']),len(self.last_wire))
            self.assertEqual([c[0] for c in calls],['ingress','authorize','authorize','history'])
        for method in ('getShieldedFeeQuote','submitShieldedPayment','getShieldedPaymentStatus','getBlock','getSignatureStatuses'):
            code,_,_=self.request(dict(request,method=method,params=[]),header,headers={'Accept-Encoding':'gzip'},app_body=body)
            self.assertEqual(code,200);self.assertEqual(self.last_wire,body)
            self.assertNotIn('Content-Encoding',self.last_headers);self.assertNotIn('Vary',self.last_headers)
        for access,quota,error,expected in ((None,None,None,403),(header,1,None,429),
                (header,None,ValueError('unavailable'),403),(header,None,HistoryTooLarge(HISTORY_SIZE_MESSAGE),200)):
            code,_,_=self.request(request,access,headers={'Accept-Encoding':'gzip'},authorize_limit=quota,app_error=error,app_body=body)
            self.assertEqual(code,expected);self.assertNotIn('Content-Encoding',self.last_headers)
            self.assertNotIn('Vary',self.last_headers)
        # A highly compressible body is still rejected at its ORIGINAL byte cap.
        code,result,_=self.request(request,header,headers={'Accept-Encoding':'gzip'},app_body=b'x'*(16*1024*1024+1))
        self.assertEqual(code,200);self.assertEqual(result['error']['code'],HISTORY_SIZE_CODE)
        self.assertNotIn('Content-Encoding',self.last_headers)

    def test_real_http_history_gzip_preserves_full_json_and_persistent_framing(self):
        charged=[]
        class Faucet:
            def ingress(self,*args):charged.append('edge')
            def command(self,command,proof):
                if command!='authorize' or proof!={'signature':'valid'}:raise ValueError('invalid test proof')
                charged.append('authorize')
        gateway=object.__new__(Gateway);gateway.faucet=Faucet()
        def forward(raw,timeout):
            q=json.loads(raw)
            return json.dumps(dict(jsonrpc='2.0',id=q['id'],result=dict(parentSlot=q['params'][0]-1,
                transactions=[dict(transaction=['complete-proof-'+str(q['params'][0])+'ciphertext'*100,'base64'],meta={'err':None})]))).encode()
        gateway.forward=forward
        server=HTTPServer(('127.0.0.1',0),Handler);server.authority='127.0.0.1:'+str(server.server_port);server.app=gateway
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
        request=dict(jsonrpc='2.0',id='unchanged',method='getWalletHistoryBlocks',params=[list(range(1,18))])
        expected=json.loads(gateway.history_blocks(request,request['params'][0]));socket_number=None
        try:
            for accept,encoding in (('gzip','gzip'),('gzip;q=0',None)):
                headers={'Content-Type':'application/json','Accept-Encoding':accept,
                         'X-Testnet-Access':base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()}
                connection.request('POST','/',json.dumps(request),headers)
                response=connection.getresponse();wire=response.read()
                self.assertEqual(response.status,200);self.assertEqual(response.getheader('Content-Encoding'),encoding)
                self.assertEqual(response.getheader('Vary'),'Accept-Encoding');self.assertEqual(int(response.getheader('Content-Length')),len(wire))
                decoded=gzip.decompress(wire) if encoding else wire
                self.assertEqual(json.loads(decoded),expected)
                if socket_number is None:socket_number=connection.sock.fileno()
                else:self.assertEqual(connection.sock.fileno(),socket_number)
            # Duplicate negotiation headers must not deny admission or silently
            # enable compression, and must not disturb the next body boundary.
            raw=json.dumps(request).encode()
            connection.putrequest('POST','/',skip_accept_encoding=True)
            connection.putheader('Content-Type','application/json');connection.putheader('Content-Length',str(len(raw)))
            connection.putheader('X-Testnet-Access',base64.urlsafe_b64encode(b'{"signature":"valid"}').decode())
            connection.putheader('Accept-Encoding','gzip');connection.putheader('Accept-Encoding','br');connection.endheaders(raw)
            response=connection.getresponse();wire=response.read()
            self.assertEqual(response.status,200);self.assertIsNone(response.getheader('Content-Encoding'))
            self.assertEqual(int(response.getheader('Content-Length')),len(wire));self.assertEqual(json.loads(wire),expected)
            self.assertEqual(connection.sock.fileno(),socket_number)
            self.assertEqual(charged,['edge','authorize','authorize']*3)
        finally:
            connection.close();server.shutdown();server.server_close();thread.join(timeout=5)


    def test_real_http_bulk_history_rechecks_membership_on_each_persistent_request(self):
        charges=[];forwarded=[];membership={'state':'active'}
        class Faucet:
            def ingress(self,*args):pass
            def command(self,command,proof,extra=()):
                self_check=(command,proof,extra)
                charges.append(self_check)
                if proof!={'signature':'valid'} or membership['state']!='active':
                    raise ValueError(membership['state'])
                return dict(authorized=True,units=16)
        gateway=object.__new__(Gateway);gateway.faucet=Faucet();gateway.authorize_many=True
        def history(request,slots):
            forwarded.append(slots);return json.dumps(dict(jsonrpc='2.0',id=request['id'],result=slots)).encode()
        gateway.history_blocks=history
        server=HTTPServer(('127.0.0.1',0),Handler);server.authority='127.0.0.1:'+str(server.server_port);server.app=gateway
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
        request=dict(jsonrpc='2.0',id='same',method='getWalletHistoryBlocks',params=[list(range(1,257))])
        headers={'Content-Type':'application/json','X-Testnet-Access':base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()}
        socket_number=None
        try:
            for state,expected in (('active',200),('active',200),('revoked',403),('membership expired',403),('proof expired',403)):
                membership['state']=state
                connection.request('POST','/',json.dumps(request),headers)
                response=connection.getresponse();body=json.loads(response.read())
                self.assertEqual(response.status,expected)
                if expected==200:
                    self.assertEqual(body['result'],request['params'][0])
                    if socket_number is None:socket_number=connection.sock.fileno()
                    else:self.assertEqual(connection.sock.fileno(),socket_number)
                else:self.assertNotIn('result',body)
            self.assertEqual(len(forwarded),2)
            self.assertEqual(charges,[('authorize-many',{'signature':'valid'},['--units','16'])]*5)
        finally:
            connection.close();server.shutdown();server.server_close();thread.join(timeout=5)


class NativeGatewayBindingTests(unittest.TestCase):
    def test_bulk_authorization_requires_explicit_boolean_and_cli_opt_in(self):
        for capability in (None,0,1,'true',{}):
            with self.assertRaisesRegex(ValueError,'explicit bulk authorization'):
                Gateway(object(),authorize_many=capability)
        for policy in (None,0,1,17,255,257,True,256.0,'256'):
            with self.assertRaisesRegex(ValueError,'compact authorization policy'):
                Gateway(object(),authorize_many=True,compact_headers_per_unit=policy)
        with self.assertRaisesRegex(ValueError,'compact authorization policy'):
            Gateway(object(),compact_headers_per_unit=256)
        from testnet_gateway import main
        for arguments,expected,policy in (([],False,16),(['--authorize-many'],True,16),
                (['--authorize-many','--compact-headers-per-unit','256'],True,256)):
            with self.subTest(arguments=arguments),patch('sys.argv',['testnet_gateway.py','--root','/test/faucet',
                    '--password-file','/test/password',*arguments]),patch('testnet_gateway.Faucet') as faucet,\
                    patch('testnet_gateway.Gateway') as gateway,patch('service_tls.listener') as listener:
                gateway.return_value.relay=None
                main()
                self.assertIs(gateway.call_args.kwargs['authorize_many'],expected)
                self.assertEqual(gateway.call_args.kwargs['compact_headers_per_unit'],policy)
                listener.return_value.serve_forever.assert_called_once_with()
                faucet.return_value.close.assert_called_once_with()

    def test_native_relay_binds_public_invited_profile_separately_from_operator_source(self):
        from shielded_relay import save
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            faucet_root = root / 'faucet'; faucet_root.mkdir(mode=0o700)
            relay_root = root / 'relay'; relay_root.mkdir(mode=0o700)
            network = dict(network=[67]*32, genesis_hash='1'*32)
            public_path = root / 'tester.json'
            relay_config = dict(format='native-shielded-relay-v1', network=network,
                network_file='/fixed/v4.json', rpc='http://127.0.0.1:18899', payer=[8]*32,
                payer_file='/fixed/shared-key', binary='/fixed/binary', fee=2,
                gross_cap=1000000, max_jobs=4, per_member=2,
                pool_format='NPOOL004', native_profile=str(public_path), native_ingress=['127.0.0.1:19001'])
            save(relay_root / 'config.json', relay_config)
            (faucet_root / 'claims.json').write_text(json.dumps(dict(policy={})))
            class Faucet:
                root = faucet_root
                def command(self, command):
                    return dict(invite_required=True, network=network, rpc_audience='https://127.0.0.1:18898')
            # The operator source is deliberately non-invited loopback HTTP.
            source = dict(rpc=dict(url='http://127.0.0.1:18899'), pool_format='NPOOL004', program='pinned-program', pool='pinned-pool')
            public = dict(format='native-wallet-profile-v1', key_mode='user-wallet-v1',
                **network, program=source['program'], pool=source['pool'], pool_format='NPOOL004',
                rpc=dict(transport='https', url='https://127.0.0.1:18898'),
                private_send_transport='native-inline-v1', invite_required=True)
            (faucet_root / 'profile.json').write_text(json.dumps(source))
            with patch('testnet_gateway.Gateway.forward', return_value=json.dumps(dict(result=network['genesis_hash'])).encode()):
                for changed in [dict(public, pool_format='NPOOL003'),
                                {k:v for k,v in public.items() if k != 'private_send_transport'},
                                dict(public, private_send_transport='staged'), dict(public, invite_required=False),
                                dict(public, rpc=dict(transport='https',url='https://127.0.0.1:19999')),
                                dict(public, network=[68]*32), dict(public, program='wrong')]:
                    save(public_path, changed)
                    with self.assertRaisesRegex(ValueError, 'explicit invited V4'):
                        Gateway(Faucet(), relay_root=relay_root)
                save(public_path, public)
                save(relay_root / 'config.json', dict(relay_config, rpc='http://127.0.0.1:19999'))
                with self.assertRaisesRegex(ValueError, 'pinned private RPC'):
                    Gateway(Faucet(), relay_root=relay_root)
                save(relay_root / 'config.json', dict(relay_config, network=dict(network=[68]*32,genesis_hash='1'*32)))
                with self.assertRaisesRegex(ValueError, 'network mismatch'):
                    Gateway(Faucet(), relay_root=relay_root)
                save(relay_root / 'config.json', relay_config)
                gateway=Gateway(Faucet(), relay_root=relay_root)
                try:
                    self.assertEqual(gateway.relay.quote()['transport'],'native-inline-v1')
                    self.assertNotIn('native_profile',gateway.relay.quote())
                finally: gateway.relay.close()


class InvitedWalletTests(unittest.TestCase):
    def app(self, directory):
        profile=dict(label='Invited testnet',genesis_hash='11111111111111111111111111111111',invite_required=True,faucet={'transport':'loopback-http','url':'http://127.0.0.1:8780'})
        result=type('Result',(),dict(returncode=0,stdout=json.dumps(profile)))()
        with patch('wallet_ui.subprocess.run',return_value=result):
            return WalletApp.from_profile(Path('profile.json'),Path(directory)/'client')
    def test_invite_is_private_temporary_input_and_backup_precedes_redemption(self):
        with tempfile.TemporaryDirectory() as directory:
            app=self.app(directory); code='invite1_'+'A'*43; seen=[]
            self.assertTrue(app.status()['invite_required'])
            with self.assertRaisesRegex(ValueError,'recovery'): app.action(dict(action='join',password='local-password-long',invitation=code))
            app.ack.touch()
            def cli(command,password,extra):
                self.assertEqual(command,'join'); self.assertEqual(password,'local-password-long')
                self.assertEqual(extra[0],'--invitation-file')
                path=Path(extra[1]); self.assertEqual(path.stat().st_mode&0o777,0o600)
                self.assertEqual(path.read_text(),code); seen.append(path)
                self.assertNotIn(code,extra)
                return {'admitted':True,'state':'queued'}
            with patch.object(app,'cli',side_effect=cli):
                app.action(dict(action='join',password='local-password-long',invitation=code,rpc='attacker-url',amount=9999))
            self.assertTrue(app.admitted); self.assertFalse(seen[0].exists())
            with patch.object(app,'cli',side_effect=ValueError('expired')):
                with self.assertRaisesRegex(ValueError,'expired'): app.action(dict(action='join',password='local-password-long',invitation=code))
            self.assertEqual(list(app.directory.glob('.invite-*')),[])
    def test_revoked_access_blocks_value_actions_but_preserves_wallet_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            app=self.app(directory); app.ack.touch()
            app.wallet.write_text('encrypted-wallet-preserved')
            for action in ['balance','fees','test-coins','send','withdraw','resolve','reclaim']:
                with patch.object(app,'cli',return_value={'admitted':False,'state':'revoked'}) as cli:
                    with self.assertRaisesRegex(ValueError,'access is unavailable'): app.action(dict(action=action,password='local-password-long'))
                    self.assertEqual(cli.call_args.args,('access-status','local-password-long'))
            self.assertEqual(app.wallet.read_text(),'encrypted-wallet-preserved')
            with patch.object(app,'cli',return_value={'address':'npriv1-same-wallet'}):
                self.assertEqual(app.action(dict(action='ack-backup',password='local-password-long'))['address'],'npriv1-same-wallet')


class InviteCheckpointTests(unittest.TestCase):
    def test_resume_refuses_completed_running_and_unrelated_evidence_before_mutation(self):
        from invite_localnet import gas_checkpoint, compat_checkpoint
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/'invite-result.json'
            for status in ['passed','running','failed']:
                path.write_text(json.dumps(dict(status=status,error='unrelated failure',events=[])))
                original=path.read_bytes()
                with self.assertRaisesRegex(ValueError,'exact failed'): gas_checkpoint(root)
                with self.assertRaisesRegex(ValueError,'exact failed'): compat_checkpoint(root,root)
                self.assertEqual(path.read_bytes(),original)


if __name__=='__main__': unittest.main()
