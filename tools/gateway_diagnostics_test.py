import importlib.util,io,json,threading,unittest
from pathlib import Path
from unittest.mock import patch
p=Path(__file__).with_name('gateway_diagnostics.py');s=importlib.util.spec_from_file_location('D',p);D=importlib.util.module_from_spec(s);s.loader.exec_module(D)
class Diagnostics(unittest.TestCase):
 def setUp(self):
  D._count=0;self.output=io.StringIO();p=patch.object(D.sys,'stderr',self.output);p.start();self.addCleanup(p.stop)
 def rows(self):return [json.loads(x) for x in self.output.getvalue().splitlines()]
 def test_quote_returns_identical_value_and_never_logs_proof(self):
  value=object();proof={'secret':'do-not-log'}
  class Original:
   def shielded(self,request,p):self.received=(request,p);return value
  x=D.gateway_class(Original)();q={'method':'getShieldedFeeQuote'};self.assertIs(x.shielded(q,proof),value);self.assertIs(x.received[1],proof);self.assertEqual([x['event'] for x in self.rows()],['fee_quote_begin','fee_quote_end']);self.assertNotIn('do-not-log',self.output.getvalue())
 def test_nonquote_unmodified_and_unlogged(self):
  class Original:
   def shielded(self,q,p):return (q,p)
  q={'method':'submitShieldedPayment'};p=object();self.assertEqual(D.gateway_class(Original)().shielded(q,p),(q,p));self.assertEqual(self.rows(),[])
 def test_exception_class_only_propagates_and_omits_secret_message(self):
  class Original:
   def shielded(self,q,p):raise KeyError('secret-header-value')
  with self.assertRaises(KeyError):D.gateway_class(Original)().shielded({'method':'getShieldedFeeQuote'},None)
  self.assertEqual(self.rows()[-1]['exception_class'],'KeyError');self.assertNotIn('secret-header-value',self.output.getvalue())
 def test_slots_preserve_exact_capacity_and_release(self):
  q=D._Slots(threading.BoundedSemaphore(16));self.assertEqual([q.acquire(False) for _ in range(17)],[True]*16+[False]);q.release();self.assertTrue(q.acquire(False));self.assertEqual([x['event'] for x in self.rows()],['listener_slots_exhausted'])
 def test_tls_success_preserves_context_arguments_and_result(self):
  value=object()
  class Context:
   def wrap_socket(self,*a,**k):self.received=(a,k);return value
  original=Context();x=D._TLSContext(original);self.assertIs(x.wrap_socket('socket',server_side=True),value);self.assertEqual(original.received,(('socket',),{'server_side':True}));self.assertEqual(self.rows()[-1]['event'],'tls_handshake_success')
 def test_tls_error_rethrown_without_error_text(self):
  class Context:
   def wrap_socket(self,*a,**k):raise OSError('secret-peer-detail')
  with self.assertRaises(OSError):D._TLSContext(Context()).wrap_socket(None)
  self.assertEqual(self.rows()[-1]['exception_class'],'OSError');self.assertNotIn('secret-peer-detail',self.output.getvalue())
 def test_handler_status_and_exception_preserve_behavior(self):
  class Handler:
   def send_response(self,code,message=None):self.code=code
   def do_POST(self):self.send_response(403);return 'same'
  x=D.handler_class(Handler)();self.assertEqual(x.do_POST(),'same');self.assertEqual(x.code,403);self.assertEqual(self.rows()[-1]['http_status'],403)
 def test_log_bound_and_log_io_failure_do_not_change_control(self):
  for _ in range(520):D.emit('test')
  self.assertEqual(len(self.rows()),512)
  class Broken:
   def write(self,*a):raise OSError('log broken')
  D._count=0
  with patch.object(D.sys,'stderr',Broken()):D.emit('test')

class RefusalDiagnostics(unittest.TestCase):
 setUp=Diagnostics.setUp
 rows=Diagnostics.rows
 def test_expected_refusals_keep_exact_http_body_and_fixed_stage(self):
  import base64
  import testnet_gateway as G
  import testnet_gateway_test as E
  proof=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
  request=dict(jsonrpc='2.0',id=1,method='getWalletSyncSnapshot',params=[7])
  cases=[(None,{},'proof',403),
         (proof,dict(authorize_limit=0),'authorization',429),
         (proof,dict(limit=True),'ingress',429),
         (proof,dict(app_error=ValueError('private-error-content')),'snapshot',403)]
  for access,options,stage,status in cases:
   with self.subTest(stage=stage):
    with patch.object(G.time,'monotonic',return_value=1000):
     original=E.GatewayTests().request(request,access,**options)
    self.output.seek(0);self.output.truncate()
    with patch.object(E,'Handler',D.handler_class(G.Handler)), patch.object(G.time,'monotonic',return_value=1000):
     observed=E.GatewayTests().request(request,access,**options)
    self.assertEqual(observed,original)
    rows=[r for r in self.rows() if r['event']=='http_post_refusal']
    self.assertEqual([(r['stage'],r['http_status']) for r in rows],[(stage,status)])
    self.assertNotIn('private-error-content',self.output.getvalue())
    self.assertNotIn('signature',self.output.getvalue())
 def test_snapshot_exception_leaf_is_fixed_and_original_exception_escapes(self):
  import testnet_gateway as G
  from wallet_sync_snapshot_test import Fixture
  import urllib.error
  cases=[('snapshot_metadata_upstream','metadata_io'),
         ('snapshot_metadata_response','metadata_response'),
         ('snapshot_history_upstream','history_io'),('snapshot_shape','shape')]
  for expected,kind in cases:
   with self.subTest(kind=kind):
    self.output.seek(0);self.output.truncate()
    f=Fixture();f.app.__class__=D.gateway_class(G.Gateway);original=f.forward
    failure=urllib.error.URLError('private-upstream-error')
    def forward(raw,timeout):
     request=json.loads(raw)
     full=request['method']=='getBlock' and request['params'][1].get('transactionDetails')=='full'
     if kind=='metadata_io' or kind=='history_io' and full:raise failure
     if kind=='metadata_response':return b'{"jsonrpc":"2.0","id":0,"result":"x","private":"never-log"}'
     return original(raw,timeout)
    f.app.forward=forward
    if kind=='shape':
     f.modify=lambda c,v:'1'*33 if c['method']=='getGenesisHash' else v
    with self.assertRaises((ValueError,urllib.error.URLError)) as caught:f.page()
    if kind.endswith('_io'):self.assertIs(caught.exception,failure)
    stages=[r['stage'] for r in self.rows() if r['event']=='snapshot_read_exception']
    self.assertIn(expected,stages)
    self.assertNotIn('private-upstream-error',self.output.getvalue())
    self.assertNotIn('never-log',self.output.getvalue())
 def test_observer_failure_does_not_change_snapshot_or_handler_result(self):
  import testnet_gateway as G
  from wallet_sync_snapshot_test import Fixture
  f=Fixture();failure=ValueError('original-not-log')
  f.app.forward=lambda *_args,**_kwargs:(_ for _ in ()).throw(failure)
  def broken(*_args):raise RuntimeError('observer failed')
  f.app.diagnostic_failure=broken
  with self.assertRaises(ValueError) as caught:f.page()
  self.assertIs(caught.exception,failure)
  G._observe_failure(broken,'authorization',failure)
 def test_unrecognized_diagnostic_labels_are_not_logged(self):
  class Original:pass
  D.handler_class(Original)().diagnostic_refusal('secret-stage',ValueError('secret'),403)
  D.handler_class(Original)().diagnostic_refusal('authorization',ValueError('secret'),200)
  D.gateway_class(Original)().diagnostic_failure('secret-stage',ValueError('secret'))
  self.assertEqual(self.rows(),[])

if __name__=='__main__':unittest.main()
