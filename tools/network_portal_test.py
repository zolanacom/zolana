import base64
import copy
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import network_portal as portal


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='zolana-portal-test-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.network={'network':[7]*32,'genesis_hash':portal.b58(bytes([9])*32)}
        self.profile=self.root/'profile.json';self.save(self.profile,self.network)
        self.history=self.root/'history';self.history.mkdir(mode=0o700)
        tx={'transaction':[base64.b64encode(b'\x01'+bytes([5])*64+b'\x01\x00\x00').decode(),'base64'],'meta':{'fee':5000,'err':None}}
        self.records=[];previous=0;previous_hash=self.network['genesis_hash']
        for i,slot in enumerate([2,4,5]):
            block={'slot':slot,'parent_slot':previous,'blockhash':portal.b58(bytes([20+i])*32),'previous_blockhash':previous_hash,'block_height':i+1,'transactions':[copy.deepcopy(tx)] if i==1 else []}
            self.records.append(block);previous=slot;previous_hash=block['blockhash']
        self.publish()
    def save(self,path,value):path.write_text(json.dumps(value));path.chmod(0o600)
    def publish(self):
        raw=json.dumps(self.records,separators=(',',':')).encode();digest=hashlib.blake2b(raw,digest_size=32,person=b'NPayArchiveV1').hexdigest()
        self.segment=self.history/('segment-00000000-'+digest+'.json');self.segment.write_bytes(raw);self.segment.chmod(0o600)
        self.save(self.history/'manifest.json',{'format':'native-payment-history-v1','network':self.network,'segments':[{'first_slot':self.records[0]['slot'],'last_slot':self.records[-1]['slot'],'count':len(self.records),'digest':digest}]})
    def app(self,**kwargs):return portal.Portal(self.profile,self.history,probe=lambda:{'loaded':False,'pid':None},**kwargs)

    def test_actual_archive_index_search_and_pagination_keep_recorded_provenance(self):
        app=self.app();info=app.query('/api/network',{})
        self.assertEqual(info['name'],'Zolana');self.assertEqual(info['ticker'],'ZOL');self.assertEqual(info['phase'],'paused');self.assertEqual(info['validator_count'],0)
        self.assertEqual(info['recorded_blocks'],3);self.assertEqual(info['recorded_transactions'],1);self.assertFalse(info['rpc_available'])
        page=app.query('/api/blocks',{'limit':['2']});self.assertEqual([v['slot'] for v in page['items']],[5,4]);self.assertEqual(page['next'],4)
        self.assertEqual(app.query('/api/blocks',{'before':['4']})['items'][0]['slot'],2)
        block=app.query('/api/search',{'q':['4']});self.assertEqual(block['value']['transactions'][0]['fee_units'],5000)
        signature=block['value']['transactions'][0]['signature'];self.assertEqual(app.query('/api/search',{'q':[signature]})['value']['slot'],4)
        self.assertEqual(app.query('/api/search',{'q':[self.records[1]['blockhash']]})['value']['slot'],4)
        self.assertIsNone(app.query('/api/search',{'q':['900']})['value'])

    def test_live_overlap_is_checked_before_replacing_any_saved_index(self):
        from explorer_feed import atomic
        public=self.root/'public';public.mkdir(mode=0o755);path=public/'explorer.json'
        rows=[]
        for b in self.records[1:]:
            row={k:v for k,v in b.items() if k!='transactions'}
            row.update(status='finalized',transactions=[portal.transaction(tx,b['slot'],i,'finalized') for i,tx in enumerate(b['transactions'])],transaction_count=len(b['transactions']))
            rows.append(row)
        # Full blocks may include a vote before the retained payment. Its
        # canonical full-block position differs from its retained-subset index.
        payment=rows[0]['transactions'][0];payment['position']=1
        vote=dict(payment,signature=portal.b58(bytes([6])*64),position=0)
        rows[0]['transactions'].insert(0,vote);rows[0]['transaction_count']=2
        value=dict(format='native-explorer-feed-v1',network=self.network,instance='a'*32,sequence=1,published_at=time.time(),sampled_at=time.time()-1,phase='live',observed_finalized_slot=5,blocks=rows,validators=[])
        atomic(path,value,0o644)
        app=self.app(feed=path,feed_owner=os.getuid());app.overview()
        before=copy.deepcopy(app.archive.blocks);self.assertEqual(app.archive.by_slot[4]['status'],'finalized')
        for mutation in ('fee','transaction_set','blockhash','network','sequence'):
            bad=copy.deepcopy(value);bad['sequence']=2;bad['published_at']=time.time()
            if mutation=='fee':bad['blocks'][0]['transactions'][1]['fee_units']+=1
            elif mutation=='transaction_set':bad['blocks'][0]['transactions']=[];bad['blocks'][0]['transaction_count']=0
            elif mutation=='blockhash':bad['blocks'][-1]['blockhash']=portal.b58(bytes([33])*32)
            elif mutation=='network':bad['network']['network'][0]=90
            else:bad['sequence']=0
            atomic(path,bad,0o644);app.cached_at=-float('inf')
            self.assertTrue(app.overview()['feed_error']);self.assertEqual(app.archive.blocks,before)
        self.assertEqual(portal.Archive(self.history,self.network).blocks[-1]['status'],'recorded')

    def test_restart_preserves_exact_index_and_source_bytes_without_opening_unreferenced_files(self):
        sentinel=self.history/'operator.key';sentinel.write_bytes(b'do not open');sentinel.chmod(0o000)
        before={p.name:p.read_bytes() for p in self.history.iterdir() if p!=sentinel}
        a=self.app();b=self.app();self.assertEqual(a.archive.digest,b.archive.digest);self.assertEqual(a.archive.blocks,b.archive.blocks);self.assertEqual(a.archive.transactions,b.archive.transactions)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.history.iterdir() if p!=sentinel});sentinel.chmod(0o600)

    def test_corrupted_segment_and_wrong_network_fail_closed(self):
        self.segment.write_bytes(self.segment.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'checksum'):self.app()
        self.publish();profile=copy.deepcopy(self.network);profile['genesis_hash']=portal.b58(bytes([8])*32);self.save(self.profile,profile)
        with self.assertRaisesRegex(ValueError,'identity'):self.app()

    def test_rehashed_discontinuity_omission_and_duplicate_signature_are_rejected(self):
        original=copy.deepcopy(self.records)
        for mutation in ('parent','previous_hash','height','duplicate'):
            self.records=copy.deepcopy(original)
            if mutation=='parent':self.records[1]['parent_slot']=1
            elif mutation=='previous_hash':self.records[1]['previous_blockhash']=self.network['genesis_hash']
            elif mutation=='height':self.records[1]['block_height']=90
            else:self.records[2]['transactions']=self.records[1]['transactions']
            self.publish()
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.app()

    def test_malformed_transactions_oversized_vectors_and_metadata_are_rejected(self):
        original=self.records[1]['transactions'][0]
        for raw in (b'',b'\xff\xff\xff',b'\x00x',b'\x01'+bytes(20),b'\x81\x00'+bytes(64)+b'x'):
            value=copy.deepcopy(original);value['transaction'][0]=base64.b64encode(raw).decode()
            with self.assertRaises(ValueError):portal.transaction(value,4,0)
        value=copy.deepcopy(original);value['meta']['fee']=True
        with self.assertRaises(ValueError):portal.transaction(value,4,0)
        value=copy.deepcopy(original);value['transaction'][0]='<script>'
        with self.assertRaises(ValueError):portal.transaction(value,4,0)

    def test_unsafe_history_permissions_and_symlinks_are_refused(self):
        self.segment.chmod(0o644)
        with self.assertRaises(ValueError):self.app()
        self.segment.chmod(0o600);target=self.root/'link';target.symlink_to(self.history,target_is_directory=True)
        with self.assertRaises(ValueError):portal.Portal(self.profile,target)

    def test_no_history_and_unknown_health_do_not_invent_activity(self):
        app=portal.Portal(probe=lambda:(_ for _ in ()).throw(OSError('probe failed')))
        info=app.overview();self.assertEqual(info['phase'],'unknown');self.assertIsNone(info['validator_count']);self.assertIsNone(info['recorded_blocks']);self.assertEqual(info['source'],'not-connected')
        with self.assertRaises(ValueError):app.query('/api/blocks',{})

    def test_queries_cannot_invoke_rpc_mutations_unbounded_ranges_or_arbitrary_paths(self):
        app=self.app()
        for path,params in [('/rpc',{}),('/api/sendTransaction',{}),('/api/blocks',{'limit':['51']}),('/api/blocks',{'before':['-1']}),('/api/blocks',{'file':['operator.key']}),('/api/search',{'q':['<script>']}),('/api/search',{'q':['9'*16]})]:
            with self.subTest(path=path,params=params),self.assertRaises(ValueError):app.query(path,params)

    def test_stale_or_mismatched_heartbeat_cannot_report_running_validators(self):
        app=portal.Portal(self.profile,self.history,health=Path('/unused'),probe=lambda:{'loaded':True,'pid':99},health_genesis=self.network['genesis_hash'])
        heartbeat={'pid':99,'published_at':0,'phase':'ready','validator_count':2,'finalized_slot':123,'sampled_at':0}
        with patch('network_portal.read_health',return_value=heartbeat):info=app.overview()
        self.assertEqual(info['phase'],'unknown');self.assertIsNone(info['validator_count']);self.assertEqual(info['last_observed_slot'],123)

    def test_health_and_saved_wallet_identities_are_explicit_and_never_silently_rebound(self):
        with self.assertRaisesRegex(ValueError,'genesis binding'):portal.Portal(self.profile,self.history,health=Path('/unused'))
        with self.assertRaisesRegex(ValueError,'genesis binding'):portal.Portal(self.profile,self.history,health=Path('/unused'),health_genesis=portal.b58(bytes([6])*32))
        old=portal.b58(bytes([6])*32);app=portal.Portal(self.profile,self.history,wallet_genesis=old,probe=lambda:{'loaded':False,'pid':None})
        self.assertEqual(app.overview()['wallet_genesis_hash'],old);self.assertNotEqual(app.overview()['wallet_genesis_hash'],app.overview()['genesis_hash'])

    def test_http_is_host_bound_same_origin_read_only_and_has_no_file_or_rpc_proxy(self):
        server=portal.Server(0,self.app());thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.addCleanup(thread.join,3);self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        def request(path='/',method='GET',headers=None):
            connection=HTTPConnection('127.0.0.1',server.server_address[1],timeout=3)
            try:
                connection.request(method,path,headers=headers or {});response=connection.getresponse();return response.status,dict(response.headers),response.read()
            finally:connection.close()
        code,headers,raw=request('/api/network');self.assertEqual(code,200);self.assertIn('frame-ancestors',headers['Content-Security-Policy']);self.assertNotIn('Access-Control-Allow-Origin',headers);self.assertNotIn(b'operator.key',raw)
        self.assertEqual(request(headers={'Host':'evil.test'})[0],403);self.assertEqual(request(headers={'Origin':'https://evil.test'})[0],403);self.assertEqual(request(headers={'Sec-Fetch-Site':'cross-site'})[0],403)
        self.assertEqual(request('/api/network',method='POST')[0],405);self.assertEqual(request('/../network.json')[0],404);self.assertEqual(request('/api/blocks?limit=1&limit=2')[0],400);self.assertEqual(request('/api/sendTransaction')[0],400)
        self.assertEqual(request('/')[0],200)


if __name__=='__main__':unittest.main()
