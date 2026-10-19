import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from explorer_feed import Feed,read
from explorer_model import b58,validate
from operator_health import Publisher
from network_portal import Portal


class RPC:
    def __init__(self,count=4):
        self.network={'network':[7]*32,'genesis_hash':b58(bytes([9])*32)};self.tip=count;self.calls=[];self.records={};self.append(count)
    def append(self,count):
        for i in range(len(self.records)+1,count+1):
            raw=b'\x01'+hashlib.sha512(str(i).encode()).digest()+b'\x01\x00\x00'
            tx={'transaction':[base64.b64encode(raw).decode(),'base64'],'meta':{'fee':5000,'err':None,'logMessages':['not exported']}}
            self.records[i]={'parentSlot':i-1,'blockhash':b58(hashlib.sha256(str(i).encode()).digest()),'previousBlockhash':self.records[i-1]['blockhash'] if i>1 else self.network['genesis_hash'],'blockHeight':i,'transactions':[tx]}
        self.tip=count
    def __call__(self,method,params,timeout):
        self.calls.append((method,params,timeout))
        if method=='getGenesisHash':return self.network['genesis_hash']
        if method=='getSlot':return self.tip
        if method=='getBlocks':return list(range(params[0],params[1]+1))
        if method=='getBlock':return copy.deepcopy(self.records[params[0]])
        if method=='getVoteAccounts':return {'current':[{'nodePubkey':b58(bytes([30])*32),'votePubkey':b58(bytes([31])*32),'lastVote':self.tip,'activatedStake':1000,'rootSlot':self.tip}],'delinquent':[]}
        raise ValueError('unapproved RPC')


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='zolana-live-feed-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.public=self.root/'public';self.public.mkdir(mode=0o755);self.path=self.public/'explorer.json';self.rpc=RPC();self.clock=lambda:time.time()
    def feed(self):
        result=Feed(self.path,self.rpc.network,self.rpc,clock=self.clock);self.addCleanup(result.close);return result
    def profile(self):
        path=self.root/'profile.json';path.write_text(json.dumps(self.rpc.network));path.chmod(0o600);return path

    def test_finalized_only_projection_has_no_raw_transactions_logs_or_capability(self):
        writer=self.feed();value=writer.sample();loaded=read(self.path,os.getuid(),self.rpc.network);self.assertEqual(loaded,value)
        raw=self.path.read_text();self.assertNotIn('logMessages',raw);self.assertNotIn('not exported',raw);self.assertNotIn('base64',raw);self.assertNotIn('token',raw)
        self.assertEqual(value['phase'],'live');self.assertEqual(value['blocks'][-1]['slot'],4);self.assertEqual(len(value['validators']),1)
        self.assertTrue(all(v['status']=='finalized' for v in value['blocks']));self.assertTrue(all(0<t<=5 for _,_,t in self.rpc.calls))

    def test_restart_revalidates_original_checkpoint_and_extends_without_duplicates(self):
        writer=self.feed();first=writer.sample();writer.close();self.rpc.append(7);second=self.feed();value=second.sample()
        self.assertNotEqual(first['instance'],value['instance']);self.assertEqual([v['slot'] for v in value['blocks']],list(range(1,8)));self.assertGreater(value['sequence'],first['sequence'])
        self.assertTrue(any(m=='getBlock' and p[0]==4 for m,p,_ in self.rpc.calls));self.assertEqual(len({t['signature'] for b in value['blocks'] for t in b['transactions']}),7)

    def test_crash_recovery_refuses_changed_checkpoint_genesis_and_regression(self):
        writer=self.feed();writer.sample();writer.close();before=self.path.read_bytes()
        self.rpc.records[4]['blockhash']=b58(bytes([40])*32)
        resumed=self.feed()
        with self.assertRaisesRegex(ValueError,'canonical'):resumed.sample()
        self.assertEqual(self.path.read_bytes(),before)
        resumed.close()
        self.rpc.tip=2
        with self.assertRaisesRegex(ValueError,'regressed'):self.feed().sample()

    def test_continuity_omission_out_of_order_and_duplicate_transactions_fail_closed(self):
        writer=self.feed();writer.sample();before=self.path.read_bytes();self.rpc.append(6)
        self.rpc.records[5]['previousBlockhash']=self.rpc.network['genesis_hash']
        with self.assertRaisesRegex(ValueError,'ancestry'):writer.sample()
        self.assertEqual(self.path.read_bytes(),before)

    def test_corrupt_existing_projection_permissions_and_concurrent_writer_are_refused(self):
        writer=self.feed();writer.sample()
        with self.assertRaises(BlockingIOError):Feed(self.path,self.rpc.network,self.rpc)
        writer.close();self.path.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):Feed(self.path,self.rpc.network,self.rpc)
        self.path.chmod(0o666)
        with self.assertRaises(ValueError):read(self.path,os.getuid(),self.rpc.network)

    def test_uncertain_atomic_write_poison_requires_original_restart(self):
        writer=self.feed();writer.sample();self.rpc.append(5)
        from explorer_feed import atomic
        def uncertain(*args):atomic(*args);raise OSError('uncertain fsync')
        with patch('explorer_feed.atomic',side_effect=uncertain),self.assertRaises(OSError):writer.sample()
        with self.assertRaisesRegex(ValueError,'storage failed'):writer.sample()
        writer.close();resumed=self.feed();self.assertEqual(resumed.sample()['blocks'][-1]['slot'],5)

    def test_bounded_catchup_and_pause_survive_restart(self):
        self.rpc.append(70);writer=self.feed();value=writer.sample();self.assertEqual(len(value['blocks']),32);self.assertEqual(value['phase'],'syncing')
        value=writer.sample();self.assertEqual(len(value['blocks']),64);self.assertEqual(value['phase'],'syncing')
        value=writer.sample();self.assertEqual(value['phase'],'live');writer.close();self.assertEqual(read(self.path,os.getuid(),self.rpc.network)['phase'],'paused')

    def test_portal_shows_live_then_paused_and_recovers_same_feed_after_restart(self):
        writer=self.feed();value=writer.sample();health=self.public/'heartbeat.json';pub=Publisher(health).start();self.addCleanup(pub.close);pub.observe(4,validator_count=2);pub.update('ready',ingress_ready=True)
        options=dict(profile=self.profile(),feed=self.path,feed_owner=os.getuid(),health=health,health_owner=os.getuid(),health_genesis=self.rpc.network['genesis_hash'],probe=lambda:{'loaded':True,'pid':os.getpid()},wallet_genesis=self.rpc.network['genesis_hash'])
        app=Portal(**options);network=app.overview();self.assertEqual(network['source'],'live-feed');self.assertEqual(network['wallet_genesis_hash'],network['genesis_hash']);self.assertEqual(len(network['validators']),1)
        self.assertEqual(app.query('/api/search',{'q':['4']})['value']['status'],'finalized')
        writer.close();app.cached_at=-float('inf');self.assertEqual(app.overview()['source'],'saved-feed');restarted=Portal(**options);self.assertEqual(restarted.query('/api/blocks',{})['items'],app.query('/api/blocks',{})['items'])

    def test_stale_invalid_and_replayed_feed_never_claims_live_or_discards_last_good(self):
        writer=self.feed();writer.sample();app=Portal(self.profile(),feed=self.path,feed_owner=os.getuid(),probe=lambda:{'loaded':False,'pid':None});app.overview();before=app.query('/api/blocks',{})
        self.path.write_bytes(b'corrupt');app.cached_at=-float('inf');info=app.overview();self.assertTrue(info['feed_error']);self.assertEqual(info['source'],'saved-feed');self.assertEqual(app.query('/api/blocks',{}),before)

    def test_live_transaction_pagination_uses_stable_signatures_when_new_blocks_arrive(self):
        writer=self.feed();writer.sample();app=Portal(self.profile(),feed=self.path,feed_owner=os.getuid(),probe=lambda:{'loaded':False,'pid':None})
        page=app.query('/api/transactions',{'limit':['2']});self.assertEqual([v['slot'] for v in page['items']],[4,3])
        self.rpc.append(6);writer.sample();app.cached_at=-float('inf')
        older=app.query('/api/transactions',{'limit':['2'],'before':[page['next']]})
        self.assertEqual([v['slot'] for v in older['items']],[2,1]);self.assertIsNone(older['next'])

    def test_schema_extra_fields_false_finality_and_secret_fields_are_rejected(self):
        value=self.feed().sample()
        for mutation in ('secret','status','finality','continuity'):
            bad=copy.deepcopy(value)
            if mutation=='secret':bad['raw_rpc_token']='must never cross boundary'
            elif mutation=='status':bad['blocks'][0]['status']='confirmed'
            elif mutation=='finality':bad['observed_finalized_slot']=1
            else:bad['blocks'][1]['parent_slot']=0
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):validate(bad,self.rpc.network)


if __name__=='__main__':unittest.main()
