import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gateway_archival import ArchiveRPC, parameters

NETWORK = dict(network=[9]*32, genesis_hash='1'*32)


class CanonicalArchiveTests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.gateway=SimpleNamespace(info=dict(network=NETWORK,rpc_audience='https://127.0.0.1:18898'),faucet=SimpleNamespace(root=Path('/unused')))
        self.reader=ArchiveRPC(self.gateway,'http://127.0.0.1:18899',{'policy':{}})
        self.gateway.forward=lambda raw,timeout:self.reply(raw,timeout,True)
        self.reader.forward=lambda raw,timeout:self.reply(raw,timeout,False)
        self.mutate=lambda method,params,primary,value:value

    def reply(self,raw,timeout,primary):
        self.assertGreater(timeout,0);self.assertLessEqual(timeout,15)
        query=json.loads(raw);method,params=query['method'],query['params'];self.calls.append((primary,method,params))
        if method=='getGenesisHash':value=NETWORK['genesis_hash']
        elif method=='getBlocksWithLimit':value=list(range(params[0],params[0]+16))
        else:
            slot=params[0]
            value=dict(blockhash='1'*32,previousBlockhash='1'*32,parentSlot=slot-1,blockHeight=slot,transactions=[])
        value=self.mutate(method,params,primary,value)
        return json.dumps(dict(jsonrpc='2.0',id=1,result=value)).encode()

    def page(self,after=0,target=20,token=None):
        return json.loads(self.reader.page(dict(id=1,params=[after,target,token])))['result']

    def test_fixed_bounded_full_finalized_pages_resume_without_server_memory(self):
        first=self.page();self.assertEqual(first['next_slot'],16);self.assertFalse(first['complete'])
        old=self.reader
        self.reader=ArchiveRPC(self.gateway,old.url,{'policy':{}});self.reader.forward=old.forward
        last=self.page(16,20,first['anchor'])
        self.assertEqual([b['slot'] for b in last['blocks']],[17,18,19,20]);self.assertTrue(last['complete'])
        self.assertEqual(last['anchor'],first['anchor'])
        for primary,method,params in self.calls:
            self.assertIn(method,['getGenesisHash','getBlock','getBlocksWithLimit'])
            if method=='getBlock':
                self.assertEqual(params[1]['commitment'],'finalized')
                if params[1]['transactionDetails']=='full':
                    self.assertFalse(primary);self.assertEqual(params[1]['encoding'],'base64');self.assertEqual(params[1]['maxSupportedTransactionVersion'],0)

    def test_unavailable_behind_divergent_wrong_genesis_and_incomplete_fail_closed(self):
        for mode in range(8):
            def mutate(method,params,primary,value):
                if mode==0 and method=='getGenesisHash':return 'wrong'
                if mode==1 and method=='getBlock' and not primary:return None
                if mode==2 and method=='getBlock' and not primary:return dict(value,blockhash='2'*32)
                if mode==3 and method=='getBlock' and not primary:return dict(value,blockHeight=0)
                if mode==4 and method=='getBlocksWithLimit':return []
                if mode==5 and method=='getBlocksWithLimit':return [1,1]
                if mode==6 and method=='getBlocksWithLimit':return [True]
                if mode==7 and method=='getBlock' and params[1]['transactionDetails']=='full':return dict(value,transactions=None)
                return value
            self.mutate=mutate
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.page()
        self.mutate=lambda m,p,a,v:v
        token=self.page()['anchor'];token['blockhash']='2'*32
        with self.assertRaises(ValueError):self.page(16,20,token)

    def test_endpoint_and_cursor_never_accept_client_routes_or_tcp_downgrade(self):
        for url in ['https://127.0.0.1:18899','http://localhost:18899','http://127.0.0.1:18899/','http://u:p@127.0.0.1:18899','http://evil:18899','http://127.0.0.1:18899?x']:
            with self.assertRaises(ValueError):ArchiveRPC(self.gateway,url,{'policy':{}})
        with patch('operator_transport.Operator',return_value=SimpleNamespace(path=None)):
            with self.assertRaisesRegex(ValueError,'downgraded'):ArchiveRPC(self.gateway,'http://127.0.0.1:18899',{'policy':dict(operator_rpc=True,operator_unix=True)})
        for params in [[True,20,None],[0,0,None],[0,2**64,None],[21,20,None],[16,20,None],
                       [0,1,dict(slot=True,blockhash='1'*32,block_height=1)],
                       [0,20,dict(slot=20,blockhash='1'*32,block_height=True)]]:
            with self.assertRaises(ValueError):parameters(dict(params=params))

    def test_response_budget_and_shared_deadline_never_publish_partial_or_oversized_reply(self):
        def big(method,params,primary,value):
            if method=='getBlock' and params[1]['transactionDetails']=='full':return dict(value,transactions=[{'padding':'x'*(6*1024*1024)}])
            return value
        self.mutate=big
        first=self.page();self.assertEqual(first['next_slot'],2);self.assertFalse(first['complete'])
        self.assertEqual(self.page(2,3,dict(first['anchor'],slot=3,block_height=3))['next_slot'],3)
        with patch('gateway_archival.time.monotonic',side_effect=[0,16]):
            with self.assertRaisesRegex(ValueError,'deadline'):self.page()


if __name__=='__main__':unittest.main()
