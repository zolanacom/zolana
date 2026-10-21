"""Sealed test-mode-only real finalized grant ACK gate; no invented RPC results."""
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.request

import native_linux_service as base
from test_faucet import BoundedServer
from testnet_gateway import HISTORY_PAGE, READ_METHODS, read_calls

HEX=re.compile('[a-f0-9]{64}')
MAX_RESPONSE=16*1024*1024
BLOCK_CONFIG=dict(encoding='base64',transactionDetails='full',rewards=False,
                  commitment='finalized',maxSupportedTransactionVersion=0)


class HistoryResponseTooLarge(ValueError):
    """Only an explicitly oversized authentic history response is recoverable."""


def history_batch(query):
    # Classification only: callers first run the complete request validator.
    return (isinstance(query,list) and bool(query) and
            all(isinstance(call,dict) and call.get('method')=='getBlock' for call in query))


def rpc_json(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate RPC JSON field')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite RPC JSON')))


def checked_request(raw):
    if not 1<=len(raw)<=100_000:raise ValueError('test RPC request exceeds bound')
    query=rpc_json(raw)
    if isinstance(query,dict):return query  # Existing single worker/relay RPCs stay unchanged.
    if not isinstance(query,list) or not 1<=len(query)<=HISTORY_PAGE:
        raise ValueError('only bounded read-only RPC batches are permitted')
    for index,call in enumerate(query):
        if (not isinstance(call,dict) or set(call)!={'jsonrpc','id','method','params'} or
                call['jsonrpc']!='2.0' or type(call['id']) is not int or call['id']!=index or
                not isinstance(call['method'],str)):
            raise ValueError('exact positional read-only RPC batch envelope required')
    if all(call['method']=='getBlock' for call in query):
        if len(raw)>65536:raise ValueError('history RPC batch exceeds bound')
        prior=0
        for call in query:
            args=call['params']
            if (not isinstance(args,list) or len(args)!=2 or type(args[0]) is not int or
                    not prior<args[0]<=2**64-1 or not isinstance(args[1],dict) or
                    args[1]!=BLOCK_CONFIG or any(type(args[1][key]) is not type(value) for key,value in BLOCK_CONFIG.items())):
                raise ValueError('only ascending finalized full base64 history blocks may be batched')
            prior=args[0]
    elif all(call['method'] in READ_METHODS for call in query):
        if len(raw)>32768:raise ValueError('small-read RPC batch exceeds bound')
        read_calls({'params':[[{'method':call['method'],'params':call['params']} for call in query]]})
    else:raise ValueError('writes, statuses and mixed history/read RPC batches are forbidden')
    return query


def checked_response(query,raw):
    if len(raw)>MAX_RESPONSE:
        if history_batch(query):raise HistoryResponseTooLarge('history RPC response exceeds bound')
        raise ValueError('test RPC response exceeds bound')
    if not raw:raise ValueError('empty test RPC response')
    response=rpc_json(raw)
    if isinstance(query,list):
        if not isinstance(response,list) or len(response)!=len(query):raise ValueError('incomplete RPC batch response')
        seen=set()
        for item in response:
            if (not isinstance(item,dict) or item.get('jsonrpc')!='2.0' or type(item.get('id')) is not int or
                    not 0<=item['id']<len(query) or item['id'] in seen or
                    set(item) not in ({'jsonrpc','id','result'},{'jsonrpc','id','error'}) or
                    ('error' in item and not isinstance(item['error'],dict))):
                raise ValueError('invalid or ambiguous RPC batch response')
            seen.add(item['id'])
    return response


def root_for(rehearsal):
    if type(rehearsal) is not bool:raise ValueError('only fixed cohort test modes allowed')
    return Path('/var/lib/zolana-native-058/gateway')/('cohort-060-rehearsal' if rehearsal else 'cohort-060')


def finalized_match(request,response,signature):
    if (not isinstance(request,dict) or request.get('method')!='getSignatureStatuses' or
            not isinstance(response,dict) or response.get('jsonrpc')!='2.0' or response.get('id')!=request.get('id') or
            'error' in response or not isinstance(request.get('params'),list) or not request['params'] or
            not isinstance(request['params'][0],list) or not 1<=len(request['params'][0])<=32):return None
    signatures=request['params'][0];result=response.get('result')
    if not isinstance(result,dict) or not isinstance(result.get('value'),list) or len(result['value'])!=len(signatures):return None
    for original,status in zip(signatures,result['value']):
        if (original==signature and isinstance(status,dict) and status.get('err') is None and
                status.get('confirmationStatus')=='finalized' and status.get('confirmations') is None and
                type(status.get('slot')) is int and status['slot']>0):return status
    return None


class GrantRpcGate:
    def __init__(self,upstream,network,uid,rehearsal=False):
        base.endpoint(upstream)
        if os.geteuid()!=uid:raise PermissionError('grant test proxy requires the dedicated gateway UID')
        self.root=root_for(rehearsal);self.directory=self.root/'grant-ack-gate'
        if not os.path.lexists(self.directory):self.directory.mkdir(mode=0o700)
        base.real_directory(self.directory,uid,0o700)
        self.uid,self.network,self.upstream=uid,network,upstream
        self.stop=threading.Event();self.lock=threading.Lock();owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                try:
                    sizes=self.headers.get_all('Content-Length',[])
                    if self.path!='/' or len(sizes)!=1 or not sizes[0].isdecimal() or 'Transfer-Encoding' in self.headers:
                        raise ValueError('bounded plain JSON-RPC request required')
                    size=int(sizes[0])
                    if not 1<=size<=100_000:raise ValueError('test RPC request exceeds bound')
                    raw=self.rfile.read(size)
                    if len(raw)!=size:raise ValueError('incomplete test RPC request')
                    query=checked_request(raw)
                    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),base.NoRedirect())
                    request=urllib.request.Request('http://'+owner.upstream,raw,{'Content-Type':'application/json'})
                    try:
                        with opener.open(request,timeout=15) as upstream:
                            if upstream.status!=200:raise ValueError('upstream did not return its real JSON-RPC result')
                            data=upstream.read(MAX_RESPONSE+1)
                    except urllib.error.HTTPError as error:
                        if error.code==413 and history_batch(query):
                            error.close()
                            raise HistoryResponseTooLarge('upstream history response exceeds bound') from error
                        raise
                    response=checked_response(query,data)
                    if isinstance(query,dict) and owner.observe(query,response,data):owner.hold()
                    self.send_response(200);self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                except HistoryResponseTooLarge:
                    # No RPC result or ACK is invented. The authenticated
                    # gateway may map only this explicit history-size signal.
                    data=b'{"error":"history_response_too_large"}'
                    self.close_connection=True
                    self.send_response(413);self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                except (OSError,ValueError,RuntimeError):
                    self.close_connection=True
        self.server=BoundedServer(('127.0.0.1',0),Handler)
        self.endpoint='127.0.0.1:'+str(self.server.server_address[1])
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()

    def arm(self,now=None):
        path=self.directory/'arm.json'
        if not os.path.lexists(path):return None
        value=json.loads(base.owned(path,0,4096,0o640));now=time.time() if now is None else now
        if (not isinstance(value,dict) or set(value)!={'format','nonce','expires_at'} or
                value['format']!='zolana-native-cohort-grant-arm-v1' or not isinstance(value['nonce'],str) or
                HEX.fullmatch(value['nonce']) is None or type(value['expires_at']) is not int or value['expires_at']>now+180):
            raise ValueError('root-owned test arm must name one bounded expiring cohort case')
        return None if value['expires_at']<=now else value

    def observe(self,request,response,response_bytes):
        # Only the cohort's own fsynced pending signature is eligible. Shared
        # relay requests, unrelated users, confirmed responses and missing
        # statuses pass unchanged and can never create fault evidence.
        if not isinstance(request,dict) or request.get('method')!='getSignatureStatuses':return False
        with self.lock:
            arm=self.arm()
            if arm is None:return False
            pending_path=self.root/'faucet/wallet.enc.json.pending.json'
            if not os.path.lexists(pending_path):return False
            pending_bytes=base.owned(pending_path,self.uid,4096);pending=json.loads(pending_bytes)
            if pending.get('network')!=self.network:return False
            status=finalized_match(request,response,pending.get('signature'))
            if status is None:return False
            staging_bytes=base.owned(self.root/'faucet/wallet.enc.json.staging.json',self.uid,4096)
            staging=json.loads(staging_bytes)
            if staging.get('network')!=self.network or staging.get('staging_account')!=pending.get('staging_account'):
                raise ValueError('original grant pending/staging identity mismatch')
            claims=json.loads(base.owned(self.root/'faucet/claims.json',self.uid,1024*1024))
            if claims.get('policy',{}).get('format')!='native-test-faucet-native-v1' or not isinstance(claims.get('claims'),list) or len(claims['claims'])>10:
                raise ValueError('test fault requires the separate finite native grant ledger')
            matches=[]
            for claim in claims['claims']:
                fee=claim.get('fee_address')
                if not isinstance(fee,str):raise ValueError('invalid original claim identity')
                claim_id=hashlib.blake2b(fee.encode(),digest_size=32).hexdigest()
                progress_bytes=base.owned(self.root/'faucet'/(claim_id+'.json'),self.uid,128*1024)
                progress=json.loads(progress_bytes);proof=progress.get('proof')
                if (progress.get('private_done') is True or not progress.get('submission_started') or
                        not isinstance(proof,list) or len(proof)!=9222 or any(type(x) is not int or not 0<=x<=255 for x in proof)):
                    continue
                proof=bytes(proof)
                if list(hashlib.blake2b(proof,digest_size=32,person=b'NativeStageV1!!!').digest())==staging.get('payload_digest'):
                    matches.append((claim_id,proof,progress_bytes))
            if len(matches)!=1:raise ValueError('real grant ACK is not bound to exactly one saved original claim proof')
            claim_id,proof,progress_bytes=matches[0]
            record=dict(format='zolana-native-cohort-real-grant-ack-v1',nonce=arm['nonce'],signature=pending['signature'],
                claim_id=claim_id,pending_sha256=hashlib.sha256(pending_bytes).hexdigest(),
                staging_sha256=hashlib.sha256(staging_bytes).hexdigest(),progress_sha256=hashlib.sha256(progress_bytes).hexdigest(),
                proof_sha256=hashlib.sha256(proof).hexdigest(),proof_bytes=len(proof),authentic_finalized_status=status,
                authentic_response=response,authentic_response_sha256=hashlib.sha256(response_bytes).hexdigest())
            path=self.directory/'observed.json'
            if os.path.lexists(path):
                original=json.loads(base.owned(path,self.uid,65536))
                stable=set(record)-{'authentic_response','authentic_response_sha256'}
                if any(original.get(k)!=record[k] for k in stable):raise ValueError('test fault cannot replace its original admitted grant evidence')
            else:
                self.write_original('original.pending.json',pending_bytes)
                self.write_original('original.staging.json',staging_bytes)
                self.write_original('original.progress.json',progress_bytes)
                self.write_original('original.proof',proof)
                base.atomic(path,record)
            return True

    def write_original(self,name,raw):
        with os.fdopen(os.open(self.directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as target:
            target.write(raw);target.flush();os.fsync(target.fileno())
        base.fsync_dir(self.directory)

    def hold(self):
        deadline=time.monotonic()+180
        while not self.stop.wait(.1):
            if time.monotonic()>=deadline or self.arm() is None:return

    def close(self):
        self.stop.set();self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)
        if self.thread.is_alive():raise RuntimeError('owned test grant RPC proxy did not stop')
