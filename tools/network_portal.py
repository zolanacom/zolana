#!/usr/bin/env python3
"""Read-only Zolana portal over a pinned public-history snapshot; no RPC keys."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import re
import threading
import time
from urllib.parse import parse_qs, urlsplit

from history_retention import MAX_SEGMENT, STORE_BUDGET, block_hash, directory, manifest, natural, read
from operator_health import read as read_health
from operator_monitor import launch_probe

ASSETS=Path(__file__).resolve().parents[1]/'clients/network-portal'
ALPHABET='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58(raw):
    number=int.from_bytes(raw,'big');result=''
    while number:number,index=divmod(number,58);result=ALPHABET[index]+result
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+result


def transaction(value,slot,position):
    if not isinstance(value,dict) or not isinstance(value.get('transaction'),list) or len(value['transaction'])!=2 or value['transaction'][1]!='base64' or not isinstance(value.get('meta'),dict):raise ValueError('unsupported recorded transaction')
    encoded=value['transaction'][0]
    if not isinstance(encoded,str) or not 1<=len(encoded)<=2*1024*1024:raise ValueError('recorded transaction exceeds bounds')
    raw=base64.b64decode(encoded,validate=True)
    # Solana short-vector signature count, followed by 64-byte signatures.
    count=0;cursor=0
    for shift in (0,7,14):
        if cursor>=len(raw):raise ValueError('truncated signature vector')
        byte=raw[cursor];cursor+=1;count|=(byte&127)<<shift
        if byte<128:break
    else:raise ValueError('invalid signature vector')
    if not 1<=count<=64 or cursor+count*64>=len(raw) or raw[:cursor]!=(bytes([count]) if count<128 else b''):raise ValueError('invalid recorded signature count')
    fee=value['meta'].get('fee')
    if not natural(fee) or 'err' not in value['meta']:raise ValueError('invalid recorded transaction metadata')
    return {'signature':b58(raw[cursor:cursor+64]),'slot':slot,'position':position,'fee_units':fee,'execution':'success' if value['meta']['err'] is None else 'failed','status':'recorded'}


class Archive:
    def __init__(self,root,network):
        root=directory(root);raw,files,tip=manifest(root,network)
        self.digest=hashlib.sha256(raw).hexdigest();self.tip=tip;self.blocks=[];self.by_slot={};self.by_hash={};self.transactions=[];self.by_signature={}
        self.captured_at=root.joinpath('manifest.json').stat().st_mtime;total=0;previous=0;previous_hash=network['genesis_hash'];height=None
        for name,descriptor in files:
            data=read(root/name,MAX_SEGMENT);total+=len(data)
            if total>STORE_BUDGET or hashlib.blake2b(data,digest_size=32,person=b'NPayArchiveV1').hexdigest()!=descriptor['digest']:raise ValueError('recorded history checksum/capacity mismatch')
            records=json.loads(data)
            if not isinstance(records,list) or not records or len(records)!=descriptor['count'] or records[0].get('slot')!=descriptor['first_slot'] or records[-1].get('slot')!=descriptor['last_slot']:raise ValueError('recorded history boundaries changed')
            for block in records:
                if (not isinstance(block,dict) or set(block)!={'slot','parent_slot','blockhash','previous_blockhash','block_height','transactions'} or
                        not natural(block['slot']) or not previous<block['slot'] or block['parent_slot']!=previous or type(block['parent_slot']) is not int or
                        not block_hash(block['blockhash']) or not block_hash(block['previous_blockhash']) or block['previous_blockhash']!=previous_hash or
                        not natural(block['block_height']) or (height is not None and block['block_height']!=height+1) or not isinstance(block['transactions'],list) or len(block['transactions'])>4096):raise ValueError('recorded history continuity mismatch')
                if len(self.blocks)>=100000 or len(self.transactions)+len(block['transactions'])>100000:raise ValueError('portal index exceeds capacity')
                transactions=[transaction(v,block['slot'],i) for i,v in enumerate(block['transactions'])]
                for tx in transactions:
                    if tx['signature'] in self.by_signature:raise ValueError('duplicate recorded transaction signature')
                    self.by_signature[tx['signature']]=tx
                summary={key:block[key] for key in ('slot','parent_slot','blockhash','previous_blockhash','block_height')};summary.update(transaction_count=len(transactions),status='recorded')
                if block['blockhash'] in self.by_hash:raise ValueError('duplicate recorded block hash')
                self.blocks.append(summary);self.by_slot[block['slot']]=summary;self.by_hash[block['blockhash']]=summary;self.transactions.extend(transactions)
                previous,previous_hash,height=block['slot'],block['blockhash'],block['block_height']
        self.blocks.reverse();self.transactions.reverse()

    def block(self,slot):
        value=self.by_slot.get(slot)
        if value is None:return None
        return dict(value,transactions=[v for v in self.transactions if v['slot']==slot])


class Portal:
    def __init__(self,profile=None,history=None,health=None,health_owner=450,probe=launch_probe,health_genesis=None,wallet_genesis=None):
        self.network=None;self.archive=None;self.health=health;self.health_owner=health_owner;self.probe=probe;self.lock=threading.Lock();self.cached=None;self.cached_at=0;self.wallet_genesis=wallet_genesis
        if profile is not None:
            value=json.loads(read(Path(profile),32768));self.network={key:value[key] for key in ('network','genesis_hash')}
            if not block_hash(self.network['genesis_hash']) or not isinstance(self.network['network'],list) or len(self.network['network'])!=32 or any(type(v) is not int or not 0<=v<=255 for v in self.network['network']):raise ValueError('invalid portal network identity')
        if health is not None and (self.network is None or health_genesis!=self.network['genesis_hash']):raise ValueError('health requires an explicit matching genesis binding')
        if wallet_genesis is not None and not block_hash(wallet_genesis):raise ValueError('invalid saved wallet genesis')
        if history is not None:
            if self.network is None:raise ValueError('history requires independently selected network identity')
            self.archive=Archive(history,self.network)

    def overview(self):
        with self.lock:
            if self.cached is not None and time.monotonic()-self.cached_at<3:return self.cached
            phase='unknown';slot=None;count=None;observed=None
            try:
                job=self.probe()
                if job['loaded'] is False:phase='paused';count=0
                if self.health is not None:
                    value=read_health(self.health,self.health_owner);slot=value['finalized_slot'];observed=value['sampled_at']
                    if job['loaded'] is True and job['pid']==value['pid'] and 0<=time.time()-value['published_at']<=15:
                        phase='running' if value['phase']=='ready' else value['phase'];count=value['validator_count']
            except (OSError,ValueError,KeyError):pass
            a=self.archive
            self.cached={'name':'Zolana','ticker':'ZOL','environment':'local-development','phase':phase,'validator_count':count,'last_observed_slot':slot,'observed_at':observed,
                'genesis_hash':self.network['genesis_hash'] if self.network else None,'source':'saved-history' if a else 'not-connected','history_tip':a.tip if a else None,
                'history_sha256':a.digest if a else None,'history_captured_at':a.captured_at if a else None,'recorded_blocks':len(a.blocks) if a else None,'recorded_transactions':len(a.transactions) if a else None,
                'wallet_genesis_hash':self.wallet_genesis,'rpc_available':False,'solana_bridge':False,'mainnet':False};self.cached_at=time.monotonic();return self.cached

    def query(self,path,params):
        if path=='/api/network' and not params:return self.overview()
        if self.archive is None:raise ValueError('saved history is not connected')
        a=self.archive
        if path in ('/api/blocks','/api/transactions'):
            if set(params)-{'before','limit'}:raise ValueError('invalid pagination')
            limit=integer(params.get('limit',['12'])[0],1,50);before=integer(params['before'][0],0,2**53-1) if 'before' in params else None
            if path=='/api/blocks':
                rows=[v for v in a.blocks if before is None or v['slot']<before][:limit+1];next_value=rows[limit-1]['slot'] if len(rows)>limit else None
            else:
                start=before or 0
                if start>len(a.transactions):raise ValueError('invalid transaction cursor')
                rows=a.transactions[start:start+limit+1];next_value=start+limit if len(rows)>limit else None
            return {'items':rows[:limit],'next':next_value,'source':'saved-history','history_tip':a.tip}
        if path=='/api/search' and set(params)=={'q'}:
            query=params['q'][0]
            if re.fullmatch('[0-9]{1,16}',query):
                found=a.block(integer(query,0,2**53-1));return {'kind':'block','value':found,'source':'saved-history'}
            if not re.fullmatch('[1-9A-HJ-NP-Za-km-z]{32,88}',query):raise ValueError('enter a slot, block hash or transaction signature')
            if query in a.by_hash:return {'kind':'block','value':a.block(a.by_hash[query]['slot']),'source':'saved-history'}
            return {'kind':'transaction','value':a.by_signature.get(query),'source':'saved-history'}
        raise ValueError('portal route is read-only and bounded')


def integer(value,low,high):
    if not isinstance(value,str) or not re.fullmatch('[0-9]{1,16}',value):raise ValueError('invalid numeric query')
    number=int(value)
    if not low<=number<=high:raise ValueError('query exceeds bounds')
    return number


class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,port,app):
        self.app=app;self.authority='127.0.0.1:'+str(port);self.slots=threading.BoundedSemaphore(8);super().__init__(('127.0.0.1',port),Handler)
        self.authority='127.0.0.1:'+str(self.server_address[1])
    def process_request(self,request,address):
        if not self.slots.acquire(False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,*args):
        try:super().process_request_thread(*args)
        finally:self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def setup(self):super().setup();self.connection.settimeout(5)
    def log_message(self,*_):pass
    def respond(self,code,raw,mime='application/json'):
        self.send_response(code);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header('Cross-Origin-Resource-Policy','same-origin');self.end_headers()
        try:self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError):pass
    def do_GET(self):
        if self.headers.get('Host')!=self.server.authority or self.headers.get('Origin') not in (None,'http://'+self.server.authority) or self.headers.get('Sec-Fetch-Site')=='cross-site':return self.respond(403,b'{"error":"Request origin rejected."}')
        if len(self.path)>512:return self.respond(400,b'{"error":"Request exceeds bounds."}')
        url=urlsplit(self.path)
        try:
            if url.path.startswith('/api/'):
                params=parse_qs(url.query,keep_blank_values=True,max_num_fields=3)
                if any(len(v)!=1 for v in params.values()):raise ValueError('duplicate query')
                return self.respond(200,json.dumps(self.server.app.query(url.path,params),allow_nan=False).encode())
            paths={'/':'index.html','/style.css':'style.css','/app.js':'app.js','/views.js':'views.js','/veil.png':'veil.png','/favicon.svg':'favicon.svg'}
            if url.query or url.path not in paths:return self.respond(404,b'{"error":"Page not found."}')
            path=ASSETS/paths[url.path];raw=path.read_bytes()
            self.respond(200,raw,mimetypes.guess_type(path)[0] or 'application/octet-stream')
        except (OSError,ValueError,KeyError,RecursionError):self.respond(400,b'{"error":"History request unavailable. Preserve the selected source and try again."}')
    def do_POST(self):self.respond(405,b'{"error":"This explorer is read-only."}')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=8780);parser.add_argument('--profile',type=Path);parser.add_argument('--history',type=Path);parser.add_argument('--health',type=Path);parser.add_argument('--health-owner',type=int,default=450);parser.add_argument('--health-genesis');parser.add_argument('--wallet-genesis');args=parser.parse_args()
    if not 1024<=args.port<=65535:parser.error('use a nonprivileged local port')
    app=Portal(args.profile,args.history,args.health,args.health_owner,health_genesis=args.health_genesis,wallet_genesis=args.wallet_genesis);server=Server(args.port,app)
    print('Zolana portal: http://'+server.authority+' — read-only local development',flush=True)
    try:server.serve_forever(poll_interval=.5)
    except KeyboardInterrupt:pass
    finally:server.server_close()


if __name__=='__main__':main()
