#!/usr/bin/env python3
"""Pinned pilot funding intents and bounded balance observations. Never transfers."""
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import pilot_cohort as cohort
from operator_transport import Operator, NoRedirect
from wallet_release import atomic, create, decode, encode, fsync_dir, read, sha


@contextmanager
def native_lock(path):
    fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077 or meta.st_size:
            raise ValueError('unsafe native operation lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)


@contextmanager
def frozen(root,digest):
    root=Path(root).absolute()
    with cohort.locked(root),ExitStack() as locks:
        for name in ('worker.lock','claims.json.lock'):
            locks.enter_context(native_lock(root/'faucet'/name))
        value=cohort.checked(root,digest);claims,info=cohort.policy(root,value)
        cohort.checked_exports(root,cohort.issuance(root,value))
        source=root/'faucet/wallet.enc.json'
        if claims['claims'] or info.get('issued')!=0:
            raise ValueError('initial funding check requires an unused cohort; never reset live admission')
        if any(os.path.lexists(Path(str(source)+'.'+kind+'.json')) for kind in ('pending','staging')):
            raise ValueError('original funding operation requires recovery before verification')
        yield root,value,claims,source


def make_intent(root,digest):
    with frozen(root,digest) as (root,value,claims,source):
        prepared=cohort.private_json(root/'prepared.json')
        p=claims['policy']
        if prepared['private_address']!=p['source_private_address'] or prepared['fee_address']!=p['source_fee_address']:
            raise ValueError('prepared funding authority differs')
        intent=dict(format='zolana-pilot-funding-intent-v1',plan_sha256=digest,
                    network=value['source_profile']['network'],genesis_hash=value['source_profile']['genesis_hash'],
                    private_address=p['source_private_address'],fee_address=p['source_fee_address'],
                    encrypted_wallet_sha256=sha(read(source,16384,secret=True)),
                    private_units=value['budget']['private_grants'],public_units=value['budget']['conservative_public_units'],
                    automatic_refill=False,transfer_authorized=False)
        path=root/'funding-intent.json'
        if os.path.lexists(path):
            if cohort.private_json(path)!=intent:raise ValueError('original funding intent changed')
        else:create(path,encode(intent));fsync_dir(root)
        return intent


class Reader:
    def __init__(self,profile,key=None):
        self.url=profile['rpc']['url'];self.operator=Operator(self.url,key) if key else None
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def rpc(self,method,params=()):
        if method not in ('getGenesisHash','getSlot','getBlock','getBalance'):
            raise ValueError('funding reader is read-only')
        raw=encode(dict(jsonrpc='2.0',id=1,method=method,params=list(params)))
        try:
            if self.operator:body=self.operator.forward(raw,timeout=10)
            else:
                # Only an explicitly unisolated disposable loopback fixture reaches this branch.
                request=urllib.request.Request(self.url,raw,{'Content-Type':'application/json'})
                with self.opener.open(request,timeout=10) as reply:body=reply.read(65537)
        except urllib.error.HTTPError as error:
            error.close();raise ValueError('funding RPC request denied') from None
        if len(body)>65536:raise ValueError('funding observation exceeds bounds')
        data=decode(body)
        if data.get('id')!=1 or 'error' in data or 'result' not in data:raise ValueError('funding RPC observation unavailable')
        return data['result']


def scan(root,value,source,password_file):
    password=read(password_file,1024,secret=True)
    if len(password)<12:raise ValueError('bounded private faucet password required')
    # This fixed derivative only selects the existing operator CLI path. No role keys
    # or sponsor material is supplied, and the only command is balance.
    config={k:value['source_profile'][k] for k in ('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')}
    config.update(key_mode='local-testnet-rehearsal-v1',fixture_keys_are_public=False)
    with tempfile.TemporaryDirectory(dir=root,prefix='.funding-read-') as folder:
        path=Path(folder)/'network.json';create(path,encode(config))
        args=[str(cohort.WALLET),'balance','--network',str(path),'--wallet',str(source),'--password-file','-',
              '--rpc',value['source_profile']['rpc']['url']]
        key=root/'faucet/rpc-access.key'
        if os.path.lexists(key):args+=['--rpc-access-file',str(key)]
        child=subprocess.run(args,input=password,capture_output=True,timeout=180)
        if child.returncode:raise ValueError('native funding scan failed; preserve original wallet and history')
        return decode(child.stdout)


def validate_receipt(receipt,intent,now=None):
    now=time.time() if now is None else now
    keys={'format','intent_sha256','plan_sha256','genesis_hash','fee_address','private_units','public_units',
          'private_observed','public_observed','max_private_payment','private_finalized_slot','public_finalized_slot','anchor_blockhash',
          'checked_at','expires_at','funding_verified','transfers_submitted'}
    if (not isinstance(receipt,dict) or set(receipt)!=keys or receipt['format']!='zolana-pilot-funding-receipt-v1' or
            receipt['intent_sha256']!=sha(encode(intent)) or receipt['plan_sha256']!=intent['plan_sha256'] or
            receipt['genesis_hash']!=intent['genesis_hash'] or receipt['fee_address']!=intent['fee_address'] or
            receipt['private_units']!=intent['private_units'] or receipt['public_units']!=intent['public_units'] or
            any(not cohort.bounded(receipt[k],0,2**64-1) for k in ('private_observed','public_observed','max_private_payment','private_finalized_slot','public_finalized_slot')) or
            receipt['private_observed']<intent['private_units'] or receipt['public_observed']<intent['public_units'] or
            receipt['max_private_payment']<intent['private_units'] or receipt['max_private_payment']>receipt['private_observed'] or
            not receipt['private_finalized_slot'] or receipt['public_finalized_slot']<receipt['private_finalized_slot'] or
            not isinstance(receipt['anchor_blockhash'],str) or not 32<=len(receipt['anchor_blockhash'])<=44 or
            type(receipt['checked_at']) is not int or type(receipt['expires_at']) is not int or
            receipt['expires_at']!=receipt['checked_at']+300 or not receipt['checked_at']<=now<receipt['expires_at'] or
            receipt['funding_verified'] is not True or receipt['transfers_submitted']!=0):
        raise ValueError('funding receipt is stale, insufficient or mismatched; make a new read-only check')
    return receipt


def checked_clock(root):
    path=root/'funding-clock.json';now=int(time.time())
    if os.path.lexists(path) and now<cohort.private_json(path)['last_time']:raise ValueError('funding clock moved backwards')
    atomic(path,dict(last_time=now));return now


def check(root,digest,check_id):
    if not isinstance(check_id,str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,31}',check_id) is None:raise ValueError('invalid check ID')
    intent=make_intent(root,digest)
    with frozen(root,digest) as (root,_,__,___):
        now=checked_clock(root)
        return validate_receipt(cohort.private_json(root/'funding-checks'/(check_id+'.json')),intent,now)


def verify(root,digest,password_file,check_id,reader_factory=Reader,scan_fn=scan):
    if not isinstance(check_id,str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,31}',check_id) is None:
        raise ValueError('short nonpersonal funding check ID required')
    with frozen(root,digest) as (root,value,claims,source):
        intent=cohort.private_json(root/'funding-intent.json')
        p=claims['policy']
        expected=dict(format='zolana-pilot-funding-intent-v1',plan_sha256=digest,
                      network=value['source_profile']['network'],genesis_hash=value['source_profile']['genesis_hash'],
                      private_address=p['source_private_address'],fee_address=p['source_fee_address'],
                      encrypted_wallet_sha256=sha(read(source,16384,secret=True)),
                      private_units=value['budget']['private_grants'],public_units=value['budget']['conservative_public_units'],
                      automatic_refill=False,transfer_authorized=False)
        if intent!=expected:raise ValueError('original funding intent/authority changed')
        folder=root/'funding-checks'
        if not os.path.lexists(folder):folder.mkdir(mode=0o700);fsync_dir(root)
        cohort.directory(folder)
        output=folder/(check_id+'.json')
        now=checked_clock(root)
        if os.path.lexists(output):return validate_receipt(cohort.private_json(output),intent)
        key=root/'faucet/rpc-access.key'
        reader=reader_factory(value['source_profile'],key if os.path.lexists(key) else None)
        if reader.rpc('getGenesisHash')!=intent['genesis_hash']:raise ValueError('funding RPC has wrong genesis')
        before={n:sha(read(root/'faucet'/n,1024*1024,secret=True)) for n in ('claims.json','admission.json','wallet.enc.json')}
        observed=scan_fn(root,value,source,password_file)
        slot=observed['finalized_slot']
        if (not cohort.bounded(slot,1,2**64-1) or observed['fee_address']!=intent['fee_address'] or
                not cohort.bounded(observed['balance'],0,2**64-1) or observed['balance']<intent['private_units'] or
                not cohort.bounded(observed.get('max_single_payment'),intent['private_units'],observed['balance'])):
            raise ValueError('shielded reservoir is insufficient or bound to a different authority')
        header=lambda:reader.rpc('getBlock',[slot,dict(commitment='finalized',transactionDetails='none',rewards=False)])
        block=header()
        public=reader.rpc('getBalance',[intent['fee_address'],dict(commitment='finalized',minContextSlot=slot)])
        if (not isinstance(block,dict) or not isinstance(block.get('blockhash'),str) or
                not isinstance(public,dict) or not cohort.bounded(public.get('value'),0,2**64-1) or
                public['value']<intent['public_units'] or
                not cohort.bounded(public.get('context',{}).get('slot'),slot,2**64-1) or
                header()!=block or reader.rpc('getGenesisHash')!=intent['genesis_hash']):
            raise ValueError('public funding is insufficient or canonical evidence changed')
        if any(sha(read(root/'faucet'/n,1024*1024,secret=True))!=h for n,h in before.items()):
            raise ValueError('cohort changed during funding verification')
        if int(time.time())<now or int(time.time())-now>=300:raise ValueError('funding check exceeded freshness window')
        receipt=dict(format='zolana-pilot-funding-receipt-v1',intent_sha256=sha(encode(intent)),plan_sha256=digest,
                     genesis_hash=intent['genesis_hash'],fee_address=intent['fee_address'],
                     private_units=intent['private_units'],public_units=intent['public_units'],
                     private_observed=observed['balance'],public_observed=public['value'],max_private_payment=observed['max_single_payment'],private_finalized_slot=slot,
                     public_finalized_slot=public['context']['slot'],anchor_blockhash=block['blockhash'],
                     checked_at=now,expires_at=now+300,funding_verified=True,transfers_submitted=0)
        validate_receipt(receipt,intent);atomic(output,receipt)
        return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('intent','verify','check'))
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--password-file',type=Path);parser.add_argument('--check-id')
    args=parser.parse_args()
    if args.action=='intent':result=make_intent(args.root,args.plan_sha256)
    elif args.action=='verify':
        if args.password_file is None:raise ValueError('password file required for native verified scan')
        result=verify(args.root,args.plan_sha256,args.password_file,args.check_id)
    else:
        result=check(args.root,args.plan_sha256,args.check_id)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Pilot funding verification failed closed; preserve original funding and recovery records. No transfer was submitted.')
