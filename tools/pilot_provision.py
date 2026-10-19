#!/usr/bin/env python3
"""Explicit finite test-unit ceremony. No service activation or automatic refill."""
import argparse
import base64
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import time

import pilot_cohort as cohort
import pilot_funding as funding
import pilot_runtime as runtime
from operator_transport import Operator
from wallet_release import create, decode, encode, fsync_dir, read, sha

PROJECT=Path(__file__).resolve().parents[1]
LAB=PROJECT/'target/debug/native-localnet'
FILES=('pilot_provision.py',)


def command(args):
    result=subprocess.run([str(x) for x in args],capture_output=True,timeout=180)
    if result.returncode:raise ValueError('native ceremony step failed; preserve original journals and inspect privately')
    return decode(result.stdout)


def prepare(network_root,root,digest):
    network_root,root=Path(network_root).absolute(),Path(root).absolute()
    funding.make_intent(root,digest)
    with funding.frozen(root,digest):
        net,network_sha,rpc=runtime.network(network_root)
        value,_,__,intent=runtime.cohort_check(root,digest,net,rpc,network_root)
        if value['budget']!=cohort.budget(10):raise ValueError('this ceremony is exactly ten lifetime testers')
        plan=dict(format='zolana-pilot-provision-v1',network_root=str(network_root),network_sha256=network_sha,
                  cohort_root=str(root),plan_sha256=digest,intent_sha256=sha(encode(intent)),
                  pins={name:sha(cohort.code_bytes(PROJECT/name,256*1024*1024)) for name in
                        ('tools/pilot_provision.py','target/debug/native-localnet','target/debug/native-wallet')},
                  private_deposits=[dict(id='pilot-ten-deposit-01',amount=5_000_000),dict(id='pilot-ten-deposit-02',amount=5_000_000)],
                  public_units=6_000_300_000,public_fee_cap=10_000,automatic_refill=False)
        path=root/'provision-plan.json'
        if os.path.lexists(path):
            if read(path,16384,secret=True)!=encode(plan):raise ValueError('original funding ceremony changed')
        else:create(path,encode(plan));fsync_dir(root)
        return dict(provision_sha256=sha(encode(plan)),transfers_submitted=0)


class Transport:
    def __init__(self,rpc,key):self.operator=Operator(rpc,key)
    def rpc(self,method,params=()):
        if method not in ('getGenesisHash','getSignatureStatuses','getBlock','getBlockHeight','sendTransaction','getBalance'):
            raise ValueError('unsupported treasury method')
        response=decode(self.operator.forward(encode(dict(jsonrpc='2.0',id=1,method=method,params=list(params))),timeout=15))
        if response.get('id')!=1 or 'error' in response or 'result' not in response:raise ValueError('treasury RPC unavailable; original signature retained')
        return response['result']


def public_allocation(root,plan,wallet,password,cold,transport,hook=lambda _:None):
    nr=Path(plan['network_root']);saved=root/'treasury-signed.json'
    if not os.path.lexists(saved):
        signed=command([LAB,'pilot-treasury-sign',nr,wallet,password,cold,plan['rpc']])
        create(saved,encode(signed));fsync_dir(root)
        hook('signature-durable')
    signed=command([LAB,'pilot-treasury-check',nr,wallet,password,saved])
    if signed['amount']!=plan['public_units'] or signed['fee']>plan['public_fee_cap']:raise ValueError('treasury allocation contract changed')
    receipt=root/'treasury-finalized.json';prior=read(receipt,16384,secret=True) if os.path.lexists(receipt) else None
    deadline=time.monotonic()+90;sent=False
    while time.monotonic()<deadline:
        if transport.rpc('getGenesisHash')!=signed['genesis_hash']:raise ValueError('funding RPC changed genesis')
        reply=transport.rpc('getSignatureStatuses',[[signed['signature']],{'searchTransactionHistory':True}])
        status=reply['value'][0]
        if status and status.get('confirmationStatus')=='finalized':
            if status.get('err') is not None:raise ValueError('original treasury allocation finalized unsuccessfully; never replace automatically')
            block=transport.rpc('getBlock',[status['slot'],{'commitment':'finalized','transactionDetails':'signatures','rewards':False,'maxSupportedTransactionVersion':0}])
            if not block or signed['signature'] not in block['signatures']:raise ValueError('canonical treasury inclusion unavailable')
            result=dict(format='zolana-pilot-treasury-finalized-v1',signature_sha256=sha(read(saved,16384,secret=True)),
                        signature=signed['signature'],slot=status['slot'],blockhash=block['blockhash'],amount=signed['amount'],recipient=signed['recipient'])
            if prior is not None:
                if prior!=encode(result):raise ValueError('original treasury finality evidence changed')
            else:create(receipt,encode(result));fsync_dir(root)
            hook('public-finalized');return result
        if prior is not None:raise ValueError('original canonical treasury finality no longer available; preserve receipt')
        height=transport.rpc('getBlockHeight',[{'commitment':'finalized'}])
        if height>signed['last_valid_block_height']:
            raise ValueError('original signature expired or unresolved; canonical operator review required, never re-sign')
        if not sent:
            tx=base64.b64encode(bytes(signed['transaction'])).decode()
            signature=transport.rpc('sendTransaction',[tx,{'encoding':'base64','preflightCommitment':'confirmed','maxRetries':0}])
            if signature!=signed['signature']:raise ValueError('broadcast returned different signature')
            sent=True;hook('public-broadcast')
        time.sleep(.25)
    raise ValueError('original treasury outcome pending; restart with the same provision digest')


def run(root,expected,password,cold,sponsor,hook=lambda _:None):
    root=Path(root).absolute();password,cold,sponsor=map(lambda p:Path(p).absolute(),(password,cold,sponsor))
    with cohort.locked(root),ExitStack() as locks:
        for name in ('worker.lock','claims.json.lock'):locks.enter_context(funding.native_lock(root/'faucet'/name))
        raw=read(root/'provision-plan.json',16384,secret=True);plan=decode(raw)
        if sha(raw)!=expected:raise ValueError('reviewed provision digest changed')
        nr=Path(plan['network_root']);net,network_sha,rpc=runtime.network(nr)
        value,claims,info,intent=runtime.cohort_check(root,plan['plan_sha256'],net,rpc,nr)
        if (plan['format']!='zolana-pilot-provision-v1' or plan['cohort_root']!=str(root) or plan['network_sha256']!=network_sha or
                plan['intent_sha256']!=sha(encode(intent)) or value['budget']!=cohort.budget(10) or
                plan['public_units']!=intent['public_units'] or plan['public_fee_cap']!=10_000 or plan['automatic_refill'] is not False or
                plan['private_deposits']!=[dict(id='pilot-ten-deposit-01',amount=5_000_000),dict(id='pilot-ten-deposit-02',amount=5_000_000)] or
                claims['claims'] or info['issued'] or any(os.path.lexists(nr/name) for name in runtime.FILES) or
                plan['pins']!={name:sha(cohort.code_bytes(PROJECT/name,256*1024*1024)) for name in
                               ('tools/pilot_provision.py','target/debug/native-localnet','target/debug/native-wallet')}):
            raise ValueError('initial ceremony identity, code or unused capacity changed')
        wallet=root/'faucet/wallet.enc.json';base=[cohort.WALLET,None,'--network',nr/'network.json','--wallet',wallet,'--password-file',password,
                                                    '--rpc',rpc,'--rpc-access-file',nr/'rpc-access.key']
        def native(action,extra=()):return command([*base[:1],action,*base[2:],*extra])
        transport=Transport(rpc,nr/'rpc-access.key')
        initial=native('balance')['balance']
        if initial not in (0,5_000_000,10_000_000) or (initial and not os.path.lexists(root/('pilot-ten-deposit-0'+str(initial//5_000_000)+'-started.json'))):
            raise ValueError('unrecognized existing private funds; no allocation submitted')
        public=public_allocation(root,{**plan,'rpc':rpc},wallet,password,cold,transport,hook)
        for index,item in enumerate(plan['private_deposits']):
            # Resolve the ORIGINAL signed payment and upload before inspecting balances.
            if os.path.lexists(Path(str(wallet)+'.pending.json')):native('resolve')
            if os.path.lexists(Path(str(wallet)+'.staging.json')):native('reclaim',['--sponsor-password-file',sponsor])
            balance=native('balance');amount=balance['balance'];target=(index+1)*5_000_000
            receipt=root/(item['id']+'.json');started=root/(item['id']+'-started.json')
            if os.path.lexists(started) and decode(read(started,16384,secret=True))!=dict(provision_sha256=expected,request=item):
                raise ValueError('original deposit request changed')
            if os.path.lexists(receipt):
                saved=decode(read(receipt,16384,secret=True))
                if saved!=dict(provision_sha256=expected,request=item,balance=target) or amount<target:raise ValueError('original deposit evidence changed')
                continue
            if amount==target:
                if not os.path.lexists(started):raise ValueError('unrecognized private funds; no deposit inferred')
            elif amount==target-5_000_000:
                if not os.path.lexists(started):create(started,encode(dict(provision_sha256=expected,request=item)));fsync_dir(root)
                elif decode(read(started,16384,secret=True))!=dict(provision_sha256=expected,request=item):raise ValueError('original deposit request changed')
                native('deposit',['--sponsor-password-file',sponsor,'--sponsor-request-id',item['id'],'--amount',str(item['amount'])])
                hook('private-'+str(index+1)+'-broadcast')
                balance=native('balance')
                if balance['balance']!=target:raise ValueError('original private deposit not canonically spendable yet')
            else:raise ValueError('unexpected private reservoir balance; preserve original notes and journals')
            create(receipt,encode(dict(provision_sha256=expected,request=item,balance=target)));fsync_dir(root)
            hook('private-'+str(index+1)+'-durable')
        final=native('balance')
        if final['balance']!=10_000_000 or final['max_single_payment']<10_000_000 or final['unspent_notes']!=2:
            raise ValueError('ten-tester reservoir is not exactly two spendable notes')
        public_balance=transport.rpc('getBalance',[intent['fee_address'],{'commitment':'finalized'}])['value']
        if public_balance!=plan['public_units']:raise ValueError('public reservoir differs from original finite allocation')
        result=dict(format='zolana-pilot-provision-complete-v1',provision_sha256=expected,public_signature=public['signature'],
                    public_units=public_balance,private_units=final['balance'],private_notes=2,automatic_refill=False)
        path=root/'provision-complete.json'
        if os.path.lexists(path):
            if read(path,16384,secret=True)!=encode(result):raise ValueError('original provision completion differs')
        else:create(path,encode(result));fsync_dir(root)
        return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('prepare','run'))
    p.add_argument('--root',type=Path,required=True);p.add_argument('--network-root',type=Path);p.add_argument('--plan-sha256');p.add_argument('--provision-sha256')
    for name in ('password-file','cold-password-file','sponsor-password-file'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    result=prepare(a.network_root,a.root,a.plan_sha256) if a.action=='prepare' else run(a.root,a.provision_sha256,a.password_file,a.cold_password_file,a.sponsor_password_file)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):raise SystemExit('Pilot provisioning stopped. Preserve original signed allocation, sponsor reservations and wallet journals; never reset or refill.')
