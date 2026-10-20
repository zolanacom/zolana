#!/usr/bin/env python3
"""Explicit one-time operator allocation. Never imported by the grant service.

The caller supplies private-namespace RPC and the reviewed cohort plan. Only the
existing shared relay key signs; no tester, validator or cold treasury key is read.
"""
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import struct

from native_pilot_cohort import canonical, directory, hash_value, validate_plan
from wallet_release import create, decode, fsync_dir, read

ALPHABET='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
FORMAT='zolana-native-cohort-public-funding-v1'
KEYS={'format','plan_sha256','network','payer','target','amount','blockhash',
      'last_valid_block_height','fee','transaction','signature'}
RETAIN=100_000_000


class FundingPending(ValueError):
    """Original signed allocation remains authoritative; call again to resolve it."""


def b58(raw):
    number=int.from_bytes(raw,'big');text=''
    while number:
        number,remainder=divmod(number,58);text=ALPHABET[remainder]+text
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+text


def un58(value,size):
    if not isinstance(value,str) or not 1<=len(value)<=100:raise ValueError('invalid funding public identity')
    number=0
    for char in value:
        if char not in ALPHABET:raise ValueError('invalid funding public identity')
        number=number*58+ALPHABET.index(char)
    raw=b'\0'*(len(value)-len(value.lstrip('1')))+number.to_bytes((number.bit_length()+7)//8,'big')
    if len(raw)!=size or b58(raw)!=value:raise ValueError('noncanonical funding public identity')
    return raw


def message(payer,target,blockhash,amount):
    # Legacy transaction: one writable signer, writable destination, readonly
    # system program; one SystemInstruction::Transfer (u32 discriminant 2).
    return (b'\x01\x00\x01\x03'+un58(payer,32)+un58(target,32)+bytes(32)+
            un58(blockhash,32)+b'\x01\x02\x02\x00\x01\x0c'+struct.pack('<IQ',2,amount))


def checked_int(value,maximum=2**64-1):
    if type(value) is not int or not 0<=value<=maximum:raise ValueError('invalid funding RPC integer')
    return value


def value(reply):
    if not isinstance(reply,dict) or 'value' not in reply:raise ValueError('invalid funding RPC response')
    return reply['value']


def signer(path,expected):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    secret=decode(read(Path(path),2048,secret=True))
    if (not isinstance(secret,list) or len(secret)!=64 or
            any(type(byte) is not int or not 0<=byte<=255 for byte in secret)):
        raise ValueError('operator key must be exactly 64 bounded bytes')
    key=Ed25519PrivateKey.from_private_bytes(bytes(secret[:32]))
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    if bytes(secret[32:])!=public or public!=un58(expected,32):
        raise ValueError('original relay signer identity differs')
    return key


def checked_intent(intent,plan,payer):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if (not isinstance(intent,dict) or set(intent)!=KEYS or intent['format']!=FORMAT or
            intent['plan_sha256']!=hash_value(plan) or intent['network']!=plan['network'] or
            intent['payer']!=payer or intent['target']!=plan['source_fee_address'] or
            type(intent['amount']) is not int or intent['amount']!=plan['public_budget']):
        raise ValueError('original allocation binding changed; never refill or replace it')
    checked_int(intent['last_valid_block_height']);checked_int(intent['fee'],10_000)
    if not isinstance(intent['transaction'],str) or len(intent['transaction'])!=288:
        raise ValueError('invalid original allocation packet')
    try:packet=base64.b64decode(intent['transaction'],validate=True)
    except (ValueError,TypeError) as error:raise ValueError('invalid original allocation packet') from error
    msg=message(payer,intent['target'],intent['blockhash'],intent['amount'])
    signature=un58(intent['signature'],64)
    if packet!=b'\x01'+signature+msg or base64.b64encode(packet).decode()!=intent['transaction']:
        raise ValueError('original allocation packet changed')
    try:Ed25519PublicKey.from_public_bytes(un58(payer,32)).verify(signature,msg)
    except Exception as error:raise ValueError('original allocation signature is invalid') from error
    return packet


def finalized(rpc,intent):
    reply=value(rpc('getSignatureStatuses',[[intent['signature']],{'searchTransactionHistory':True}]))
    if not isinstance(reply,list) or len(reply)!=1:raise ValueError('invalid original allocation status')
    status=reply[0]
    if status is None:return None
    if not isinstance(status,dict):raise ValueError('invalid original allocation status')
    if status.get('confirmationStatus')!='finalized':return None
    if 'err' not in status or status['err'] is not None:raise ValueError('original allocation finalized unsuccessfully; never replace it')
    slot=checked_int(status.get('slot'))
    if slot==0:raise ValueError('invalid finalized allocation slot')
    tx=rpc('getTransaction',[intent['signature'],{'encoding':'base64','commitment':'finalized',
                                                'maxSupportedTransactionVersion':0}])
    if (not isinstance(tx,dict) or type(tx.get('slot')) is not int or tx['slot']!=slot or
            tx.get('transaction')!=[intent['transaction'],'base64'] or
            not isinstance(tx.get('meta'),dict) or 'err' not in tx['meta'] or tx['meta']['err'] is not None or
            type(tx['meta'].get('fee')) is not int or tx['meta']['fee']!=intent['fee']):
        raise ValueError('exact finalized allocation evidence unavailable; preserve original identity')
    return dict(format='zolana-native-cohort-public-finalized-v1',plan_sha256=intent['plan_sha256'],
                network=intent['network'],payer=intent['payer'],target=intent['target'],
                amount=intent['amount'],signature=intent['signature'],slot=slot,fee=intent['fee'],
                transaction_sha256=hashlib.sha256(base64.b64decode(intent['transaction'])).hexdigest())


def fund_public(root,plan,rpc,payer_file,expected_payer):
    """Resolve/replay one exact allocation; raise FundingPending until finalized.

    rpc(method, params_list) must return a decoded JSON-RPC *result*, using the
    independently pinned private validator transport. This function never opens
    a network connection or chooses an RPC endpoint itself.
    """
    validate_plan(plan);un58(expected_payer,32)
    if expected_payer==plan['source_fee_address']:raise ValueError('allocation payer and target must differ')
    root=Path(root).absolute();directory(root)
    folder=root/'funding'
    if not os.path.lexists(folder):folder.mkdir(mode=0o700);fsync_dir(root)
    directory(folder)
    lock=folder/'public.lock';first=not os.path.lexists(lock)
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_size:
            raise ValueError('unsafe allocation lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fsync_dir(folder)
        saved=folder/'public.json';receipt=folder/'public-finalized.json'
        if rpc('getGenesisHash',[])!=plan['network']['genesis_hash']:raise ValueError('funding RPC genesis mismatch')
        if os.path.lexists(saved):
            intent=decode(read(saved,8192,secret=True));checked_intent(intent,plan,expected_payer)
        else:
            if not first or os.path.lexists(receipt):
                raise ValueError('original allocation journal missing; operator review required, never refill')
            if checked_int(value(rpc('getBalance',[plan['source_fee_address'],{'commitment':'finalized'}])))!=0:
                raise ValueError('new allocation target must have zero finalized public balance')
            key=signer(payer_file,expected_payer)
            latest=value(rpc('getLatestBlockhash',[{'commitment':'finalized'}]))
            if not isinstance(latest,dict):raise ValueError('invalid funding blockhash response')
            height=checked_int(latest.get('lastValidBlockHeight'))
            msg=message(expected_payer,plan['source_fee_address'],latest.get('blockhash'),plan['public_budget'])
            fee=checked_int(value(rpc('getFeeForMessage',[base64.b64encode(msg).decode(),{'commitment':'finalized'}])),10_000)
            balance=checked_int(value(rpc('getBalance',[expected_payer,{'commitment':'finalized'}])))
            if balance<plan['public_budget']+fee+RETAIN:raise ValueError('relay payer must retain at least 100m units')
            signature=key.sign(msg);packet=b'\x01'+signature+msg
            intent=dict(format=FORMAT,plan_sha256=hash_value(plan),network=plan['network'],payer=expected_payer,
                target=plan['source_fee_address'],amount=plan['public_budget'],blockhash=latest['blockhash'],
                last_valid_block_height=height,fee=fee,transaction=base64.b64encode(packet).decode(),signature=b58(signature))
            checked_intent(intent,plan,expected_payer);create(saved,canonical(intent));fsync_dir(folder)
        result=finalized(rpc,intent)
        if result is not None:
            raw=canonical(result)
            if os.path.lexists(receipt):
                if read(receipt,8192,secret=True)!=raw:raise ValueError('original allocation receipt changed')
            else:create(receipt,raw);fsync_dir(folder)
            return result
        if os.path.lexists(receipt):raise ValueError('original finalized allocation evidence unavailable; preserve receipt')
        height=checked_int(rpc('getBlockHeight',[{'commitment':'finalized'}]))
        if height>intent['last_valid_block_height']:
            raise ValueError('original allocation expired or uncertain; never re-sign or refill')
        try:
            reply=rpc('sendTransaction',[intent['transaction'],{'encoding':'base64','skipPreflight':False,
                'preflightCommitment':'confirmed','maxRetries':0}])
        except Exception as error:
            raise FundingPending('original allocation delivery uncertain; signed journal retained') from error
        if reply!=intent['signature']:raise ValueError('allocation broadcast returned a different signature')
        raise FundingPending('original allocation pending finality; signed journal retained')
    finally:os.close(fd)
