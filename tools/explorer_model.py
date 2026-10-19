"""Bounded public explorer DTOs. No RPC transport or wallet capability."""
import base64
import math
import re

ALPHABET='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
MAX_BYTES=2*1024*1024
MAX_BLOCKS=2048


def b58(raw):
    number=int.from_bytes(raw,'big');result=''
    while number:number,index=divmod(number,58);result=ALPHABET[index]+result
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+result


def natural(value):return type(value) is int and 0<=value<=2**53-1


def public_key(value):
    if not isinstance(value,str) or not 32<=len(value)<=44:return False
    number=0
    for c in value:
        if c not in ALPHABET:return False
        number=number*58+ALPHABET.index(c)
    return len(value)-len(value.lstrip('1'))+(number.bit_length()+7)//8==32


def transaction(value,slot,position,status='recorded'):
    if not isinstance(value,dict) or not isinstance(value.get('transaction'),list) or len(value['transaction'])!=2 or value['transaction'][1]!='base64' or not isinstance(value.get('meta'),dict):raise ValueError('unsupported recorded transaction')
    encoded=value['transaction'][0]
    if not isinstance(encoded,str) or not 1<=len(encoded)<=MAX_BYTES:raise ValueError('recorded transaction exceeds bounds')
    raw=base64.b64decode(encoded,validate=True);count=0;cursor=0
    for shift in (0,7,14):
        if cursor>=len(raw):raise ValueError('truncated signature vector')
        byte=raw[cursor];cursor+=1;count|=(byte&127)<<shift
        if byte<128:break
    else:raise ValueError('invalid signature vector')
    if not 1<=count<=64 or cursor+count*64>=len(raw) or raw[:cursor]!=bytes([count]):raise ValueError('invalid recorded signature count')
    fee=value['meta'].get('fee')
    if not natural(fee) or 'err' not in value['meta']:raise ValueError('invalid recorded transaction metadata')
    return {'signature':b58(raw[cursor:cursor+64]),'slot':slot,'position':position,'fee_units':fee,'execution':'success' if value['meta']['err'] is None else 'failed','status':status}


def block(slot,value):
    if not isinstance(value,dict) or not natural(slot):raise ValueError('invalid finalized block')
    result={key:value[key] for key in ('parentSlot','blockhash','previousBlockhash','blockHeight')}
    if not natural(result['parentSlot']) or not result['parentSlot']<slot or not natural(result['blockHeight']) or not public_key(result['blockhash']) or not public_key(result['previousBlockhash']) or not isinstance(value.get('transactions'),list) or len(value['transactions'])>1024:raise ValueError('invalid finalized block metadata')
    rows=[transaction(tx,slot,i,'finalized') for i,tx in enumerate(value['transactions'])]
    return {'slot':slot,'parent_slot':result['parentSlot'],'blockhash':result['blockhash'],'previous_blockhash':result['previousBlockhash'],'block_height':result['blockHeight'],'transaction_count':len(rows),'transactions':rows,'status':'finalized'}


def validate(value,network):
    keys={'format','network','instance','sequence','published_at','sampled_at','phase','observed_finalized_slot','blocks','validators'}
    if not isinstance(value,dict) or set(value)!=keys or value['format']!='native-explorer-feed-v1' or value['network']!=network or not isinstance(value['instance'],str) or re.fullmatch('[0-9a-f]{32}',value['instance']) is None or not natural(value['sequence']) or value['sequence']==0 or value['phase'] not in ('live','syncing','paused','unavailable'):raise ValueError('invalid explorer feed identity')
    for k in ('published_at','sampled_at'):
        if type(value[k]) not in (int,float) or not math.isfinite(value[k]) or value[k]<0:raise ValueError('invalid explorer timestamp')
    if value['sampled_at']>value['published_at'] or not natural(value['observed_finalized_slot']) or not isinstance(value['blocks'],list) or not 1<=len(value['blocks'])<=MAX_BLOCKS or not isinstance(value['validators'],list) or len(value['validators'])>128:raise ValueError('invalid explorer feed bounds')
    previous=None;signatures=set()
    for item in value['blocks']:
        if not isinstance(item,dict) or set(item)!={'slot','parent_slot','blockhash','previous_blockhash','block_height','transaction_count','transactions','status'} or not natural(item['slot']) or not natural(item['parent_slot']) or item['parent_slot']>=item['slot'] or not natural(item['block_height']) or not public_key(item['blockhash']) or not public_key(item['previous_blockhash']) or item['status']!='finalized' or not isinstance(item['transactions'],list) or not natural(item['transaction_count']) or item['transaction_count']!=len(item['transactions']) or len(item['transactions'])>1024:raise ValueError('invalid explorer block')
        if previous and (item['parent_slot']!=previous['slot'] or item['previous_blockhash']!=previous['blockhash'] or item['block_height']!=previous['block_height']+1):raise ValueError('explorer feed ancestry changed')
        if item['parent_slot']==0 and item['previous_blockhash']!=network['genesis_hash']:raise ValueError('explorer genesis anchor changed')
        for i,tx in enumerate(item['transactions']):
            if not isinstance(tx,dict) or set(tx)!={'signature','slot','position','fee_units','execution','status'} or not isinstance(tx['signature'],str) or re.fullmatch('[1-9A-HJ-NP-Za-km-z]{64,88}',tx['signature']) is None or tx['signature'] in signatures or type(tx['slot']) is not int or tx['slot']!=item['slot'] or type(tx['position']) is not int or tx['position']!=i or not natural(tx['fee_units']) or tx['execution'] not in ('success','failed') or tx['status']!='finalized':raise ValueError('invalid explorer transaction')
            signatures.add(tx['signature'])
        previous=item
    if previous['slot']>value['observed_finalized_slot'] or (value['phase']=='live' and previous['slot']!=value['observed_finalized_slot']):raise ValueError('explorer finality mismatch')
    votes=set()
    for v in value['validators']:
        if not isinstance(v,dict) or set(v)!={'identity','vote_account','last_vote','activated_stake','delinquent'} or not public_key(v['identity']) or not public_key(v['vote_account']) or v['vote_account'] in votes or not natural(v['last_vote']) or not isinstance(v['activated_stake'],str) or re.fullmatch('[0-9]{1,20}',v['activated_stake']) is None or int(v['activated_stake'])>2**64-1 or type(v['delinquent']) is not bool:raise ValueError('invalid public validator observation')
        votes.add(v['vote_account'])
    return value
