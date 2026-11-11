// Actual worker control flow, inert RPC/storage/core contract fixtures only.
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
import { hintAccount } from './product-worker-pool-fixture.mjs';
const worker=process.argv[2]?new URL('file://'+process.argv[2]):new URL('./product-worker.js',import.meta.url);
const source = await loadWorkerSource(worker);
const network={network:Array(32).fill(7),genesis_hash:'1'.repeat(32)},before=1000,target=2000;
function page(tip=900){return {network,checkpoint:{segments:1,sha256:'a'.repeat(64)},retained_tip:tip,
  after_slot:before,through_slot:tip,next_slot:before,complete:true,
  compact_headers:{format:'zolana-retained-headers-v1',count:0,parent_slot:null,previous_blockhash:null,data_base64:''},transactions:[]};}
function fixture({value=page(),coreError=false,cursorSlot=before,cursorTarget=target,canonicalError=false}={}){
  const trace=[],calls=[];let tick=0;
  const context=createWorkerContext({hintAccount,TextEncoder,Uint8Array,atob,btoa,BigInt,network,value,coreError,cursorSlot,cursorTarget,canonicalError,
    trace,WalletStorageError:class extends Error{},self:{postMessage(){}},crypto:{randomUUID:()=> 'fixture-id'},
    performance:{now:()=>++tick},recordCall:(m,p)=>calls.push([m,JSON.parse(JSON.stringify(p))])});
  vm.runInContext(`${source}
    configuration={network,label:'fixture',environment:'testnet'};
    transport={program:hintAccount().owner,pool:'1'.repeat(32),rpc_audience:'https://fixture.invalid/'};
    const original=new Uint8Array([7]),final=new Uint8Array([8]);let slot=1000;
    session.store={snapshot:async()=>({revision:17,encryptedCheckpoint:original,pending:null}),
      commitCheckpoint:async input=>{if(input.expectedRevision!==17||input.encryptedCheckpoint!==final)throw Error('changed commit');trace.push('commit');},
      settlePending:async()=>{throw Error('unexpected pending settlement');}};
    session.vault={identity:()=> '{}',rpc_header:()=> 'fixture',checkpoint_info:()=> '{"slot":1000}',
      begin_sync:(pool,h,checkpoint,cached)=>{if(checkpoint!==original||JSON.parse(cached).blockhash!=='hash-1000')throw Error('checkpoint discarded');
        trace.push('begin-original');return JSON.stringify({slot,target:2000});},
      apply_compact_history_page:(metadata,bytes)=>{trace.push('core-retained');
        if(coreError)throw Error('core rejected malformed network/checkpoint/page');
        if(bytes.length!==0||JSON.parse(metadata).compact_headers.count!==0)throw Error('bad byte bridge');
        return JSON.stringify({slot:cursorSlot,target:cursorTarget});},
      apply_canonical_blocks:text=>{trace.push('canonical');if(canonicalError)throw Error('canonical verification failed');
        for(const block of JSON.parse(text)){if(block.parent_slot!==slot||block.previous_blockhash!=='hash-'+slot)throw Error('missing canonical link');slot=block.slot;}
        return JSON.stringify({slot,target:2000});},
      finish_sync:()=>{trace.push('finish');if(slot!==2000)throw Error('target incomplete');return final;},
      payment_status:()=>JSON.stringify({verified:true,balance:'12000000',max_payment:'12000000',slot})};
    checkAccess=async()=>{trace.push('access');session.admission={admitted:true,state:'active',accessUntil:1234};};core=async()=>({});
    rpc=async(method,params)=>{recordCall(method,params);
      if(method==='getWalletSyncSnapshot')return {format:'zolana-wallet-sync-snapshot-v1',network,genesis:network.genesis_hash,
        pool:{context:{slot:2000},value:{...hintAccount(),lamports:1}},target_header:{blockhash:'hash-2000',blockHeight:2000},
        saved_header:{blockhash:'hash-1000',blockHeight:1000},canonical_tail:null,fallback:'tail-too-large'};
      if(method==='getWalletRetainedHistoryV3')return value;
      if(method==='getBlocks')return [1500,2000];
      if(method==='getWalletHistoryBlocks')return [{slot:1500,block:{parentSlot:1000,previousBlockhash:'hash-1000',blockhash:'hash-1500',blockHeight:1500,transactions:[]}},
        {slot:2000,block:{parentSlot:1500,previousBlockhash:'hash-1500',blockhash:'hash-2000',blockHeight:2000,transactions:[]}}];
      throw Error('unexpected method');};
    globalThis.sync=syncWallet;
  `,context);
  return {context,trace,calls};
}
let cases=0;
for(const tip of [900,before]){
  const f=fixture({value:page(tip)});const state=await f.context.sync();
  assert.deepEqual(f.calls.map(c=>c[0]),['getWalletSyncSnapshot','getWalletRetainedHistoryV3','getBlocks','getWalletHistoryBlocks']);
  assert.deepEqual(f.calls[2][1],[1001,2000,{commitment:'finalized'}]);
  assert.deepEqual(f.trace,['access','begin-original','core-retained','canonical','finish','commit']);
  assert.equal(state.verified.balance,'12000000');cases++;
}
for(const options of [{cursorSlot:999},{cursorSlot:before,cursorTarget:1999},
  {value:{...page(),complete:false}},{value:{...page(),retained_tip:'900'}},
  {value:{...page(),retained_tip:1500,through_slot:1500}}]){
  const f=fixture(options);await assert.rejects(f.context.sync(),e=>e.code==='history');
  assert(!f.trace.includes('canonical')&&!f.trace.includes('finish')&&!f.trace.includes('commit'));cases++;
}
for(const change of [p=>p.network={...network,network:Array(32).fill(8)},p=>p.checkpoint.sha256='b'.repeat(64),
  p=>p.after_slot=999,p=>p.through_slot=901,p=>p.next_slot=999]){
  const p=page();change(p);const f=fixture({value:p,coreError:true});await assert.rejects(f.context.sync());
  assert(f.trace.includes('core-retained'));assert(!f.trace.includes('canonical')&&!f.trace.includes('commit'));cases++;
}
{
  const p=page();p.compact_headers.data_base64='AB==';const f=fixture({value:p});await assert.rejects(f.context.sync(),e=>e.code==='history');
  assert(!f.trace.includes('core-retained')&&!f.trace.includes('commit'));cases++;
}
{
  const f=fixture({canonicalError:true});await assert.rejects(f.context.sync());
  assert(f.trace.includes('core-retained')&&f.trace.includes('canonical'));assert(!f.trace.includes('finish')&&!f.trace.includes('commit'));cases++;
}
console.log('PASS: '+cases+' retained-lag cases preserve the exact saved checkpoint, require core validation, fetch the canonical tail, and reject regression/inconsistency without commit.');
