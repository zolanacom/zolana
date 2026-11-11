// LOCAL101 actual worker control flow; synthetic public pools and inert storage/core.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
const worker=process.argv[2]?new URL("file://"+process.argv[2]):new URL("./product-worker.js",import.meta.url);
const source = await loadWorkerSource(worker);
const network={network:Array(32).fill(7),genesis_hash:"1".repeat(32)},program="1".repeat(32),poolAddress="2".repeat(32);
function pool({slot=1,backing=100,count=2,anchor=0}={}){
  const bytes=Buffer.alloc(25728);bytes.write("NPOOL004");bytes.fill(7,8,40);
  bytes.writeBigUInt64LE(1n,40);bytes.writeBigUInt64LE(BigInt(backing),48);bytes.writeBigUInt64LE(BigInt(count),56);
  bytes[1100]=anchor;
  return {context:{slot},value:{owner:program,lamports:101,data:[bytes.toString("base64"),"base64"]}};
}
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
function fixture(options={}){
  const messages=[],trace=[],calls=[],commitGate=options.commitGate,rpcGate=options.rpcGate;
  const p=options.pool||pool(),hint=options.hint||p;
  const context=createWorkerContext({TextEncoder,TextDecoder,Uint8Array,BigInt,atob,btoa,TypeError,AbortController,setTimeout,clearTimeout,
    network,program,poolAddress,p,hint,options,trace,commitGate,rpcGate,WalletStorageError:class extends Error{},
    crypto:{randomUUID:()=>"fixture-id"},performance:{now:()=>1},self:{postMessage:r=>messages.push(r)},
    fetch:async()=>{
      if(options.accessFailure==="connection")throw new TypeError("fixed connection interruption");
      const status=options.accessFailure==="502"||options.accessFailure==="unmarked502"?502:options.accessFailure==="rate_limit"?429:200;
      const result=status===502?(options.accessFailure==="502"?{error:"upstream_unavailable",outcome:"unknown",automatic_retry:false}:{error:"unmarked"}):
        {admitted:!options.notInvited,fee_address:program,state:options.accessFailure==="malformed"?"wrong":options.notInvited?"not_invited":"active",access_until:null};
      const data=new TextEncoder().encode(JSON.stringify(result));let done=false;
      return {status,ok:status===200,headers:{get:()=>"application/json"},body:{getReader:()=>({read:async()=>done?{done:true}:(done=true,{done:false,value:data}),releaseLock(){}})}};
    },
    recordCall:(m,params,limit)=>calls.push([m,JSON.parse(JSON.stringify(params)),limit])});
  vm.runInContext(`${source}
    configuration={network,label:"fixture",environment:"testnet"};catalog={};
    transport={program,pool:poolAddress,rpc_audience:"https://fixture.invalid",faucet_audience:"https://fixture.invalid/faucet"};
    let hintReply=hint,pending=options.pending||null,snapshotNumber=0,slot=0,locked=false;
    const oldVerified={verified:true,balance:"50",max_payment:"50",slot:0};
    if(options.verified)session.verifiedStatus=oldVerified;
    if(options.baseline)session.verifiedPoolHint=poolPaymentHint(options.baseline);
    if(options.review)session.reviewedQuote={reviewId:"original-review"};
    session.savedPending=options.savedPending||false;
    session.store={snapshot:async()=>{
      trace.push("snapshot");snapshotNumber++;
      if(options.pendingOnSnapshot===snapshotNumber)pending={packetId:"original-pending"};
      return {revision:4,encryptedCheckpoint:null,pending};},
      commitCheckpoint:async()=>{
        trace.push("commit-start");options.onCommitStarted?.();if(commitGate)await commitGate.promise;
        if(options.commitFailure)throw Error("durability failed");trace.push("commit-done");},
      settlePending:async()=>{throw Error("automatic action must never settle pending");},
      close:()=>trace.push("store-close")};
    session.vault={identity:()=>JSON.stringify({fee_address:program}),admission_status:()=>"{}",rpc_header:()=>"fixture-access",checkpoint_info:()=>'{"slot":0}',
      begin_sync:()=>{trace.push("begin");return JSON.stringify({slot:0,target:p.context.slot});},
      apply_compact_history_page:()=>{throw Error("unexpected retained page");},
      apply_canonical_blocks:()=>{trace.push("canonical");slot=p.context.slot;return JSON.stringify({slot,target:slot});},
      finish_sync:()=>{trace.push("finish");if(options.verifyFailure)throw Error("verification rejected");return new Uint8Array([9]);},
      payment_status:()=>JSON.stringify(options.invalidStatus?{verified:false,balance:"99",max_payment:"99",slot}:options.wrongStatusSlot?
        {verified:true,balance:"99",max_payment:"99",slot:slot+1}:{verified:true,balance:"99",max_payment:"99",slot}),
      lock:()=>{locked=true;trace.push("lock");},free:()=>trace.push("free")};
    core=async()=>({});const originalRpc=rpc;
    rpc=async(method,params,at,value,unsigned,limit)=>{
      recordCall(method,params,limit);
      if(options.rpcError){const error=publicFailure(options.rpcError,"fixed fixture failure");
        if(options.interrupted)interruptedReadFailures.add(error);throw error;}
      if(method==="getAccountInfo"){
        if(rpcGate)await rpcGate.promise;
        if(options.lockAfterRpc){session.generation++;session.release();}
        if(options.pendingAfterRpc)pending={packetId:"new-original-pending"};
        return hintReply;
      }
      if(method==="getWalletSyncSnapshot")return {format:"zolana-wallet-sync-snapshot-v1",network,genesis:network.genesis_hash,pool:p,
        target_header:{blockhash:"1".repeat(32),blockHeight:1},saved_header:null,fallback:null,
        canonical_tail:{after_slot:0,target_slot:p.context.slot,next_slot:p.context.slot,complete:true,
          blocks:[{slot:p.context.slot,block:{parentSlot:0,blockhash:"1".repeat(32),previousBlockhash:"1".repeat(32),blockHeight:1,transactions:[]}}]}};
      throw Error("unexpected RPC");
    };
    globalThis.api=action=>dispatch({id:"fixture",action});
    globalThis.inspect=()=>({baseline:session.verifiedPoolHint,verified:session.verifiedStatus,pending:session.savedPending,review:session.reviewedQuote,locked});
    globalThis.setHint=p=>{hintReply=p;};globalThis.setReview=()=>{session.reviewedQuote={reviewId:"late-review"};};
    globalThis.forceLock=()=>{session.generation++;session.release();};
    globalThis.waitQueue=()=>session.completion;
  `,context);
  return {context,messages,trace,calls};
}
let cases=0;
{
  const f=fixture();assert.deepEqual(JSON.parse(JSON.stringify(await f.context.api("payment_hint"))),{changed:true,baselineKnown:false});
  assert.deepEqual(f.calls[0],["getAccountInfo",[poolAddress,{commitment:"finalized",encoding:"base64"}],65536]);
  assert.equal(f.context.inspect().baseline,undefined);assert(!f.trace.includes("begin")&&!f.trace.includes("commit-start"));cases++;
}
{
  const baseline=pool(),f=fixture({baseline,hint:pool({slot:9,anchor:255})});
  assert.deepEqual(JSON.parse(JSON.stringify(await f.context.api("payment_hint"))),{changed:false,baselineKnown:true});
  for(const hint of [pool({backing:101}),pool({count:4})]){
    f.context.setHint(hint);assert.equal((await f.context.api("payment_hint")).changed,true);
    assert.equal((await f.context.api("payment_hint")).changed,true); // Reads never acknowledge a payment.
  }cases++;
}
for(const mutate of [
  p=>p.value.owner="3".repeat(32),p=>p.value.data[1]="base64+zstd",p=>p.value.data[0]=p.value.data[0].slice(4),
  p=>{const raw=Buffer.from(p.value.data[0],"base64");raw[0]=0;p.value.data[0]=raw.toString("base64");},
  p=>{const raw=Buffer.from(p.value.data[0],"base64");raw[8]=8;p.value.data[0]=raw.toString("base64");},
  p=>p.value.data.push("extra"),p=>p.value.data[0]="!".repeat(34304),p=>p.context.slot=-1
]){
  const bad=pool();mutate(bad);const f=fixture({baseline:pool(),hint:bad});const before=f.context.inspect().baseline;
  await assert.rejects(f.context.api("payment_hint"),e=>e.code==="hint");assert.equal(f.context.inspect().baseline,before);cases++;
}
for(const action of ["payment_hint","automatic_sync"]){
  for(const options of [{pending:{packetId:"original"}},{savedPending:true},{review:true}]){
    const f=fixture({...options,baseline:pool(),verified:true}),before=f.context.inspect();
    await assert.rejects(f.context.api(action),e=>["pending","review"].includes(e.code));
    assert.equal(f.calls.length,0);assert.equal(f.context.inspect().baseline,before.baseline);
    assert.equal(f.context.inspect().verified,before.verified);assert.equal(f.context.inspect().review,before.review);cases++;
  }
}
{
  const f=fixture({pendingOnSnapshot:2,verified:true,baseline:pool()}),old=f.context.inspect();
  await assert.rejects(f.context.api("automatic_sync"),e=>e.code==="pending");
  assert.equal(f.context.inspect().verified,old.verified);assert.equal(f.context.inspect().baseline,old.baseline);
  assert(!f.trace.includes("begin"));cases++;
}
for(const options of [{pendingAfterRpc:true},{lockAfterRpc:true}]){
  const f=fixture({...options,baseline:pool()});await assert.rejects(f.context.api("payment_hint"),e=>["pending","locked"].includes(e.code));
  assert(!f.trace.includes("commit-start"));if(options.lockAfterRpc)assert.equal(f.context.inspect().baseline,undefined);cases++;
}
{
  const commitGate=deferred(),began=deferred(),f=fixture({commitGate,onCommitStarted:began.resolve});const sync=f.context.api("automatic_sync");
  await began.promise;
  assert(f.trace.includes("commit-start"));assert.equal(f.context.inspect().baseline,undefined);
  f.context.setHint(pool({slot:2,backing:200,count:4}));commitGate.resolve();await sync;
  assert.equal((await f.context.api("payment_hint")).changed,true); // New payment during commit is not lost.
  assert.equal(f.trace.filter(x=>x==="commit-done").length,1);cases++;
}
for(const options of [{commitFailure:true},{verifyFailure:true},{invalidStatus:true},{wrongStatusSlot:true}]){
  const f=fixture({...options,baseline:pool({backing:50})}),old=f.context.inspect().baseline;
  await assert.rejects(f.context.api("automatic_sync"));assert.equal(f.context.inspect().baseline,old);cases++;
}
{
  const commitGate=deferred(),began=deferred(),f=fixture({commitGate,onCommitStarted:began.resolve});
  const sync=f.context.api("automatic_sync");await began.promise;f.context.forceLock();commitGate.resolve();
  await assert.rejects(sync,e=>e.code==="locked");assert.equal(f.context.inspect().baseline,undefined);
  assert.equal(f.context.inspect().verified,undefined);cases++;
}
{
  const f=fixture({review:true,verified:true,baseline:pool(),savedPending:true}),before=f.context.inspect();
  await f.context.api("cancel_review");const after=f.context.inspect();
  assert.equal(after.review,undefined);assert.equal(after.pending,true);assert.equal(after.baseline,before.baseline);assert.equal(after.verified,before.verified);
  await assert.rejects(f.context.api("payment_hint"),e=>e.code==="pending");cases++;
}
{
  const f=fixture({review:true});await f.context.api("cancel_review");assert.equal((await f.context.api("payment_hint")).changed,true);cases++;
}
for(const [rpcError,interrupted,retryable] of [["rate_limit",false,true],["connection",true,true],["transport",true,true],
  ["transport",false,false],["access",false,false],["rpc",false,false],["hint",false,false]]){
  for(const action of ["payment_hint","automatic_sync"]){
    const f=fixture({rpcError,interrupted});f.context.self.onmessage({data:{id:"reply",action}});await f.context.waitQueue();
    assert.equal(f.messages.at(-1).ok,false);assert.equal(f.messages.at(-1).retryableRead,retryable);cases++;
  }
  const f=fixture({rpcError,interrupted});f.context.self.onmessage({data:{id:"manual",action:"sync"}});await f.context.waitQueue();
  assert.equal(Object.hasOwn(f.messages.at(-1),"retryableRead"),false);cases++;
}
for(const [accessFailure,retryable] of [["connection",true],["502",true],["rate_limit",true],["unmarked502",false],["malformed",false]]){
  const f=fixture({accessFailure});f.context.self.onmessage({data:{id:"bootstrap",action:"check_access"}});await f.context.waitQueue();
  assert.equal(f.messages.at(-1).ok,false);assert.equal(f.messages.at(-1).retryableRead,retryable);cases++;
}
{
  const f=fixture({notInvited:true});f.context.self.onmessage({data:{id:"bootstrap",action:"check_access"}});await f.context.waitQueue();
  assert.equal(f.messages.at(-1).ok,true);assert.equal(f.messages.at(-1).result.admission.admitted,false);
  assert.equal(Object.hasOwn(f.messages.at(-1),"retryableRead"),false);cases++;
}
{
  const rpcGate=deferred(),f=fixture({rpcGate});
  f.context.self.onmessage({data:{id:"hint",action:"payment_hint"}});
  for(let i=0;i<10&&f.calls.length===0;i++)await Promise.resolve();
  f.context.self.onmessage({data:{id:"cancel",action:"cancel_review"}});
  assert.equal(f.messages.length,0);rpcGate.resolve();await f.context.waitQueue();
  assert.deepEqual(f.messages.map(m=>m.id),["hint","cancel"]);cases++;
}
console.log("PASS: "+cases+" LOCAL101 worker cases cover stable public hints, strict bounds, pending/review/lock races, durable baseline publication, queueing and auto-only retry classification.");
