// Execute the production scheduler with a deterministic clock and inert reads.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import test from 'node:test';

const app = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const source = app.slice(app.indexOf('function createAutomaticReceive('), app.indexOf('/* End automatic receive controller. */'));
assert(source.startsWith('function createAutomaticReceive('));
const create = vm.runInNewContext(`${source}\ncreateAutomaticReceive`);
const drain = async () => { for (let i=0;i<16;i++) await Promise.resolve(); };
const deferred = () => { let resolve,reject; const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject}; };

function fixture(options={}) {
  let time=0, id=0;
  const timers=new Map(), calls=[], errors=[], results=[];
  const state={enabled:true,blocked:false,pending:false,admitted:true,verified:true,...options.state};
  const actions={
    access: options.access || (async()=>({admitted:true})),
    hint: options.hint || (async()=>({changed:false,baselineKnown:true})),
    sync: options.sync || (async()=>({verified:true})),
  };
  const record=(kind,fn)=>async()=>{calls.push([kind,time]);return fn();};
  const controller=create({
    state:()=>({...state}), now:()=>time,
    setTimer:(fn,delay)=>{const value=++id;timers.set(value,{fn,at:time+delay});return value;},
    clearTimer:value=>timers.delete(value),
    readAccess:record('access',()=>actions.access()), readHint:record('hint',()=>actions.hint()),
    synchronize:record('sync',()=>actions.sync()),
    onResult:(result,kind)=>{results.push([kind,result]);if(kind==='access')state.admitted=result.admitted;if(kind==='sync')state.verified=result.verified;},
    onError:async(error,info)=>{errors.push([error.code,info.retrying,time]);},
  });
  async function advance(ms=0) {
    const end=time+ms;let ticks=0;
    for (;;) {
      const entry=[...timers.entries()].filter(([,value])=>value.at<=end).sort((a,b)=>a[1].at-b[1].at)[0];
      if(!entry)break;
      assert(++ticks<10000,'scheduler spin');
      time=entry[1].at;timers.delete(entry[0]);entry[1].fn();await drain();
    }
    time=end;await drain();
  }
  return {controller,state,calls,errors,results,timers,actions,advance};
}

test('initial unlocked member checks access and commits verified sync before watching',async()=>{
  const f=fixture({state:{admitted:null,verified:false}});
  f.controller.resume({immediate:true});await f.advance();
  assert.deepEqual(f.calls.map(c=>c[0]),['access','sync','hint']);
  assert.equal(f.state.verified,true);
});
test('uninvited wallet checks membership once, never redeems an invitation or requests funding',async()=>{
  const f=fixture({state:{admitted:null,verified:false},access:async()=>({admitted:false})});
  f.controller.resume({immediate:true});await f.advance(60000);
  assert.deepEqual(f.calls,[['access',0]]);
  f.state.admitted=true;f.controller.resume({immediate:true});await f.advance();
  assert(f.calls.some(c=>c[0]==='sync'));
});
test('unchanged public hint never starts a history sync and is limited to60/minute',async()=>{
  const f=fixture();f.controller.resume({immediate:true});await f.advance(120000);
  assert(f.calls.every(c=>c[0]==='hint'));
  for(const [,at]of f.calls)assert(f.calls.filter(([,t])=>t>at-60000&&t<=at).length<=60);
});
test('unchanged hints keep one second between starts and wait for a slow read to finish', async () => {
  const first = deferred();
  const second = deferred();
  const unchanged = {changed:false, baselineKnown:true};
  const f = fixture({hint: () => first.promise});
  f.controller.resume({immediate:true});
  await f.advance(280);
  first.resolve(unchanged);
  f.actions.hint = () => second.promise;
  await drain();
  await f.advance(719);
  assert.deepEqual(f.calls, [['hint', 0]]);
  await f.advance(1);
  assert.deepEqual(f.calls, [['hint', 0], ['hint', 1000]]);
  await f.advance(1500);
  assert.equal(f.calls.length, 2);
  f.actions.hint = async () => unchanged;
  second.resolve(unchanged);
  await drain();
  await f.advance();
  assert.deepEqual(f.calls, [['hint', 0], ['hint', 1000], ['hint', 2500]]);
});
test('changed hints coalesce behind a one-second minimum gap and 12 syncs per minute',async()=>{
  const f=fixture({hint:async()=>({changed:true,baselineKnown:true})});
  f.controller.resume({immediate:true});await f.advance(120000);
  const starts=f.calls.filter(c=>c[0]==='sync').map(c=>c[1]);
  assert(starts.length>=20);
  assert.equal(starts[1] - starts[0], 1000);
  starts.forEach((at,i)=>{if(i)assert(at-starts[i-1]>=1000);assert(starts.filter(t=>t>at-60000&&t<=at).length<=12);});
});
test('unknown baseline requires verified sync rather than inferring a balance',async()=>{
  const f=fixture({hint:async()=>({changed:false,baselineKnown:false})});
  f.controller.resume({immediate:true});await f.advance();
  assert(f.calls.some(c=>c[0]==='sync'));
});
for(const field of ['blocked','pending'])test(`no automatic work while ${field}`,async()=>{
  const f=fixture({state:{[field]:true}});f.controller.resume({immediate:true});await f.advance(10000);
  assert.equal(f.calls.length,0);f.state[field]=false;await f.advance(1000);assert.equal(f.calls[0][0],'hint');
});
test('disabled/locked/background state owns no timer or read',async()=>{
  const f=fixture({state:{enabled:false}});f.controller.resume({immediate:true});await f.advance(30000);
  assert.equal(f.calls.length,0);assert.equal(f.timers.size,0);
});
test('one hint remains outstanding; opening a review before its reply suppresses sync',async()=>{
  const gate=deferred();const f=fixture({hint:()=>gate.promise});
  f.controller.resume({immediate:true});await f.advance(10000);assert.equal(f.calls.length,1);
  f.state.blocked=true;gate.resolve({changed:true,baselineKnown:true});await drain();await f.advance(10000);
  assert.equal(f.calls.length,1);
});
test('pause invalidates late reads and resume retains its wakeup after the old read finishes',async()=>{
  const gate=deferred();const f=fixture({hint:()=>gate.promise});
  f.controller.resume({immediate:true});await f.advance();f.controller.pause();
  f.actions.hint=async()=>({changed:false,baselineKnown:true});f.controller.resume({immediate:true});
  gate.resolve({changed:true,baselineKnown:true});await drain();await f.advance(1000);
  assert.deepEqual(f.calls.map(c=>c[0]),['hint','hint']);
  assert.equal(f.results.filter(c=>c[0]==='sync').length,0);
});
test('lock/hide during automatic sync discards its result',async()=>{
  const gate=deferred();const f=fixture({state:{verified:false},sync:()=>gate.promise});
  f.controller.resume({immediate:true});await f.advance();f.state.enabled=false;f.controller.pause();
  gate.resolve({verified:true});await drain();await f.advance(60000);
  assert.equal(f.state.verified,false);assert.equal(f.results.length,0);assert.equal(f.timers.size,0);
});
test('only reviewed transient reads retry, with bounded exponential backoff',async()=>{
  const error=Object.assign(new Error('temporary'),{code:'connection',retryableRead:true});
  const f=fixture({hint:async()=>{throw error;}});f.controller.resume({immediate:true});await f.advance(120000);
  assert.deepEqual(f.calls.slice(0,5).map(c=>c[1]),[0,2000,6000,14000,30000]);
  assert(f.calls.length<10);assert(f.errors.every(c=>c[1]===true));
});
for(const code of ['access','transport','sync','history','pending','review'])test(`${code} stops automatic reads until explicit successful reset`,async()=>{
  const f=fixture({hint:async()=>{throw Object.assign(new Error('stop'),{code});}});
  f.controller.resume({immediate:true});await f.advance(60000);assert.equal(f.calls.length,1);
  f.controller.resume();await f.advance(10000);assert.equal(f.calls.length,1);
  f.actions.hint=async()=>({changed:false,baselineKnown:true});f.controller.resume({resetFailure:true,immediate:true});await f.advance();
  assert.equal(f.calls.length,2);
});
test('malformed hint stops before any balance or sync result is accepted',async()=>{
  const f=fixture({hint:async()=>({changed:'yes',baselineKnown:true})});
  f.controller.resume({immediate:true});await f.advance(10000);
  assert.equal(f.results.length,0);assert.deepEqual(f.errors.map(c=>c.slice(0,2)),[['hint',false]]);
});
