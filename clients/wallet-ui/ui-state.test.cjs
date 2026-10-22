// Source-only wallet UX regression checks. No helper, wallet data or chain is opened.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const source = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const startup = source.indexOf("try {\n  session = await (await fetch('/api/session')).json();");
assert(startup > 0);
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    id, disabled:false, textContent:'', className:'', attributes:{}, children:[], events:{},
    setAttribute(name,value) { this.attributes[name]=value; },
    removeAttribute(name) { delete this.attributes[name]; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    addEventListener(name,handler) { this.events[name]=handler; },
    append(...items) { this.children.push(...items); }, after() {},
    scrollIntoView() {}, focus() {}, contains() { return false; },
  });
  return elements.get(id);
}
const document = {
  body:element('body'), activeElement:element('body'),
  getElementById:element, querySelector:s=>element(s.slice(1)), addEventListener() {},
  createElement:()=>element(`created-${elements.size}`),
};
async function main() {
  const construct = new AsyncFunction('document', source.slice(0,startup)+`
    let apiCalls=[], renderCount=0, nextResult={}, nextError=null;
    const actualRenderer = renderDashboard;
    setScreen = () => {};
    renderDashboard = () => { renderCount++; };
    progress = () => {};
    api = async action => { apiCalls.push(action); if (nextError) throw nextError; if (nextResult.__status) Object.assign(session,nextResult.__status); return nextResult; };
    return {
      setup(value={}) {
        session = {operator_sponsor_available:true,...value.session};
        balance = value.balance ?? 10; balanceVerified = value.verified ?? true;
        lastVerifiedAt = balanceVerified ? Date.now() : null;
        busy = false; password = ''; receipt = value.receipt || null; grant = null; apiCalls=[]; renderCount=0;
        nextError = value.error || null;
        nextResult = value.result || {balance:10};
        for (const id of ['send','withdraw','fund']) document.getElementById(id).disabled=false;
      },
      applyAvailability, dashboard, send, withdraw, work, actualRenderer,
      snapshot() { return {verified:balanceVerified,balance,calls:apiCalls.slice(),renders:renderCount,receipt}; },
    };
  `);
  const ui=await construct(document);
  function paymentDisabled(expected) {
    assert.equal(element('send').disabled,expected,'private send availability');
    assert.equal(element('withdraw').disabled,expected,'public withdrawal availability');
  }
  ui.setup({verified:false}); ui.applyAvailability(); paymentDisabled(true);
  ui.setup({balance:0}); ui.applyAvailability(); paymentDisabled(true);
  ui.setup({balance:Number.MAX_SAFE_INTEGER+1}); ui.applyAvailability(); paymentDisabled(true);
  for (const key of ['pending','staging']) {
    ui.setup({session:{[key]:true}}); ui.applyAvailability(); paymentDisabled(true);
    await ui.send(); await ui.withdraw();
    assert.deepEqual(ui.snapshot().calls,[],'saved recovery state cannot request a new payment quote');
  }
  ui.setup({balance:10}); ui.applyAvailability(); paymentDisabled(false);
  ui.setup({verified:false}); await ui.send(); await ui.withdraw();
  assert.deepEqual(ui.snapshot().calls,[],'unverified balance must not start payment preparation');
  assert.match(element('notice').textContent,/Refresh your balance/);
  assert.equal(element('notice').attributes.role,'alert');

  ui.setup({balance:15,error:new Error('history unavailable')});
  await assert.rejects(ui.dashboard(),/history unavailable/);
  assert.equal(ui.snapshot().balance,15,'retain last-known evidence without presenting it as current');
  assert.equal(ui.snapshot().verified,false,'failed refresh invalidates payment availability');
  ui.applyAvailability(); paymentDisabled(true);

  for (const balance of [null,-1,1.5,Number.MAX_SAFE_INTEGER+1]) {
    ui.setup({result:{balance}});
    await assert.rejects(ui.dashboard(),/verified balance response is unavailable/);
    assert.equal(ui.snapshot().verified,false);
  }
  ui.setup({result:{balance:12}}); await ui.dashboard();
  assert.equal(ui.snapshot().verified,true);
  assert.equal(ui.snapshot().balance,12);

  ui.setup({verified:false}); await ui.work('Refresh',async()=>{}); paymentDisabled(true);
  ui.setup({session:{pending:true}}); await ui.work('Check',async()=>{}); paymentDisabled(true);
  ui.setup({session:{staging:true},result:{recovery_cleared:true,__status:{staging:false}}});
  ui.actualRenderer();
  const recovery=element('recovery-controls').children;
  await recovery.at(-1).events.click();
  assert.equal(ui.snapshot().receipt,null,'cleanup without a prior staging receipt must not invent payment success');
  console.log('wallet UX state guards passed: stale/invalid/zero balances, pending/staging, safe quote gating, work completion, accessible errors and receipt-free cleanup');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
