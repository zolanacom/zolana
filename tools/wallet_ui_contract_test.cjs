// Focused UI contract checks. No browser, wallet, validator or network is started.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'clients/wallet-ui/app.js'), 'utf8');
const startup = source.indexOf("try {\n  session = await (await fetch('/api/session')).json();");
assert(startup > 0, 'Keep session startup separate from isolated UI checks');

function documentStub() {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      id, textContent: '', value: '', disabled: false, innerHTML: '',
      events: {}, children: [], className: '',
      addEventListener(name, callback) { this.events[name] = callback; },
      append(...items) { this.children.push(...items); },
      after() {}, focus() {}, scrollIntoView() {}, querySelectorAll() { return []; },
      querySelector() { return null; },
    });
    return elements.get(id);
  }
  return {
    elements, getElementById: element,
    querySelector(selector) { return element(selector.slice(1)); },
    createElement() { return element(`created-${elements.size}`); },
    addEventListener() {},
  };
}

async function run() {
  const document = documentStub();
  let wireResponse, wireCalls = 0;
  const create = new AsyncFunction('document', 'fetch', `${source.slice(0, startup)}
    let rendered = '', calls = [], dashboards = 0;
    const wireApi = api;
    setScreen = html => { rendered = html; message(); };
    work = async (_label, action) => action();
    dashboard = async () => { dashboards++; };
    scheduleGrantCheck = () => {};
    api = async action => { calls.push(action); return {admitted:true,state:'queued'}; };
    return {
      setup(value) { session = value; grant = null; calls = []; dashboards = 0; },
      inviteAccess, renderDashboard, review, wireApi,
      grant(value) { grant = value; },
      state() { return {rendered,calls,dashboards,pending:session.pending}; },
    };
  `);
  const ui = await create(document, async () => { wireCalls++; return wireResponse; });
  const invited = { invite_required:true, test_faucet_configured:true,
    private_send_transport:'native-inline-v1', operator_sponsor_available:false,
    user_paid_sends:true, recipient_withdrawals:true };

  ui.setup(invited);
  ui.inviteAccess();
  assert.match(ui.state().rendered, />Join testnet<\/button>/);
  assert.doesNotMatch(ui.state().rendered, /includes private test coins|Join testnet \+ get test coins/);
  assert.match(ui.state().rendered, /Funding|funding depends on the operator/);
  assert.match(ui.state().rendered, /can link your submissions to this membership/);
  await document.elements.get('check-access').events.click();
  assert.deepEqual(ui.state().calls, ['access-status'], 'Checking membership must not request funding');
  assert.equal(ui.state().dashboards, 1);

  ui.setup(invited);
  ui.inviteAccess();
  document.getElementById('invitation').value = 'test-code';
  await document.elements.get('invite-form').events.submit({preventDefault(){}});
  await new Promise(setImmediate);
  assert.deepEqual(ui.state().calls, ['join'], 'Join must not repeat a coin claim');

  for (const state of ['queued', 'funding', 'ready', 'needs_attention']) {
    ui.setup(invited); ui.grant({state}); ui.renderDashboard();
    assert.match(ui.state().rendered, /Check test coin grant/);
    const text = document.elements.get('grant-status').textContent;
    if (state === 'queued') {
      assert.match(text, /queued.*Funding depends on the operator/);
      assert.doesNotMatch(text, /are being finalized|started your original grant/);
    } else if (state === 'funding') assert.match(text, /operator started.*not ready yet/);
    else if (state === 'ready') assert.match(text, /grant finalized/);
    else assert.match(text, /needs operator recovery/);
    assert.equal(document.elements.get('fund').textContent, 'Check test coin grant');
  }

  ui.setup({...invited, invite_required:false}); ui.renderDashboard();
  assert.match(ui.state().rendered, /Request test coins/);
  await document.elements.get('fund').events.click();
  assert.deepEqual(ui.state().calls, ['test-coins'], 'Funding is an explicit action');
  ui.setup({...invited, test_faucet_configured:false}); ui.renderDashboard();
  assert.doesNotMatch(ui.state().rendered, /Check test coin grant|Request test coins/);
  assert.match(ui.state().rendered, /Test funding unavailable/);
  assert.equal(document.elements.get('fund').disabled, true, 'No configured endpoint or sponsor means no funding action');
  ui.setup(invited); ui.review('npriv1recipient', 1, 'send', {fee_mode:'shielded',max_shielded_fee:3});
  assert.match(document.elements.get('review-fees').textContent, /no public gas balance/);
  assert.match(document.elements.get('review-fees').textContent, /gateway can link this request/);
  ui.review('public-destination', 1, 'withdraw', {fee_mode:'user',max_fee_debit:3});
  assert.match(document.elements.get('review-fees').textContent, /amount and destination become public/);

  const connectionError = 'error sending request for url (https://127.0.0.1:47444/status)';
  const jsonFailure = error => ({ok:false,headers:{get:()=> 'application/json'},json:async()=>({error})});
  wireResponse = jsonFailure(connectionError);
  await assert.rejects(ui.wireApi('access-status'), error => {
    assert.match(error.message, /test network is unavailable/);
    assert.doesNotMatch(error.message, /https:|47444|sending request/);
    return true;
  });
  wireResponse = jsonFailure('password is incorrect or encrypted seed was modified');
  await assert.rejects(ui.wireApi('unlock'), /password is incorrect or encrypted seed was modified/);
  const frame = new TextEncoder().encode(JSON.stringify({error:connectionError,status:{pending:true}})+'\n');
  let consumed = false;
  wireResponse = {ok:true,headers:{get:()=> 'application/x-ndjson'},body:{getReader:()=>({
    read:async()=> consumed ? {done:true} : (consumed=true,{done:false,value:frame}),
  })}};
  await assert.rejects(ui.wireApi('send'), error => {
    assert.match(error.message, /Check the saved payment status before sending again/);
    assert.doesNotMatch(error.message, /https:|47444|sending request/);
    return true;
  });
  assert.equal(ui.state().pending, true, 'A terminal connection error must preserve the saved pending state');
  assert.equal(wireCalls, 3, 'Transport errors must not cause an automatic request retry');
  console.log('wallet UI capability and privacy contract checks passed');
}

run().catch(error => { console.error(error); process.exitCode = 1; });
