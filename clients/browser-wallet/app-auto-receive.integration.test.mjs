// Execute the actual product shell and event handlers with inert DOM/worker
// boundaries. No browser, WASM, storage, credentials, network or coins are used.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const original = await readFile(new URL("./app.js", import.meta.url), "utf8");
const source = original
  .replace(/^import \{ timingLine \} from "\.\/timing\.js";\n/m, "const timingLine = () => null;\n")
  .replaceAll("import.meta.url", '"https://fixture.invalid/app.js"')
  .replace(/render\(\); void start\(\);\s*$/, "");
assert.notEqual(source, original);
assert(!source.includes("import.meta"));
assert(!/render\(\); void start\(\);\s*$/.test(source));

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
async function microtasks() { for (let i = 0; i < 24; i++) await Promise.resolve(); }

function clock() {
  let now = 0, next = 1;
  const timers = new Map();
  return {
    now: () => now,
    set(fn, delay = 0) { const id = next++; timers.set(id, { fn, at: now + delay }); return id; },
    clear(id) { timers.delete(id); },
    deadline(id) { return timers.get(id)?.at; },
    async advance(ms) {
      const target = now + ms;
      for (let turns = 0; turns < 2000; turns++) {
        const ready = [...timers].filter(([, value]) => value.at <= target)
          .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
        if (!ready) { now = target; await microtasks(); return; }
        now = ready[1].at; timers.delete(ready[0]); ready[1].fn(); await microtasks();
      }
      throw new Error("Fixture exceeded its finite timer budget");
    },
  };
}

function fakeDom() {
  const nodes = new Map(), domTasks = [];
  class Target {
    constructor(id = "") {
      this.id = id; this.listeners = new Map(); this.dataset = {}; this.attributes = new Map();
      this.hidden = false; this.open = false; this.value = ""; this.textContent = ""; this.disabled = false;
    }
    addEventListener(type, fn) { const list = this.listeners.get(type) || []; list.push(fn); this.listeners.set(type, list); }
    dispatch(type, extra = {}) {
      const event = { type, target: this, preventDefault() {}, ...extra };
      return Promise.all((this.listeners.get(type) || []).map(fn => fn(event)));
    }
    querySelector(selector) { return element(`${this.id}:${selector}`); }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    removeAttribute(name) { this.attributes.delete(name); }
    replaceChildren(...children) { this.children = children; }
    append() {}
    remove() {}
    focus() {}
    click() { return this.dispatch("click"); }
    showModal() { this.open = true; }
    close() {
      if (!this.open) return;
      this.open = false;
      // HTML dialog close is an event-loop task, not a synchronous callback.
      domTasks.push(() => this.dispatch("close"));
    }
  }
  function element(id) { if (!nodes.has(id)) nodes.set(id, new Target(id)); return nodes.get(id); }
  const document = new Target("document"), window = new Target("window");
  Object.assign(document, {
    hidden: false, body: new Target("body"), getElementById: element,
    querySelector: selector => element(selector), querySelectorAll: () => [],
    createTextNode: text => ({ textContent: text }), createElement: tag => new Target(tag),
  });
  return {
    document, window, element,
    async flushClose() { while (domTasks.length) { await domTasks.shift()(); await microtasks(); } },
  };
}

function walletState(changes = {}) {
  return { locked: false, saved: true, label: "Inert test wallet", environment: "testnet", paymentAvailable: true,
    authoritativeSync: true, verified: { balance: "20000000", slot: 10 }, admission: { admitted: true },
    identity: { private_address: "npriv1-inert-recipient" }, ...changes };
}

function fixture(options = {}) {
  const time = clock(), dom = fakeDom(), calls = [], issued = [];
  let workerState = walletState(options.wallet), workerReview, tail = Promise.resolve();
  const handlers = options.handlers || {};
  const client = {
    closed: false,
    call(action, parameters = {}) {
      calls.push({ action, parameters: structuredClone(parameters), at: time.now() });
      const result = tail.then(async () => {
        issued.push(action);
        if (handlers[action]) return handlers[action](parameters, { get state() { return workerState; }, set state(value) { workerState = value; } });
        if (action === "cancel_review") { workerReview = undefined; return {}; }
        if (action === "quote_payment") {
          workerReview = { ...parameters, reviewId: "explicit-review", feeUnits: "3000000", maximumFeeUnits: "3000000", totalUnits: "4000000" };
          return workerReview;
        }
        if (action === "send") {
          assert.equal(parameters.reviewId, workerReview?.reviewId, "Only the explicitly reviewed payment may be sent");
          workerReview = undefined; return { ...workerState, paymentOutcome: "accepted" };
        }
        if (action === "payment_hint") return { changed: false, baselineKnown: true };
        if (action === "automatic_sync" || action === "sync") {
          workerState = { ...workerState, authoritativeSync: true }; return workerState;
        }
        if (action === "check_access" || action === "status") return workerState;
        if (action === "lock") { workerState = { ...workerState, locked: true, identity: undefined }; return workerState; }
        throw new Error(`Unexpected action in inert fixture: ${action}`);
      });
      tail = result.catch(() => {}); return result;
    },
    close() { this.closed = true; },
  };
  const context = vm.createContext({
    TextEncoder, Uint8Array, BigInt, URL, URLSearchParams, Blob, console,
    performance: { now: time.now }, setTimeout: (fn, delay) => time.set(fn, delay), clearTimeout: id => time.clear(id),
    document: dom.document, window: dom.window, location: { hash: "#wallet", reload() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    crypto: { randomUUID: () => "inert-id", subtle: {} },
    isSecureContext: true,
  });
  vm.runInContext(`${source}\n
    globalThis.appTest = {
      setup(value, worker) { wallet = value; client = worker; render(); },
      inspect() { return { wallet, busy, epoch, idleTimer, paymentReview, reviewCancellation }; },
      startAutomatic(options) { automaticReceive.resume(options); },
      pauseAutomatic() { automaticReceive.pause(); },
      resetIdle, lockWallet, showProgress,
    };`, context);
  context.appTest.setup(workerState, client);
  const app = context.appTest;
  return {
    ...dom, time, calls, issued, client, app,
    actions: () => calls.map(call => call.action),
    workerReview: () => workerReview,
    setReview: value => { workerReview = value; },
    setWorkerState: value => { workerState = value; },
    async settle() { await microtasks(); },
    async openSend() { await dom.element("send-button").click(); await microtasks(); },
    async requestQuote() {
      dom.element("send-recipient").value = "npriv1-inert-recipient";
      dom.element("send-amount").value = "0.001";
      // Do not await: this handler intentionally remains pending for race tests.
      const pending = dom.element("send-form").dispatch("submit"); await microtasks(); return { pending };
    },
  };
}

let cases = 0;
for (const [submissionLimit, message] of [["member", "This test wallet has reached its payment limit."], ["network", "Testnet payment capacity is full."]]) {
  const f = fixture({ handlers: { send: async () => walletState({
    pendingPayment: true, authoritativeSync: false, paymentOutcome: "unknown", submissionLimit,
  }) } });
  await f.openSend(); await f.requestQuote();
  await f.element("confirm-send").click(); await f.flushClose(); await f.settle();
  assert(f.element("message").textContent.startsWith(message));
  assert(f.element("message").textContent.includes("saved original payment"));
  assert.equal(f.app.inspect().wallet.pendingPayment, true);
  assert.equal(f.calls.filter(call => call.action === "send").length, 1);
  assert(!f.actions().includes("recover_pending"));
  cases++;
}
{
  const quote = deferred();
  const f = fixture({ handlers: { quote_payment: () => quote.promise } });
  await f.openSend(); const { pending } = await f.requestQuote();
  f.app.showProgress({ stage: "preparing-private-wallet" });
  assert.equal(f.element("send-progress").hidden, false);
  assert.equal(f.element("send-progress").textContent, "Preparing private proofs on this device…");
  assert.equal(f.app.inspect().busy, true);
  const reason = "This payment and its private fee exceed the currently spendable amount. Choose a smaller amount.";
  quote.reject(new Error(reason)); await pending; await f.settle();
  assert.equal(f.element("send-progress").hidden, true);
  assert.equal(f.element("send-error").hidden, false);
  assert.equal(f.element("send-error").textContent,
    `${reason} This review did not send a payment or charge a fee.`);
  assert.equal(f.element("send-form").hidden, false);
  assert.equal(f.element("send-review").hidden, true);
  assert.equal(f.app.inspect().busy, false);
  assert.equal(f.app.inspect().paymentReview, undefined);
  assert.deepEqual(f.actions(), ["cancel_review", "quote_payment"]);
  await f.element("confirm-send").click(); await f.settle();
  assert(!f.actions().includes("send")); cases++;
}
{
  const gate = deferred();
  const f = fixture({ handlers: { send: async parameters => {
    assert.equal(parameters.reviewId, f.workerReview()?.reviewId);
    await gate.promise; f.setReview(undefined); return walletState({ paymentOutcome: "accepted" });
  } } });
  await f.openSend(); await f.requestQuote();
  assert.equal(f.app.inspect().paymentReview.reviewId, "explicit-review");
  const before = f.calls.length;
  await f.element("confirm-send").click(); await f.flushClose(); await f.settle();
  assert.deepEqual(f.calls.slice(before).map(call => call.action), ["send"]);
  assert.equal(f.calls[before].parameters.reviewId, "explicit-review");
  assert.equal(f.workerReview().reviewId, "explicit-review");
  assert.equal(f.app.inspect().busy, true);
  gate.resolve(); await f.settle();
  assert.equal(f.workerReview(), undefined);
  assert.equal(f.app.inspect().paymentReview, undefined); cases++;
}
{
  const f = fixture(); await f.openSend(); await f.requestQuote();
  const before = f.calls.length;
  await f.element("close-send").click(); await f.flushClose();
  assert.deepEqual(f.calls.slice(before).map(call => call.action), ["cancel_review"]);
  assert.equal(f.workerReview(), undefined); assert.equal(f.app.inspect().paymentReview, undefined);
  assert(!f.actions().includes("send")); cases++;
}
{
  const gate = deferred();
  const f = fixture({ handlers: { quote_payment: async parameters => {
    await gate.promise;
    const value = { ...parameters, reviewId: "late-review", feeUnits: "3000000", maximumFeeUnits: "3000000", totalUnits: "4000000" };
    f.setReview(value); return value;
  } } });
  await f.openSend(); const { pending } = await f.requestQuote();
  assert(f.app.inspect().busy);
  await f.element("close-send").click(); await f.flushClose();
  assert.deepEqual(f.actions().slice(-2), ["quote_payment", "cancel_review"]);
  gate.resolve(); await pending; await f.settle();
  assert.equal(f.workerReview(), undefined); assert.equal(f.app.inspect().paymentReview, undefined);
  assert(!f.actions().includes("send")); cases++;
}
{
  // The first dialog-open cleanup can still be in flight when a user submits
  // and then cancels. It must finish before any new worker review is created.
  const initialCancel = deferred();
  const f = fixture({ handlers: { cancel_review: async () => {
    await initialCancel.promise; f.setReview(undefined); return {};
  } } });
  f.setReview({ reviewId: "earlier-dialog-review" });
  await f.openSend(); const { pending } = await f.requestQuote();
  assert.equal(f.app.inspect().busy, true);
  assert.deepEqual(f.actions(), ["cancel_review"]);
  await f.element("close-send").click(); await f.flushClose();
  initialCancel.resolve(); await pending; await f.settle();
  assert.deepEqual(f.actions(), ["cancel_review"]);
  assert.equal(f.workerReview(), undefined); assert.equal(f.app.inspect().paymentReview, undefined);
  assert.equal(f.app.inspect().busy, false); cases++;
}
{
  // Reopening is refused while quote1 is running. Once it finishes, a new
  // dialog may open, but quote2 must wait for quote1's queued cleanup.
  const firstQuote = deferred(), oldCleanup = deferred();
  let quotes = 0, cancellations = 0;
  const f = fixture({ handlers: {
    quote_payment: async parameters => {
      const number = ++quotes; if (number === 1) await firstQuote.promise;
      const value = { ...parameters, reviewId: `review-${number}`, feeUnits: "3000000", maximumFeeUnits: "3000000", totalUnits: "4000000" };
      f.setReview(value); return value;
    },
    cancel_review: async () => {
      if (++cancellations === 2) await oldCleanup.promise;
      f.setReview(undefined); return {};
    },
  } });
  await f.openSend(); const quote1 = await f.requestQuote();
  await f.element("close-send").click(); await f.flushClose();
  await f.openSend(); assert.equal(f.element("send-dialog").open, false);
  assert.deepEqual(f.actions(), ["cancel_review", "quote_payment", "cancel_review"]);
  firstQuote.resolve(); await quote1.pending; await f.settle();
  assert.equal(f.app.inspect().busy, false);
  assert.equal(f.workerReview().reviewId, "review-1");
  await f.openSend(); assert.equal(f.element("send-dialog").open, true);
  const quote2 = await f.requestQuote();
  assert.equal(quotes, 1);
  assert.deepEqual(f.actions(), ["cancel_review", "quote_payment", "cancel_review"]);
  oldCleanup.resolve(); await quote2.pending; await f.settle();
  assert.deepEqual(f.actions(), ["cancel_review", "quote_payment", "cancel_review", "quote_payment"]);
  assert.equal(f.workerReview().reviewId, "review-2");
  assert.equal(f.app.inspect().paymentReview.reviewId, "review-2");
  await f.element("close-send").click(); await f.flushClose();
  assert.equal(f.workerReview(), undefined);
  assert(!f.actions().includes("send")); cases++;
}
{
  let firstHint = true;
  const f = fixture({ handlers: { payment_hint: async () => ({ changed: firstHint ? (firstHint = false, true) : false, baselineKnown: true }) } });
  f.app.resetIdle(); const originalIdle = f.app.inspect().idleTimer;
  assert.equal(f.time.deadline(originalIdle), 300000);
  f.app.startAutomatic({ immediate: true }); await f.time.advance(6000);
  assert(f.actions().includes("automatic_sync") && f.actions().includes("payment_hint"));
  assert.equal(f.app.inspect().idleTimer, originalIdle);
  assert.equal(f.time.deadline(originalIdle), 300000);
  await f.time.advance(293999); assert.equal(f.app.inspect().wallet.locked, false);
  await f.time.advance(1); assert.equal(f.app.inspect().wallet.locked, true);
  assert.equal(f.calls.filter(call => call.action === "lock").length, 1);
  assert.equal(f.calls.find(call => call.action === "lock").at, 300000); cases++;
}
for (const action of ["payment_hint", "automatic_sync"]) for (const boundary of ["hide", "lock"]) {
  const gate = deferred();
  const f = fixture({ wallet: { authoritativeSync: action !== "automatic_sync" }, handlers: {
    [action]: async () => { await gate.promise; return action === "payment_hint" ? { changed: true, baselineKnown: true } : walletState({ verified: { balance: "999999999", slot: 99 } }); },
  } });
  f.app.startAutomatic({ immediate: true }); await f.time.advance(0);
  assert(f.actions().includes(action));
  if (boundary === "hide") { f.document.hidden = true; await f.document.dispatch("visibilitychange"); }
  else await f.element("lock-button").click();
  assert.equal(f.app.inspect().wallet.locked, true);
  gate.resolve(); await f.settle();
  assert.equal(f.app.inspect().wallet.locked, true);
  assert.equal(f.app.inspect().wallet.verified.balance, "20000000");
  assert(!f.actions().includes("send"));
  const count = f.calls.length; await f.time.advance(10000); assert.equal(f.calls.length, count); cases++;
}
for (const blocked of ["busy", "pending", "dialog", "review"]) {
  const gate = deferred();
  const f = fixture({ wallet: blocked === "pending" ? { pendingPayment: { packetId: "original" } } : {},
    handlers: blocked === "busy" ? { sync: async () => { await gate.promise; return walletState(); } } : {} });
  if (blocked === "busy") { await f.element("sync-button").click(); await f.settle(); assert(f.app.inspect().busy); }
  if (blocked === "dialog") f.element("send-dialog").showModal();
  if (blocked === "review") { await f.openSend(); await f.requestQuote(); }
  const before = f.calls.length;
  f.app.startAutomatic({ immediate: true }); await f.time.advance(2500);
  assert.equal(f.calls.length, before, `Background work must skip ${blocked}`);
  if (blocked === "busy") { gate.resolve(); await f.settle(); }
  cases++;
}
{
  const f = fixture({ wallet: { admission: null, authoritativeSync: false }, handlers: {
    check_access: async () => walletState({ admission: { admitted: false }, authoritativeSync: false }),
  } });
  f.app.startAutomatic({ immediate: true }); await f.time.advance(10000);
  assert.deepEqual(f.actions(), ["check_access"]);
  assert.equal(f.app.inspect().wallet.admission.admitted, false); cases++;
}
{
  const f = fixture({ wallet: { authoritativeSync: false } });
  f.app.startAutomatic({ immediate: true }); await f.time.advance(7000);
  assert.equal(f.actions()[0], "automatic_sync");
  assert.equal(f.app.inspect().wallet.authoritativeSync, true);
  assert(f.actions().every(action => ["automatic_sync", "payment_hint"].includes(action)));
  assert(!f.actions().some(action => /join|fund|send|quote|recover/.test(action))); cases++;
}
{
  const f = fixture({ wallet: { admission: null, authoritativeSync: false }, handlers: {
    check_access: async (_parameters, worker) => {
      worker.state = walletState({ authoritativeSync: false }); return worker.state;
    },
  } });
  f.app.startAutomatic({ immediate: true }); await f.time.advance(2000);
  assert.deepEqual(f.actions().slice(0, 2), ["check_access", "automatic_sync"]);
  assert.equal(f.app.inspect().wallet.authoritativeSync, true);
  assert(f.actions().every(action => ["check_access", "automatic_sync", "payment_hint"].includes(action))); cases++;
}

console.log(`PASS: ${cases} actual app integration cases preserve explicit send authorization, quote-error progress cleanup, Cancel races, five-minute idle locking, late-response isolation and read-only automatic receive boundaries.`);
