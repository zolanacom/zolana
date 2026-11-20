// The actual product shell with an inert DOM and worker: what a wallet without a
// verified balance is told during its first check, and what a lock clears.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const original = await readFile(new URL("./app.js", import.meta.url), "utf8");
const source = original
  .replace(/^import \{ timingLine \} from "\.\/timing\.js";\n/m, "const timingLine = () => null;\n")
  .replaceAll("import.meta.url", '"https://fixture.invalid/app.js"')
  .replace(/render\(\); void start\(\);\s*$/, "");
assert.notEqual(source, original);
const settle = async () => { for (let i = 0; i < 16; i++) await Promise.resolve(); };

function fixture(wallet = {}) {
  let now = 0, timerId = 0, requestId = 0;
  const timers = new Map(), nodes = new Map(), sent = [];
  class Target {
    constructor() { this.dataset = {}; this.hidden = false; this.open = false; this.value = ""; this.textContent = ""; }
    addEventListener() {}
    querySelector() { return new Target(); }
    setAttribute() {} removeAttribute() {} replaceChildren() {} close() {}
  }
  const element = id => { if (!nodes.has(id)) nodes.set(id, new Target()); return nodes.get(id); };
  const document = Object.assign(new Target(), { hidden: false, getElementById: element,
    querySelector: () => new Target(), querySelectorAll: () => [],
    createTextNode: text => ({ textContent: text }), createElement: () => new Target() });
  class Worker { postMessage(value) { sent.push(value); } terminate() {} }
  const context = vm.createContext({ TextEncoder, Uint8Array, BigInt, URL, URLSearchParams, Worker, document,
    window: new Target(), location: { hash: "#wallet" }, performance: { now: () => now },
    crypto: { randomUUID: () => "request-" + (++requestId) },
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, at: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); } });
  vm.runInContext(`${source}
    globalThis.appTest = {
      open(value) { wallet = value; client = new WalletWorker(() => {}); render(); resetIdle(); return client; },
      unlock(value) { wallet = value; render(); resetIdle(); },
      inspect: () => ({ locked: wallet.locked, mark: verificationMark, sample: verificationSample }),
      lockWallet,
    };`, context);
  const state = { locked: false, saved: true, label: "Inert test wallet", environment: "testnet",
    authoritativeSync: false, verified: null, admission: { admitted: true }, ...wallet };
  const client = context.appTest.open(state);
  return {
    app: context.appTest, element, sent, state,
    call(action) { client.call(action).catch(() => {}); return sent.at(-1).id; },
    progress(id, slot, target, stage = "verifying-history") { client.worker.onmessage({ data: { event: "progress", id, stage, slot, target } }); },
    reply(id, result) { client.worker.onmessage({ data: { id, ok: true, result } }); },
    async advance(milliseconds) {
      const end = now + milliseconds;
      for (;;) {
        const next = [...timers.entries()].filter(([, value]) => value.at <= end).sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
        if (!next) break;
        now = next[1].at; timers.delete(next[0]); next[1].callback(); await settle();
      }
      now = end; await settle();
    },
  };
}

test("A wallet without a verified balance is told what its first check needs", () => {
  const f = fixture(), detail = f.element("sync-detail").textContent;
  assert.match(detail, /^Sending stays off until history has been verified and saved\. /);
  assert.match(detail, /every block/); assert.match(detail, /Keep this tab open and in front/);
  assert.match(detail, /starts again/); assert.match(detail, /does not lock for inactivity while this check keeps making new progress/);
  const verified = fixture({ authoritativeSync: true, verified: { balance: "20000000", slot: 10 } });
  assert.doesNotMatch(verified.element("sync-detail").textContent, /Keep this tab open/);
});

test("First verification shows this device's measured estimate and the instruction", async () => {
  const f = fixture(), id = f.call("automatic_sync"), line = () => f.element("sync-progress").textContent;
  f.progress(id, 1000, 181000);
  assert.equal(line(), "Verifying payment history on this device… Block 1,000 of 181,000. Keep this tab open and in front until it finishes.");
  await f.advance(20000); f.progress(id, 5000, 181000);
  // 4,000 blocks in 20 seconds: 176,000 blocks remain, 880 seconds, shown as 15 minutes.
  assert.equal(line(), "Verifying payment history on this device… Block 5,000 of 181,000. About 15 minutes left on this device. Keep this tab open and in front until it finishes.");
  await f.advance(40000); f.progress(id, 177000, 181000);
  assert.equal(line(), "Verifying payment history on this device… Block 177,000 of 181,000.");
});

test("A verified wallet's later checks show no first-check estimate or instruction", () => {
  const f = fixture({ authoritativeSync: true, verified: { balance: "20000000", slot: 10 } }), id = f.call("automatic_sync");
  f.progress(id, 1000, 181000);
  assert.equal(f.element("sync-progress").textContent, "Verifying payment history on this device… Block 1,000 of 181,000.");
});

test("A lock clears the first-verification mark and estimate before the next unlock", async () => {
  const f = fixture(), id = f.call("automatic_sync");
  f.progress(id, 1000, 181000); await f.advance(20000); f.progress(id, 5000, 181000);
  assert.equal(f.app.inspect().mark, 5000); assert.equal(f.app.inspect().sample.slot, 1000);
  const locking = f.app.lockWallet(); f.reply(id, f.state); await settle();
  f.reply(f.sent.at(-1).id, { ...f.state, locked: true }); await locking;
  assert.equal(f.app.inspect().locked, true); assert.equal(f.app.inspect().mark, -1); assert.equal(f.app.inspect().sample, null);
  // The next session's check starts again from its first block and is activity again.
  f.app.unlock(f.state); const next = f.call("automatic_sync");
  for (let step = 1; step <= 7; step++) { await f.advance(50000); f.progress(next, step * 100, 181000); }
  assert.equal(f.app.inspect().locked, false); assert.equal(f.app.inspect().mark, 700);
  assert.doesNotMatch(f.element("sync-progress").textContent, /NaN|Infinity/);
});
