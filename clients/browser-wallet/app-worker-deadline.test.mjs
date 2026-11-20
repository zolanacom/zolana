// Actual production worker-call and queue behavior with a virtual clock and inert worker.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const current = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const settle = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

function fixture(source = current) {
  let now = 0, timerId = 0, requestId = 0;
  const timers = new Map(), sent = [], outcomes = [];
  const constants = source.slice(source.indexOf('const IDLE_MS'), source.indexOf('/* Automatic receive controller'));
  const workerClass = source.slice(source.indexOf('class WalletWorker {'), source.indexOf('\nfunction message('));
  const idle = source.slice(source.indexOf('function resetIdle()'), source.indexOf('\nfunction readPassword('));
  class Worker {
    terminated = false;
    postMessage(value) { sent.push(value); }
    terminate() { this.terminated = true; }
  }
  const context = vm.createContext({
    Worker, URL, performance: { now: () => now }, document: { hidden: false },
    crypto: { randomUUID: () => 'request-' + (++requestId) },
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, at: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(`
    let wallet = { locked: false }, fatal = null, idleTimer, epoch = 0, lockCount = 0, client;
    const lockView = () => { wallet = { locked: true }; lockCount++; clearTimeout(idleTimer); };
    const render = () => {}, message = () => {}, showProgress = () => {}, showTiming = () => {};
    ${constants}
    ${workerClass.replaceAll('import.meta.url', '"https://fixture.invalid/app.js"')}
    ${idle}
    client = new WalletWorker(() => {});
    globalThis.app = { client, resetIdle, lockWallet,
      inspect: () => ({ locked: wallet.locked, fatal, lockCount, idleTimer, jobs: client.jobs.size }),
      hide: () => { document.hidden = true; },
      setWallet: value => { wallet = value; },
      replaceClient: value => { client = value; },
    };
  `, context);
  function call(action) {
    const result = { action, settled: false };
    outcomes.push(result);
    context.app.client.call(action).then(value => { result.settled = true; result.value = value; },
      error => { result.settled = true; result.error = error.message; });
    return { id: sent.at(-1).id, result };
  }
  function progress(id, slot, extra = {}) {
    context.app.client.worker.onmessage({ data: { event: 'progress', id, stage: 'verifying-history', slot, target: 10000, ...extra } });
  }
  function reply(id, result = {}) { context.app.client.worker.onmessage({ data: { id, ok: true, result } }); }
  async function advance(milliseconds) {
    const end = now + milliseconds;
    for (;;) {
      const next = [...timers.entries()].filter(([, value]) => value.at <= end)
        .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
      if (!next) break;
      now = next[1].at; timers.delete(next[0]); next[1].callback(); await settle();
    }
    now = end; await settle();
  }
  return { app: context.app, sent, outcomes, call, progress, reply, advance,
    now: () => now, timers, terminated: () => context.app.client.worker.terminated };
}

test('Matching advancing progress keeps cold sync alive beyond sixty seconds', async () => {
  const f = fixture(), sync = f.call('sync');
  await f.advance(50000); f.progress(sync.id, 100);
  await f.advance(50000); f.progress(sync.id, 200);
  await f.advance(20000);
  assert.equal(f.terminated(), false);
  f.reply(sync.id, { verified: true }); await settle();
  assert.equal(sync.result.value.verified, true);
  assert.equal(f.app.inspect().jobs, 0);
});

test('A sync with no progress keeps the original sixty-second failure bound', async () => {
  const f = fixture(), sync = f.call('sync');
  await f.advance(60000);
  assert.equal(f.terminated(), true);
  assert.ok(sync.result.error);
});

test('Duplicate progress does not refresh the idle deadline', async () => {
  const f = fixture(), sync = f.call('sync');
  await f.advance(40000); f.progress(sync.id, 100);
  await f.advance(50000); f.progress(sync.id, 100);
  await f.advance(10000);
  assert.equal(f.terminated(), true);
});

test('Foreign, unknown and malformed progress cannot extend the active request', async () => {
  const f = fixture(), sync = f.call('sync');
  await f.advance(50000);
  f.progress('foreign', 100);
  f.progress(sync.id, 100, { stage: 'unknown' });
  f.progress(sync.id, -1);
  f.progress(sync.id, 100, { target: 50 });
  await f.advance(10000);
  assert.equal(f.terminated(), true);
});

test('Progress cannot extend ordinary operations beyond sixty seconds', async () => {
  const f = fixture(), status = f.call('status');
  await f.advance(50000); f.progress(status.id, 100);
  await f.advance(10000);
  assert.equal(f.terminated(), true);
});

test('Continued progress cannot extend the fifteen-minute absolute deadline of a payment recovery', async () => {
  const f = fixture(), sync = f.call('recover_pending');
  for (let step = 1; step <= 17; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  await f.advance(49999); f.progress(sync.id, 2000);
  await f.advance(1);
  assert.equal(f.terminated(), true);
  assert.ok(sync.result.error);
});

test('A queued short job waits behind healthy sync then gets its own execution bound', async () => {
  const f = fixture(), sync = f.call('sync'), status = f.call('status');
  for (let step = 1; step <= 3; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  assert.equal(f.terminated(), false); assert.equal(status.result.settled, false);
  f.reply(sync.id); await settle();
  await f.advance(59000);
  assert.equal(f.terminated(), false);
  f.reply(status.id, { saved: true }); await settle();
  assert.equal(status.result.value.saved, true);
});

test('A stale completed request cannot refresh the next active operation', async () => {
  const f = fixture(), first = f.call('sync'), second = f.call('sync');
  f.reply(first.id); await settle();
  await f.advance(50000); f.progress(first.id, 100);
  await f.advance(10000);
  assert.equal(f.terminated(), true); assert.ok(second.result.error);
});

test('Close rejects active and queued jobs and clears every job timer', async () => {
  const f = fixture(), sync = f.call('sync'), status = f.call('status');
  f.app.client.close(); await settle();
  assert.equal(f.terminated(), true);
  assert.equal(f.timers.size, 0);
  assert.ok(sync.result.error); assert.ok(status.result.error);
});

test('Explicit foreground progress preserves a healthy sync beyond five-minute idle', async () => {
  const f = fixture(), sync = f.call('sync'); f.app.resetIdle();
  for (let step = 1; step <= 7; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  assert.equal(f.now(), 350000); assert.equal(f.app.inspect().locked, false);
  f.reply(sync.id); await settle();
  await f.advance(300000);
  assert.equal(f.app.inspect().locked, true);
});

test('History verification that keeps adding blocks runs past fifteen minutes', async () => {
  for (const action of ['sync', 'automatic_sync']) {
    const f = fixture(), sync = f.call(action);
    for (let step = 1; step <= 60; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
    assert.equal(f.now(), 3000000); assert.equal(f.terminated(), false);
    f.reply(sync.id, { verified: true }); await settle();
    assert.equal(sync.result.value.verified, true);
  }
});

test('History verification past fifteen minutes still stops sixty seconds after its last new block', async () => {
  const f = fixture(), sync = f.call('automatic_sync');
  for (let step = 1; step <= 20; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  await f.advance(50000); f.progress(sync.id, 2000);
  await f.advance(9999); assert.equal(f.terminated(), false);
  await f.advance(1);
  assert.equal(f.terminated(), true); assert.ok(sync.result.error);
});

test('Continued block progress cannot extend history verification beyond its four-hour ceiling', async () => {
  const f = fixture(), sync = f.call('sync');
  for (let step = 1; step <= 287; step++) { await f.advance(50000); f.progress(sync.id, step); }
  await f.advance(49999); f.progress(sync.id, 9000);
  assert.equal(f.now(), 14399999); assert.equal(f.terminated(), false);
  await f.advance(1);
  assert.equal(f.terminated(), true); assert.ok(sync.result.error);
});

test('Background automatic sync of a verified wallet preserves the five-minute idle lock', async () => {
  const f = fixture(), sync = f.call('automatic_sync'); f.app.resetIdle();
  f.app.setWallet({ locked: false, authoritativeSync: true });
  for (let step = 1; step <= 6; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  assert.equal(f.app.inspect().locked, true);
  assert.equal(f.sent.at(-1).action, 'lock');
});

test('First verification by automatic sync holds the idle lock only while it reports new blocks', async () => {
  const f = fixture(), sync = f.call('automatic_sync'); f.app.resetIdle();
  f.app.setWallet({ locked: false, authoritativeSync: false });
  for (let step = 1; step <= 14; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  assert.equal(f.now(), 700000); assert.equal(f.app.inspect().locked, false);
  // Stage changes without a block, and repeated blocks, are not activity.
  await f.advance(50000); f.progress(sync.id, undefined, { slot: undefined, target: undefined, stage: 'saving-verified-checkpoint' });
  f.reply(sync.id); await settle();
  await f.advance(249999); assert.equal(f.app.inspect().locked, false);
  await f.advance(1);
  assert.equal(f.app.inspect().locked, true);
  assert.equal(f.sent.at(-1).action, 'lock');
});

test('A restarted first verification is not activity until it passes the highest block already reported', async () => {
  const f = fixture(), first = f.call('automatic_sync'); f.app.resetIdle();
  f.app.setWallet({ locked: false, authoritativeSync: false });
  await f.advance(50000); f.progress(first.id, 5000);
  f.reply(first.id); await settle();
  const second = f.call('automatic_sync');
  for (let step = 1; step <= 5; step++) { await f.advance(50000); f.progress(second.id, step * 900); }
  assert.equal(f.now(), 300000); assert.equal(f.app.inspect().locked, false);
  await f.advance(49999); assert.equal(f.app.inspect().locked, false);
  await f.advance(1);
  assert.equal(f.app.inspect().locked, true);
  const third = fixture(), again = third.call('automatic_sync'); third.app.resetIdle();
  third.app.setWallet({ locked: false, authoritativeSync: false });
  await third.advance(50000); third.progress(again.id, 5000);
  third.reply(again.id); await settle();
  const later = third.call('automatic_sync');
  for (let step = 1; step <= 7; step++) { await third.advance(50000); third.progress(later.id, step * 1100); }
  assert.equal(third.now(), 400000); assert.equal(third.app.inspect().locked, false);
});

test('Hidden first verification cannot refresh the idle clock', async () => {
  const f = fixture(), sync = f.call('automatic_sync'); f.app.resetIdle();
  f.app.setWallet({ locked: false, authoritativeSync: false }); f.app.hide();
  for (let step = 1; step <= 6; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  assert.equal(f.app.inspect().locked, true);
});

test('Healthy automatic sync preserves an explicit foreground request waiting in its queue', async () => {
  const f = fixture(), automatic = f.call('automatic_sync'); f.app.resetIdle();
  await f.advance(50000); f.app.resetIdle();
  const explicit = f.call('sync');
  for (let step = 1; step <= 6; step++) { f.progress(automatic.id, step * 100); await f.advance(50000); }
  assert.equal(f.now(), 350000); assert.equal(f.app.inspect().locked, false);
  assert.equal(f.terminated(), false); assert.equal(explicit.result.settled, false);
  f.reply(automatic.id); await settle();
  await f.advance(50000); f.progress(explicit.id, 1000);
  assert.equal(f.app.inspect().locked, false);
  f.reply(explicit.id); await settle();
  assert.equal(explicit.result.settled, true);
});

test('Hidden foreground progress cannot refresh the idle clock', async () => {
  const f = fixture(), sync = f.call('sync'); f.app.resetIdle(); f.app.hide();
  for (let step = 1; step <= 6; step++) { await f.advance(50000); f.progress(sync.id, step * 100); }
  assert.equal(f.app.inspect().locked, true);
});

test('Manual lock hides the current wallet immediately during a healthy long sync', async () => {
  const f = fixture(), sync = f.call('sync');
  await f.advance(50000); f.progress(sync.id, 100);
  const locking = f.app.lockWallet();
  assert.equal(f.app.inspect().locked, true);
  assert.equal(f.sent.at(-1).action, 'lock');
  f.reply(sync.id); await settle();
  f.reply(f.sent.at(-1).id, { locked: true }); await locking;
  assert.equal(f.app.inspect().locked, true);
});

test('Manual lock terminates the worker when the client queue is full', async () => {
  const f = fixture(), jobs = [f.call('sync'), f.call('status'), f.call('backup'), f.call('status')];
  await f.app.lockWallet(); await settle();
  assert.equal(f.app.inspect().locked, true);
  assert.equal(f.terminated(), true);
  assert.equal(f.app.inspect().jobs, 0);
  assert.ok(jobs.every(job => job.result.settled && job.result.error));
  assert.equal(f.timers.size, 0);
});

test('Hidden-wallet lock failure terminates the worker and rejects its pending jobs', async () => {
  const f = fixture(), sync = f.call('sync'); f.app.hide();
  const postMessage = f.app.client.worker.postMessage;
  f.app.client.worker.postMessage = value => {
    if (value.action === 'lock') throw new Error('fixture lock transport failed');
    postMessage(value);
  };
  await f.app.lockWallet(); await settle();
  assert.equal(f.app.inspect().locked, true);
  assert.equal(f.terminated(), true);
  assert.ok(sync.result.error);
});

test('A late failed lock closes only the client captured by that lock', async () => {
  const f = fixture();
  let rejectLock, replacementClosed = false;
  f.app.client.call = () => new Promise((_resolve, reject) => { rejectLock = reject; });
  const locking = f.app.lockWallet();
  f.app.replaceClient({ jobs: new Map(), close() { replacementClosed = true; } });
  rejectLock(new Error('fixture late lock failure')); await locking;
  assert.equal(f.terminated(), true);
  assert.equal(replacementClosed, false);
});

test('Serialized worker progress is bound to the active request and cleared after failure', async () => {
  const workerSource = await readFile(new URL('./product-worker.js', import.meta.url), 'utf8');
  const storageImport = 'import { createWalletStore, openWalletStore, walletDatabaseName, WalletStorageError } from "./storage.js";';
  assert.equal(workerSource.split(storageImport).length, 2);
  const messages = [];
  let resume;
  const context = vm.createContext({ TextEncoder, TextDecoder, Uint8Array, AbortController, setTimeout, clearTimeout,
    WalletStorageError: class extends Error {}, self: { postMessage: value => messages.push(value) },
    gate: new Promise(resolve => { resume = resolve; }),
  });
  vm.runInContext(workerSource.replace(storageImport, '') + `
    dispatch = async message => { progress('verifying-history', { slot: 1, target: 2 });
      if (message.id === 'first') await gate;
      if (message.id === 'failed') throw new Error('fixture');
      return {}; };
    globalThis.inspectRequest = () => session.activeRequestId;
  `, context);
  const first = context.self.onmessage({ data: { id: 'first', action: 'sync' } });
  const second = context.self.onmessage({ data: { id: 'second', action: 'status' } });
  await settle(); assert.equal(context.inspectRequest(), 'first');
  resume(); await first; await second;
  await context.self.onmessage({ data: { id: 'failed', action: 'sync' } });
  assert.deepEqual(messages.filter(value => value.event === 'progress').map(value => value.id), ['first', 'second', 'failed']);
  assert.equal(context.inspectRequest(), undefined);
});
