// Exercise the production message queue with disposable vault/store handles.
import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource, sendWorkerMessage } from "./product-worker-harness.mjs";

const source = await loadWorkerSource();

function deferred() {
  let resolve;
  const promise = new Promise(value => { resolve = value; });
  return { promise, resolve };
}

function fixture() {
  const events = [], responses = [], gate = deferred(), started = deferred();
  const context = createWorkerContext({
    TextEncoder, TextDecoder, Uint8Array, AbortController, setTimeout, clearTimeout, events, gate, started,
    WalletStorageError: class extends Error {},
    self: { postMessage: response => responses.push(response) },
  });
  vm.runInContext(`${source}
    configuration = { label: "fixture", environment: "testnet" };
    catalog = {}; record = { phase: "ready" }; readRecord = async () => record;
    function vault(name) {
      return { identity: () => "{}", encrypted_backup: () => new Uint8Array([1]),
        lock: () => events.push(name + ":lock"), free: () => events.push(name + ":free") };
    }
    function store(name) { return { close: () => events.push(name + ":close") }; }
    session.adopt(vault("original"), store("original"), session.generation);
    globalThis.originalCheckAccess = checkAccess;
    globalThis.originalUnlock = unlock;
    checkAccess = async () => {
      const generation = session.generation, value = session.requireVault();
      events.push("read:started"); started.resolve(); await gate.promise;
      session.assertCurrent(generation, value);
      return currentStatus();
    };
    unlock = async () => {
      events.push("unlock:started"); session.release();
      session.adopt(vault("new"), store("new"), session.generation);
      return currentStatus();
    };
    createOrRestore = async () => { events.push("setup:started"); return currentStatus(); };
    globalThis.state = () => ({ locked: !session.vault, queued: session.operations.size,
      pending: session.savedPending, generation: session.generation });
  `, context);
  const send = (id, action, password) => sendWorkerMessage(context, { id, action, password });
  return { context, events, responses, gate, started, send };
}

function response(fixture, id) {
  return fixture.responses.find(item => item.id === id);
}

async function catalogFixture(initialRecord = null) {
  const events = [], responses = [];
  const db = { objectStoreNames: ["wallets"], close: () => events.push("catalog:close") };
  const context = createWorkerContext({
    events, initialRecord, crypto: { subtle: {} },
    indexedDB: { open() {
      const request = { result: db };
      queueMicrotask(() => request.onsuccess());
      return request;
    } },
    walletDatabaseName: (walletId, networkId) => `zolana-browser-wallet-${networkId}-${walletId}`,
    WalletStorageError: class extends Error {},
    self: { isSecureContext: true, postMessage: value => responses.push(value) },
  });
  vm.runInContext(`${source}
    sha = async () => "a".repeat(64);
    loadNetworkPin = async () => ({ format: "zolana-browser-network-pin-v1", environment: "testnet",
      network: { network: Array(32).fill(7), genesis_hash: "1".repeat(32) } });
    readRecord = async () => initialRecord;
    core = async () => ({});
    globalThis.inspect = () => ({ catalog: !!catalog, locked: !session.vault,
      queued: session.operations.size, generation: session.generation, record });
  `, context);
  const send = (id, action, password) => sendWorkerMessage(context, { id, action, password });
  await sendWorkerMessage(context, { id: "initialize", action: "initialize", configuration: {
    format: "zolana-browser-wallet-config-v1", coin: "ZOL", environment: "testnet", label: "Fixture",
    network: { network: Array(32).fill(7), genesis_hash: "1".repeat(32) },
  } });
  assert.equal(responses[0].ok, true);
  return { context, db, events, responses, send };
}

for (const action of ["unlock", "create", "restore"]) {
  test(`lock cancels queued ${action} before it can open a vault`, async () => {
    const f = fixture(), password = new Uint8Array(12).fill(9);
    f.send("read", "check_access"); await f.started.promise;
    f.send("stale", action, password);
    const completion = f.send("lock", "lock");
    assert(password.every(byte => byte === 0));
    assert.equal(f.context.state().locked, true);
    f.gate.resolve(); await completion;
    assert.equal(response(f, "stale").code, "locked");
    assert.equal(response(f, "lock").result.locked, true);
    assert(!f.events.includes("unlock:started"));
    assert(!f.events.includes("setup:started"));
    assert.equal(f.context.state().queued, 0);
  });
}

test("a full queue cannot postpone lock or run older unlock requests", async () => {
  const f = fixture(), passwords = Array.from({ length: 3 }, () => new Uint8Array(12).fill(7));
  f.send("read", "check_access"); await f.started.promise;
  passwords.forEach((password, index) => f.send(`stale-${index}`, "unlock", password));
  const completion = f.send("lock", "lock");
  assert.equal(response(f, "lock").code, "busy");
  assert.equal(f.context.state().locked, true);
  assert(passwords.every(password => password.every(byte => byte === 0)));
  f.gate.resolve(); await completion;
  assert(!f.events.includes("unlock:started"));
  passwords.forEach((_, index) => assert.equal(response(f, `stale-${index}`).code, "locked"));
  assert.equal(f.events.filter(event => event === "original:free").length, 1);
  assert.equal(f.events.filter(event => event === "original:close").length, 1);
  await f.send("fresh", "unlock", new Uint8Array(12).fill(8));
  assert.equal(response(f, "fresh").result.locked, false);
});

test("lock aborts all active request handles before draining the queue", async () => {
  const f = fixture();
  vm.runInContext(`session.requests.add({ abort: () => events.push("request:abort") });`, f.context);
  f.send("read", "check_access"); await f.started.promise;
  const completion = f.send("lock", "lock");
  assert(f.events.includes("request:abort"));
  f.gate.resolve(); await completion;
  assert.equal(response(f, "read").code, "locked");
});

test("ordinary queued unlock keeps following operations in the same generation", async () => {
  const f = fixture();
  f.send("unlock", "unlock", new Uint8Array(12).fill(4));
  await f.send("backup", "backup");
  assert.equal(response(f, "unlock").ok, true);
  assert.equal(response(f, "backup").ok, true);
  assert.equal(f.context.state().generation, 0);
});

test("lock preserves an executing password until its own cleanup and rejects stale adoption", async () => {
  const f = fixture(), activePassword = new Uint8Array(12).fill(6), queuedPassword = new Uint8Array(12).fill(5);
  vm.runInContext(`unlock = async message => {
    const generation = session.generation;
    session.release(); started.resolve(); await gate.promise;
    if (!message.password.some(Boolean)) throw Error("executing password was cleared early");
    session.adopt(vault("late"), store("late"), generation);
    return currentStatus();
  };`, f.context);
  f.send("active", "unlock", activePassword); await f.started.promise;
  f.send("queued", "unlock", queuedPassword);
  const completion = f.send("lock", "lock");
  assert(activePassword.every(byte => byte === 6));
  assert(queuedPassword.every(byte => byte === 0));
  f.gate.resolve(); await completion;
  assert.equal(response(f, "active").code, "locked");
  assert(activePassword.every(byte => byte === 0));
  assert.equal(f.context.state().locked, true);
});

test("release clears volatile state and closes store even if a vault cleanup fails", () => {
  const f = fixture();
  vm.runInContext(`session.vault.lock = () => { events.push("lock:failed"); throw Error("fixture cleanup"); };
    session.admission = {}; session.verifiedStatus = {}; session.verifiedPoolHint = "hint";
    session.savedPending = true; session.reviewedQuote = {}; session.lastOutcome = {};`, f.context);
  assert.throws(() => vm.runInContext("session.release()", f.context), /fixture cleanup/);
  assert.equal(f.context.state().locked, true);
  assert.equal(f.context.state().pending, false);
  assert(f.events.includes("original:free"));
  assert(f.events.includes("original:close"));
  assert.equal(vm.runInContext("session.admission", f.context), undefined);
  assert.equal(vm.runInContext("session.verifiedStatus", f.context), undefined);
  assert.equal(vm.runInContext("session.reviewedQuote", f.context), undefined);
});

for (const method of ["lock", "free", "close"]) {
  test(`lock replies and keeps the queue usable when ${method} cleanup fails`, async () => {
    const f = fixture();
    vm.runInContext(`session.${method === "close" ? "store" : "vault"}.${method} = () => {
      events.push("${method}:failed"); throw Error("private fixture cleanup detail");
    };`, f.context);
    let completion;
    assert.doesNotThrow(() => { completion = f.send("lock", "lock"); });
    await completion;
    assert.equal(response(f, "lock").ok, false);
    assert.equal(response(f, "lock").code, "wallet_error");
    assert(!response(f, "lock").error.includes("private fixture"));
    assert.equal(f.context.state().locked, true);
    assert.equal(f.context.state().queued, 0);
    for (const name of ["lock", "free", "close"]) {
      assert(f.events.includes(name === method ? `${name}:failed` : `original:${name}`));
    }
    await f.send("status", "status");
    assert.equal(response(f, "status").result.locked, true);
    await f.send("fresh", "unlock", new Uint8Array(12).fill(8));
    assert.equal(response(f, "fresh").result.locked, false);
  });
}

test("failed unlock cleanup replies and drains subsequent messages", async () => {
  const f = fixture(), password = new Uint8Array(12).fill(8);
  vm.runInContext(`unlock = async () => {
    session.release();
    const nextVault = vault("new"), nextStore = store("new");
    for (const method of ["lock", "free"]) nextVault[method] = () => {
      events.push("new:" + method + ":failed"); throw Error("private vault cleanup detail");
    };
    nextStore.close = () => { events.push("new:close:failed"); throw Error("private store cleanup detail"); };
    session.adopt(nextVault, nextStore, session.generation);
    throw Error("private unlock detail");
  };`, f.context);
  f.send("unlock", "unlock", password);
  await f.send("status", "status");
  assert.equal(response(f, "unlock").ok, false);
  assert.equal(response(f, "unlock").code, "wallet_error");
  assert(!response(f, "unlock").error.includes("private"));
  assert(password.every(byte => byte === 0));
  assert.equal(response(f, "status").result.locked, true);
  assert.equal(f.context.state().queued, 0);
  for (const method of ["lock", "free", "close"]) assert(f.events.includes(`new:${method}:failed`));
  await f.send("backup", "backup");
  assert.equal(response(f, "backup").code, "locked");
});

test("lock attempts all aborts and wallet cleanup after an abort fails", async () => {
  const f = fixture();
  vm.runInContext(`session.requests.add({ abort() { events.push("abort:failed"); throw Error("private abort detail"); } });
    session.requests.add({ abort() { events.push("abort:next"); } });`, f.context);
  let completion;
  assert.doesNotThrow(() => { completion = f.send("lock", "lock"); });
  await completion;
  assert.equal(response(f, "lock").code, "wallet_error");
  for (const event of ["abort:failed", "abort:next", "original:lock", "original:free", "original:close"]) {
    assert(f.events.includes(event));
  }
  await f.send("status", "status");
  assert.equal(response(f, "status").result.locked, true);
});

test("a full queue still cancels old work and replies when lock cleanup fails", async () => {
  const f = fixture(), passwords = Array.from({ length: 3 }, () => new Uint8Array(12).fill(7));
  f.send("read", "check_access"); await f.started.promise;
  passwords.forEach((password, index) => f.send(`stale-${index}`, "unlock", password));
  vm.runInContext(`session.store.close = () => { events.push("close:failed"); throw Error("private cleanup detail"); };`, f.context);
  let completion;
  assert.doesNotThrow(() => { completion = f.send("lock", "lock"); });
  assert.equal(response(f, "lock").code, "wallet_error");
  assert.equal(f.context.state().locked, true);
  assert(passwords.every(password => password.every(byte => byte === 0)));
  f.gate.resolve(); await completion;
  passwords.forEach((_, index) => assert.equal(response(f, `stale-${index}`).code, "locked"));
  assert(!f.events.includes("unlock:started"));
  await f.send("status", "status");
  assert.equal(response(f, "status").result.locked, true);
});

for (const failure of ["free", "close", "both"]) {
  test(`unlock attempts every temporary-handle cleanup when ${failure} fails`, async () => {
    const f = fixture(), password = new Uint8Array(12).fill(8);
    f.context.cleanupFailure = failure;
    vm.runInContext(`
      unlock = originalUnlock;
      record.backupDigest = "a".repeat(64);
      sha = async () => record.backupDigest;
      openWalletStore = async () => ({
        snapshot: async () => ({ encryptedWallet: new Uint8Array([1]), pending: null }),
        close() {
          events.push("temporary:close");
          if (cleanupFailure !== "free") throw "zolana-wallet-error-v1:locked";
        },
      });
      core = async () => ({ BrowserVault: { restore: () => ({
        identity: () => "{}",
        free() {
          events.push("temporary:free");
          if (cleanupFailure !== "close") throw "zolana-wallet-error-v1:recovery";
        },
      }) } });
      binding = async () => { throw Error("private temporary binding failure"); };
    `, f.context);
    await f.send("unlock", "unlock", password);
    assert(f.events.includes("temporary:free"));
    assert(f.events.includes("temporary:close"));
    const failed = response(f, "unlock");
    assert.equal(failed.ok, false);
    assert.equal(failed.code, failure === "close" ? "locked" : "recovery");
    assert(!failed.error.includes("private"));
    assert(password.every(byte => byte === 0));
    await f.send("status", "status");
    assert.equal(response(f, "status").result.locked, true);
    assert.equal(f.context.state().queued, 0);
  });
}

for (const failure of ["release", "catalog", "both"]) {
  test(`catalog versionchange invalidates and closes after ${failure} cleanup failure`, async () => {
    const { context, db, responses, events } = await catalogFixture();
    context.cleanupFailure = failure;
    db.close = () => {
      events.push("catalog:close");
      if (failure !== "release") throw "zolana-wallet-error-v1:locked";
    };
    vm.runInContext(`session.adopt({
      lock() { events.push("vault:lock"); if (cleanupFailure !== "catalog") throw "zolana-wallet-error-v1:recovery"; },
      free() { events.push("vault:free"); },
    }, { close() { events.push("store:close"); } }, session.generation);`, context);
    assert.throws(() => db.onversionchange(), error =>
      error.code === (failure === "catalog" ? "locked" : "recovery") && !error.message.includes("zolana-wallet-error-v1:"));
    for (const event of ["vault:lock", "vault:free", "store:close", "catalog:close"]) assert(events.includes(event));
    assert.equal(context.inspect().catalog, false);
    assert.equal(context.inspect().locked, true);
    await sendWorkerMessage(context, { id: "status", action: "status" });
    assert.equal(responses.at(-1).code, "uninitialized");
    assert.equal(context.inspect().queued, 0);
  });
}

for (const queuedAction of ["unlock", "create", "restore"]) {
  test(`catalog versionchange cancels running unlock and queued ${queuedAction}`, async () => {
    const f = await catalogFixture({ phase: "ready", walletId: "b".repeat(64), backupDigest: "a".repeat(64) });
    const snapshot = deferred(), started = deferred();
    const activePassword = new Uint8Array(12).fill(6), queuedPassword = new Uint8Array(12).fill(5);
    Object.assign(f.context, { snapshot, started });
    vm.runInContext(`
      openWalletStore = async () => ({
        async snapshot() { started.resolve(); return snapshot.promise; },
        close() { events.push("temporary:close"); },
      });
      core = async () => ({ BrowserVault: { restore: () => ({
        identity: () => "{}", free() { events.push("temporary:free"); },
      }) } });
      binding = async () => ({ walletId: initialRecord.walletId });
      session.requests.add({ abort() { events.push("request:abort"); } });
    `, f.context);
    f.send("active", "unlock", activePassword); await started.promise;
    const completion = f.send("queued", queuedAction, queuedPassword);
    f.db.onversionchange();
    const queuedPasswordCleared = queuedPassword.every(byte => byte === 0);
    snapshot.resolve({ encryptedWallet: new Uint8Array([1]), pending: null });
    await completion;
    assert.equal(response(f, "active").ok, false);
    assert.equal(response(f, "active").code, "locked");
    assert.equal(response(f, "queued").code, "locked");
    assert.equal(queuedPasswordCleared, true);
    assert(activePassword.every(byte => byte === 0));
    assert(f.events.includes("request:abort"));
    assert(f.events.includes("temporary:free"));
    assert(f.events.includes("temporary:close"));
    assert.equal(f.context.inspect().generation, 1);
    assert.equal(f.context.inspect().catalog, false);
    assert.equal(f.context.inspect().locked, true);
    assert.equal(f.context.inspect().queued, 0);
  });
}

test("catalog versionchange preserves the original prepared setup during unlock", async () => {
  const prepared = {
    format: "zolana-browser-product-record-v1", networkId: "a".repeat(64), walletId: "b".repeat(64),
    dbName: `zolana-browser-wallet-${"a".repeat(64)}-${"b".repeat(64)}`,
    instanceId: "00000000-0000-0000-0000-000000000001", phase: "prepared",
    backupDigest: "a".repeat(64), encryptedWallet: new Uint8Array(48).fill(3),
  };
  const f = await catalogFixture(prepared), snapshot = deferred(), started = deferred();
  Object.assign(f.context, { snapshot, started });
  vm.runInContext(`
    openWalletStore = async () => ({
      async snapshot() { started.resolve(); return snapshot.promise; },
      close() { events.push("temporary:close"); },
    });
    core = async () => ({ BrowserVault: { restore: () => ({
      identity: () => "{}", free() { events.push("temporary:free"); },
    }) } });
    binding = async () => ({ walletId: initialRecord.walletId });
  `, f.context);
  const completion = f.send("active", "unlock", new Uint8Array(12).fill(4));
  await started.promise; f.db.onversionchange();
  snapshot.resolve({ revision: 0, encryptedCheckpoint: null, pending: null, encryptedWallet: prepared.encryptedWallet });
  await completion;
  assert.equal(response(f, "active").ok, false);
  assert.equal(f.context.inspect().record, prepared);
  assert.equal(prepared.phase, "prepared");
  assert.deepEqual([...prepared.encryptedWallet], Array(48).fill(3));
  assert.equal(f.context.inspect().generation, 1);
  assert.equal(f.context.inspect().locked, true);
  assert(f.events.includes("temporary:free"));
  assert(f.events.includes("temporary:close"));
});


test("session ownership preserves the public admission route and reply code", async () => {
  const f = fixture(), paths = [];
  f.context.fetch = async path => {
    paths.push(path);
    const bytes = new TextEncoder().encode(JSON.stringify({
      admitted: true, state: "active", access_until: null, fee_address: "fixture-fee-address",
    }));
    let read = false;
    return { ok: true, status: 200, headers: { get: () => "application/json" },
      body: { getReader: () => ({
        read: async () => read ? { done: true } : (read = true, { done: false, value: bytes }),
        releaseLock() {},
      }) } };
  };
  vm.runInContext(`transport = { faucet_audience: "https://fixture.invalid/" };
    session.vault.identity = () => JSON.stringify({ fee_address: "fixture-fee-address" });
    session.vault.admission_status = () => "{}";
    checkAccess = originalCheckAccess;`, f.context);
  await f.send("access", "check_access");
  assert.deepEqual(paths, ["/admission/status"]);
  assert.equal(response(f, "access").ok, true);
  assert.equal(response(f, "access").result.admission.admitted, true);
});
