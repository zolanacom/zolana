// Actual worker RPC/sync flow, with disposable HTTP and replay fixtures only.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
import { hintAccount } from "./product-worker-pool-fixture.mjs";
const source = await loadWorkerSource();
const network = { network: Array(32).fill(7), genesis_hash: "1".repeat(32) };
const unavailable = { error: "upstream_unavailable", outcome: "unknown", automatic_retry: false };
function fixture(failures = [], { badPage = false, lockOnFailure = false, onlyRpc = false } = {}) {
  const calls = [], applied = [], commits = []; let id = 0, tick = 0, attempt = 0;
  const context = createWorkerContext({ hintAccount, atob, btoa, TextEncoder, TextDecoder, Uint8Array, BigInt, TypeError, AbortController,
    network, applied, commits, badPage, WalletStorageError: class extends Error {},
    performance: { now: () => ++tick }, self: { postMessage() {} },
    setTimeout: () => 1, clearTimeout() {}, crypto: { randomUUID: () => `fixture-${++id}` },
    fetch: async (_path, options) => {
      const request = JSON.parse(options.body); calls.push(structuredClone(request));
      if (!onlyRpc && request.method === "getWalletSyncSnapshot") return reply(200, { jsonrpc: "2.0", id: request.id, result: {
        format: "zolana-wallet-sync-snapshot-v1", network, genesis: network.genesis_hash,
        pool: { context: { slot: 3 }, value: { ...hintAccount(), lamports: 1000 } }, target_header: { blockhash: "1".repeat(32), blockHeight: 3 },
        saved_header: null, canonical_tail: null, fallback: "tail-too-large" } });
      if (!onlyRpc && request.method !== "getWalletRetainedHistoryV3") throw new Error("unexpected operation");
      // The first page succeeds. Interruptions affect the next page only.
      if (onlyRpc || request.params[0] === 2) {
        const failure = failures[attempt++];
        if (failure) {
          if (lockOnFailure) vm.runInContext("session.generation++;", context);
          if (failure === "network") throw new TypeError("disposable fixture interruption");
          if (failure === "abort") throw Object.assign(new Error("disposable abort"), { name: "AbortError" });
          if (failure === "json") return reply(200, "{", "application/json", true);
          if (failure === "mime") return reply(200, {}, "text/html");
          if (failure === "identity") return reply(200, { jsonrpc: "2.0", id: "wrong", result: {} });
          if (failure === "rpc") return reply(200, { jsonrpc: "2.0", id: request.id, error: { code: -32000 } });
          if (failure === "unmarked") return reply(502, { ...unavailable, extra: true });
          return reply(failure, failure === 502 ? unavailable : { error: "refused" });
        }
      }
      return reply(200, { jsonrpc: "2.0", id: request.id, result: {
        next: request.params[0] === 0 ? 2 : 3, valid: !badPage || request.params[0] === 0, complete: request.params[0] === 2 } });
    } });
  vm.runInContext(`${source}
    configuration = { network, label: "fixture", environment: "testnet" };
    transport = { program: hintAccount().owner, pool: "1".repeat(32), rpc_audience: "https://fixture.invalid/" };
    session.store = { snapshot: async () => ({ revision: 7, encryptedCheckpoint: null, pending: null }),
      commitCheckpoint: async value => { commits.push(value); } };
    let slot = 0;
    session.vault = { identity: () => "{}", rpc_header: () => "fixture-access", checkpoint_info: () => '{"slot":0}',
      begin_sync: () => { slot = 0; return '{"slot":0,"target":3}'; },
      apply_compact_history_page: metadata => { const page = JSON.parse(metadata); applied.push(page.next); slot = page.next;
        return JSON.stringify({ slot, target: 3, token: { segments: 1, sha256: "a".repeat(64) } }); },
      apply_canonical_blocks: () => { throw new Error("unexpected canonical fallback"); },
      finish_sync: () => { if (slot !== 3) throw new Error("unfinished history"); return new Uint8Array([9]); },
      payment_status: () => JSON.stringify({ verified: true, balance: "20", max_payment: "20", slot }) };
    checkAccess = async () => { session.admission = { admitted: true, state: "active", accessUntil: 1234 }; };
    core = async () => ({});
    compactHistory = page => { if (!page.valid) fail("history", "fixture schema refusal");
      return { metadata: JSON.stringify(page), bytes: new Uint8Array() }; };
    globalThis.sync = syncWallet;
    globalThis.singleRpc = method => rpc(method, [2, 3, null, 32768], session.generation, session.vault);
  `, context);
  return { context, calls, applied, commits };
}
function reply(status, value, type = "application/json", raw = false) {
  const body = new TextEncoder().encode(raw ? value : JSON.stringify(value)); let read = false;
  return { status, ok: status >= 200 && status < 300, headers: { get: () => type },
    body: { getReader: () => ({ read: async () => read ? { done: true } : (read = true, { done: false, value: body }), releaseLock() {} }) } };
}
for (const interruption of [502, "network", "abort"]) {
  const f = fixture([interruption]); const result = await f.context.sync();
  assert.equal(result.verified.balance, "20"); assert.deepEqual(f.applied, [2, 3]); assert.equal(f.commits.length, 1);
  const pages = f.calls.filter(row => row.method === "getWalletRetainedHistoryV3");
  assert.equal(pages.length, 3); assert.equal(pages[0].params[0], 0);
  assert.deepEqual(pages[1].params, [2, 3, { segments: 1, sha256: "a".repeat(64) }, 32768]);
  assert.deepEqual(pages[2].params, pages[1].params); assert.notEqual(pages[2].id, pages[1].id);
}
for (const failure of [403, 429, 500, "unmarked", "json", "mime", "identity", "rpc"]) {
  const f = fixture([failure]); await assert.rejects(f.context.sync());
  assert.equal(f.calls.filter(row => row.method === "getWalletRetainedHistoryV3").length, 2);
  assert.deepEqual(f.applied, [2]); assert.equal(f.commits.length, 0);
}
{
  const f = fixture([502, 502]); await assert.rejects(f.context.sync(), error => error.code === "transport");
  assert.equal(f.calls.length, 4); assert.deepEqual(f.applied, [2]); assert.equal(f.commits.length, 0);
}
{
  const f = fixture([502], { lockOnFailure: true }); await assert.rejects(f.context.sync(), error => error.code === "locked");
  assert.equal(f.calls.length, 3); assert.equal(f.commits.length, 0);
}
{
  const f = fixture([], { badPage: true }); await assert.rejects(f.context.sync(), error => error.code === "history");
  assert.equal(f.calls.length, 3); assert.deepEqual(f.applied, [2]); assert.equal(f.commits.length, 0);
}
for (const method of ["submitShieldedPayment", "getWalletSyncSnapshot", "getShieldedPaymentStatus"]) {
  const f = fixture([502], { onlyRpc: true }); await assert.rejects(f.context.singleRpc(method));
  assert.equal(f.calls.length, 1); assert.equal(f.commits.length, 0);
}
console.log("PASS: only interrupted retained V3 page reads retry once with the identical cursor/target/token/size; completed pages apply once; no partial commit, auth/quota/schema/RPC/lock retries, or financial/other-RPC retries.");
