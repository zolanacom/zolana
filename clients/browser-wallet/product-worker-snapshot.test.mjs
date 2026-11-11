// Actual consumer control flow with inert canonical fixtures, no RPC/storage/WASM.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
import { hintAccount } from "./product-worker-pool-fixture.mjs";
const source = await loadWorkerSource();
const network = { network: Array(32).fill(7), genesis_hash: "1".repeat(32) };
const hash = slot => "1".repeat(31) + String(slot + 1);
const header = slot => ({ blockhash: hash(slot), blockHeight: slot });
const blocks = [{ slot: 2, block: { ...header(2), parentSlot: 1, previousBlockhash: hash(1), transactions: [] } }];
function snapshot() {
  return { format: "zolana-wallet-sync-snapshot-v1", network, genesis: network.genesis_hash,
    pool: { context: { slot: 2 }, value: { ...hintAccount(), lamports: 1000 } }, target_header: header(2), saved_header: header(1),
    canonical_tail: { after_slot: 1, target_slot: 2, next_slot: 2, complete: true, blocks }, fallback: null };
}
function fixture({ result = snapshot(), error, pending = false, unknown = false, coreFailure, commitFailure, cold = false } = {}) {
  const trace = [], calls = []; let tick = 0;
  const context = createWorkerContext({ hintAccount, atob, btoa, TextEncoder, Uint8Array, result, error, pending, unknown, coreFailure, commitFailure, cold, trace, network,
    WalletStorageError: class extends Error {}, performance: { now: () => ++tick }, self: { postMessage() {} },
    crypto: { randomUUID: () => "fixture-id" }, recordCall: (method, params) => calls.push([method, JSON.parse(JSON.stringify(params))]) });
  vm.runInContext(`${source}
    configuration = { network, label: "fixture", environment: "testnet" };
    transport = { program: hintAccount().owner, pool: "1".repeat(32), rpc_audience: "https://fixture.invalid/" };
    let slot = cold ? 0 : 1, target = 2;
    const original = new Uint8Array([1]);
    session.store = { snapshot: async () => ({ revision: 1, encryptedCheckpoint: cold ? null : original,
      pending: pending ? { packetId: "a".repeat(64), encryptedPacket: new Uint8Array([9]) } : null }),
      commitCheckpoint: async () => { trace.push("commit"); if (commitFailure) throw new Error("commit failed"); },
      settlePending: async () => { trace.push("settle"); } };
    session.vault = {
      identity: () => "{}", rpc_header: () => "fixture-access", checkpoint_info: () => '{"slot":1}',
      validate_pending_checkpoint: (packet, checkpoint) => { trace.push("validate_pending"); if (checkpoint !== original) throw new Error("changed original pair"); },
      begin_sync: (pool, h, checkpoint, cached) => { trace.push("begin"); if (coreFailure === "begin") throw new Error("wrong root");
        if (pending && checkpoint !== original && checkpoint.length !== 0) throw new Error("replaced pending checkpoint");
        target = JSON.parse(pool).context.slot; slot = checkpoint.length ? 1 : 0;
        return JSON.stringify({ slot, target }); },
      apply_compact_history_page: () => { trace.push("retained"); slot = target; return JSON.stringify({ slot, target }); },
      apply_canonical_blocks: text => { trace.push("canonical"); const values = JSON.parse(text);
        if (coreFailure === "canonical" || values[0].parent_slot !== slot || values[0].previous_blockhash !== "1".repeat(31) + String(slot + 1)) throw new Error("bad canonical link");
        slot = values.at(-1).slot; return JSON.stringify({ slot, target }); },
      finish_sync: () => { trace.push("finish"); if (coreFailure === "finish" || slot !== target) throw new Error("final mismatch"); return new Uint8Array([2]); },
      pending_outcome: () => ({ toString() {} }),
      payment_status: () => JSON.stringify({ verified: true, balance: "10", max_payment: "10", slot })
    };
    session.vault.pending_outcome = () => JSON.stringify({ packet_id: "a".repeat(64), decision: unknown ? "unknown" : "accepted", encrypted_receipt: [8] });
    checkAccess = async () => { trace.push("access"); session.admission = { admitted: true, state: "active", accessUntil: 1234 }; };
    core = async () => ({});
    compactHistory = () => ({ metadata: "{}", bytes: new Uint8Array() });
    scanCanonicalArchive = async () => { trace.push("archive"); slot = target; return { slot, target }; };
    globalThis.realRpc = rpc;
    rpc = async (method, params) => { recordCall(method, params);
      if (method === "getWalletSyncSnapshot") { if (error) throw publicFailure(error, "fixed fixture failure"); return result; }
      if (method === "getGenesisHash") return network.genesis_hash;
      if (method === "getAccountInfo") return { context: { slot: 2 }, value: { ...hintAccount(), lamports: 1000 } };
      if (method === "getBlock") return { blockhash: "1".repeat(31) + String(params[0] + 1), blockHeight: params[0] };
      if (method === "getBlocks") return [2];
      if (method === "getWalletHistoryBlocks") return [{ slot: 2, block: { parentSlot: 1, previousBlockhash: "1".repeat(31) + "2", blockhash: "1".repeat(31) + "3", blockHeight: 2, transactions: [] } }];
      if (method === "getWalletRetainedHistoryV3") return {};
      throw new Error("unexpected RPC " + method);
    };
    globalThis.sync = syncWallet; globalThis.membership = () => session.admission;
  `, context);
  return { context, trace, calls };
}
for (const pending of [false, true]) {
  const { context, trace, calls } = fixture({ pending });
  const state = await context.sync();
  assert.deepEqual(calls, [["getWalletSyncSnapshot", [1]]]);
  assert.deepEqual(trace, pending ? ["validate_pending", "begin", "canonical", "finish", "settle"] : ["begin", "canonical", "finish", "commit"]);
  assert.equal(state.admission.admitted, true); assert.equal(state.admission.accessUntil, null);
}
{
  const value = snapshot(); value.pool.context.slot = 1; value.target_header = header(1);
  value.canonical_tail = { after_slot: 1, target_slot: 1, next_slot: 1, complete: true, blocks: [] };
  const { context, trace, calls } = fixture({ result: value });
  await context.sync();
  assert.deepEqual(trace, ["begin", "finish", "commit"]);
  assert.deepEqual(calls, [["getWalletSyncSnapshot", [1]]]);
}
for (const options of [{ unknown: true, pending: true }, { coreFailure: "begin" }, { coreFailure: "canonical" }, { coreFailure: "finish" }, { commitFailure: true }]) {
  const { context, trace } = fixture(options);
  await assert.rejects(context.sync()); assert.equal(context.membership(), undefined);
  if (!options.commitFailure) assert(!trace.includes("commit") && !trace.includes("settle"));
}
for (const reason of ["tail-too-large", "canonical-incomplete", "response-too-large"]) {
  const value = snapshot(); value.canonical_tail = null; value.fallback = reason;
  const { context, trace, calls } = fixture({ result: value });
  await context.sync(); assert(trace.includes("access"));
  assert.deepEqual(calls.map(call => call[0]), ["getWalletSyncSnapshot", "getBlocks", "getWalletHistoryBlocks"]);
}
{
  const value = snapshot(); value.saved_header = null; value.canonical_tail = null; value.fallback = "checkpoint-unavailable";
  const { context, trace, calls } = fixture({ result: value, pending: true });
  await context.sync(); assert.deepEqual(trace, ["validate_pending", "access", "begin", "archive", "finish", "settle"]);
  assert.deepEqual(calls.map(call => call[0]), ["getWalletSyncSnapshot"]);
}
{
  const value = snapshot(); value.saved_header = null; value.canonical_tail = null; value.fallback = "tail-too-large";
  const { context, trace, calls } = fixture({ result: value, cold: true });
  await context.sync(); assert(trace.includes("retained")); assert(trace.includes("access"));
  assert.deepEqual(calls.map(call => call[0]), ["getWalletSyncSnapshot", "getWalletRetainedHistoryV3"]);
}
{
  const { context, trace, calls } = fixture({ error: "rpc_method_missing" });
  await context.sync(); assert(trace.includes("access"));
  assert.deepEqual(calls.map(call => call[0]), ["getWalletSyncSnapshot", "getGenesisHash", "getAccountInfo", "getBlock", "getBlock", "getBlocks", "getWalletHistoryBlocks"]);
}
for (const error of ["access", "rate_limit", "transport", "connection", "rpc"]) {
  const { context, trace, calls } = fixture({ error });
  await assert.rejects(context.sync(), e => e.code === error);
  assert.deepEqual(trace, []); assert.equal(calls.length, 1);
}
{
  const { context, trace } = fixture({ result: null });
  await assert.rejects(context.sync()); assert.deepEqual(trace, []);
}
for (const mutate of [
  v => { v.extra = true; }, v => { v.genesis = "2".repeat(32); }, v => { v.network = { ...network, network: Array(32).fill(8) }; },
  v => { v.pool.context.slot = 0; }, v => { v.fallback = "unknown"; }, v => { v.saved_header = null; },
  v => { v.canonical_tail.complete = false; }, v => { v.canonical_tail.next_slot = 1; },
  v => { v.canonical_tail.after_slot = 0; }, v => { v.canonical_tail.blocks = []; },
  v => { v.canonical_tail.blocks = Array(257).fill(blocks[0]); }, v => { v.canonical_tail.blocks = [blocks[0], blocks[0]]; },
]) {
  const value = JSON.parse(JSON.stringify(snapshot())); mutate(value);
  const { context, trace } = fixture({ result: value });
  await assert.rejects(context.sync()); assert.deepEqual(trace, []);
}
{
  // Exact JSON-RPC method-not-found alone grants legacy compatibility.
  for (const code of [-32601, -32000, "-32601"]) {
    const { context } = fixture();
    context.replyCode = code;
    vm.runInContext(`responseJSON = async () => ({ jsonrpc: "2.0", id: "fixture-id", error: { code: replyCode } });
      globalThis.methodCheck = () => realRpc("getWalletSyncSnapshot", [1], session.generation, session.vault);`, context);
    await assert.rejects(context.methodCheck(), error => error.code === (code === -32601 ? "rpc_method_missing" : "rpc"));
  }
}
console.log("PASS: one authorized snapshot uses existing canonical verifier+durable commit; admission changes only afterward; original pending preserved; metadata reuse/V3/archive and explicit-32601 legacy fallback work; auth/transport/malformed/core failures never silently fallback or settle.");
