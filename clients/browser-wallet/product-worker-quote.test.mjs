// Actual worker quote/sync control flow with inert public fixtures only.
// No WASM, IndexedDB, credentials, network or payments are executed.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
const source = await loadWorkerSource();
const request = { recipient: "npriv1" + "1".repeat(58), amountUnits: "5" };
function fixture({ pending = false, pendingAfter = false, syncFailure = false, lockDuring = false, freshBalance = "10" } = {}) {
  const events = [], old = { revision: 3, encryptedCheckpoint: new Uint8Array([1]), pending: pending ? {} : null },
    fresh = { revision: 9, encryptedCheckpoint: new Uint8Array([2]), pending: pendingAfter ? {} : null };
  let snapshots = 0;
  const context = createWorkerContext({ TextEncoder, Uint8Array, BigInt,
    WalletStorageError: class extends Error {}, self: { postMessage() {} },
    crypto: { randomUUID: () => "fixture-review" }, events, syncFailure, lockDuring, freshBalance,
    store: { snapshot: async () => { events.push("snapshot"); return snapshots++ ? fresh : old; } } });
  vm.runInContext(`${source}
    configuration = { network: { network: Array(32).fill(7), genesis_hash: "1".repeat(32) } };
    session.vault = {}; session.store = store;
    session.verifiedStatus = { slot: 10, balance: "100", max_payment: "100" };
    session.reviewedQuote = { reviewId: "old-review" };
    globalThis.originalSync = syncWallet;
    core = async () => ({ prepare_wallet_prover() {} });
    sha = async bytes => "digest-" + bytes[0];
    rpc = async method => { events.push(method);
      if (method === "getShieldedFeeQuote") return { format: "native-shielded-fee-quote-v1", fee: 3,
        network: configuration.network, transport: "native-inline-v1", pool_format: "NPOOL004" };
      if (method === "getSlot") return 1100;
      if (method === "getGenesisHash") return configuration.network.genesis_hash;
      throw new Error("unexpected RPC " + method);
    };
    syncWallet = async options => { events.push("sync");
      if (options.rejectPending !== true) throw new Error("review permitted pending recovery");
      if (syncFailure) throw new Error("fixture sync failed");
      if (lockDuring) session.generation++;
      session.verifiedStatus = { slot: 1000, balance: freshBalance, max_payment: freshBalance };
    };
    globalThis.quote = quotePayment;
    globalThis.review = () => session.reviewedQuote;
  `, context);
  return { context, events };
}
{
  const { context, events } = fixture();
  const quote = await context.quote(request);
  assert.equal(quote.reviewId, "fixture-review");
  assert.deepEqual(events, ["snapshot", "sync", "snapshot", "getShieldedFeeQuote", "getSlot"]);
  assert.equal(context.review().revision, 9);
  assert.equal(context.review().checkpointDigest, "digest-2");
  assert.equal(context.review().expiry, 1612);
}
{
  const { context, events } = fixture({ pending: true });
  await assert.rejects(context.quote(request), error => error.code === "pending");
  assert.deepEqual(events, ["snapshot"]);
  assert.equal(context.review(), undefined);
}
for (const options of [{ pendingAfter: true }, { syncFailure: true }, { lockDuring: true }, { freshBalance: "7" }]) {
  const { context, events } = fixture(options);
  await assert.rejects(context.quote(request));
  assert.equal(context.review(), undefined);
  assert(!events.includes("getSlot"));
}
{
  // Exercise the actual sync prelude, not a mirror of its pending guard. A
  // pending send appearing after quote's first snapshot cannot be reconciled.
  const { context, events } = fixture();
  vm.runInContext(`
    const methods = ["begin_sync", "checkpoint_info", "apply_compact_history_page", "apply_canonical_blocks", "finish_sync", "payment_status"];
    session.vault = Object.fromEntries(methods.map(name => [name, () => { throw new Error("unexpected replay"); }]));
    session.vault.validate_pending_checkpoint = () => { throw new Error("pending recovery must not run"); };
    checkAccess = async () => { session.admission = { admitted: true }; };
    session.store = { snapshot: async () => ({ pending: {}, encryptedCheckpoint: new Uint8Array([1]) }) };
    globalThis.rejectNewPending = () => originalSync({ rejectPending: true });
  `, context);
  await assert.rejects(context.rejectNewPending(), error => error.code === "pending");
  assert.deepEqual(events, []);
}
console.log("PASS: actual quote refresh binds new checkpoint/revision/fee/expiry, rejects pending before sync and inside sync, and fails closed on sync/lock/balance changes; no send or recovery executed.");
