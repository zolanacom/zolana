// Real send controller with a deferred read and inert local proof/store only.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
const source = await loadWorkerSource();
const flush = () => new Promise(resolve => setImmediate(resolve));
function fixture(options = {}) {
  const trace = []; let resolveSlot, rejectSlot;
  const slot = new Promise((resolve, reject) => { resolveSlot = resolve; rejectSlot = reject; });
  const buildError = new Error("disposable build refusal");
  const context = createWorkerContext({ TextEncoder, Uint8Array, BigInt, options, trace, slot, buildError,
    WalletStorageError: class extends Error {}, performance: { now: () => 1 }, self: { postMessage() {} } });
  vm.runInContext(`${source}
    configuration = { label: "fixture", environment: "testnet" };
    session.store = {
      snapshot: async () => ({ revision: 7, encryptedCheckpoint: new Uint8Array([1]), pending: options.pending ? {} : null }),
      reservePending: async () => { trace.push("reserve"); }
    };
    session.vault = { identity: () => "{}",
      build_payment: () => { trace.push("build"); if (options.buildFailure) throw buildError;
        return JSON.stringify({ packet_id: options.malformedBuild ? "wrong" : "a".repeat(64), amount: "5", fee: "3",
          expires_at: 1612, encrypted_pending: Array(48).fill(1) }); },
      pending_packet: () => { if (!trace.includes("reserve")) throw new Error("packet before reserve"); trace.push("packet");
        return JSON.stringify({ id: "a".repeat(64), packet: { disposable: true } }); }
    };
    session.verifiedStatus = { verified: true, slot: 1000, balance: "10", max_payment: "10" };
    session.reviewedQuote = { reviewId: "fixture-review", revision: 7, checkpointDigest: "fixture-checkpoint",
      recipient: "fixture", amountUnits: "5", maximumFeeUnits: "3", quote: {}, expiry: 1612 };
    sha = async () => "fixture-checkpoint";
    rpc = async method => { trace.push(method);
      if (method === "getSlot") { const value = await slot; trace.push("slot-result"); return value; }
      if (method === "submitShieldedPayment") { if (!trace.includes("reserve")) throw new Error("submit before reserve");
        if (options.submitCode) throw publicFailure(options.submitCode, "reviewed test limit");
        if (options.lostReply) throw new Error("disposable lost reply"); return {}; }
      throw new Error("unexpected RPC");
    };
    recoverPending = async () => { trace.push("canonical-recovery");
      if (options.recoveryUnknown) return { pendingPayment: true, pendingOutcome: "unknown", lastOutcome: null };
      return { lastOutcome: { packetId: "a".repeat(64), decision: "accepted" } }; };
    globalThis.send = () => sendPayment({ reviewId: "fixture-review" });
    globalThis.cancel = () => { session.generation++; };
  `, context);
  return { context, trace, resolveSlot, rejectSlot, buildError };
}
function started(f) {
  const promise = f.context.send();
  // Also observe immediate local build refusals while the read remains pending.
  const settled = promise.then(value => ({ value }), error => ({ error }));
  return { promise, settled };
}
{
  const f = fixture(), p = started(f); await flush();
  assert.deepEqual(f.trace, ["getSlot", "build"]); // Proof starts before the read resolves.
  f.resolveSlot(1100); const result = await p.promise;
  assert.deepEqual(f.trace, ["getSlot", "build", "slot-result", "reserve", "packet", "submitShieldedPayment", "canonical-recovery"]);
  assert.equal(result.paymentOutcome, "accepted"); await assert.rejects(f.context.send());
  assert.equal(f.trace.filter(x => x === "submitShieldedPayment").length, 1);
}
for (const latest of [1612, 1613, -1, 1.5, "1100", null, NaN]) {
  const f = fixture(), p = started(f); await flush(); f.resolveSlot(latest);
  await assert.rejects(p.promise, error => error.code === "review");
  assert.deepEqual(f.trace, ["getSlot", "build", "slot-result"]);
}
{
  const f = fixture(), p = started(f), error = new Error("disposable read failure");
  await flush(); f.rejectSlot(error); await assert.rejects(p.promise, value => value === error);
  assert.deepEqual(f.trace, ["getSlot", "build"]);
}
{
  const f = fixture(), p = started(f); await flush(); f.context.cancel(); f.resolveSlot(1100);
  await assert.rejects(p.promise, error => error.code === "locked");
  assert.deepEqual(f.trace, ["getSlot", "build", "slot-result"]);
}
{
  const f = fixture({ buildFailure: true }), p = started(f), unhandled = [];
  const observer = error => unhandled.push(error); process.on("unhandledRejection", observer);
  try {
    assert.equal((await p.settled).error, f.buildError);
    f.rejectSlot(new Error("disposable later read failure")); await flush(); await flush();
    assert.deepEqual(unhandled, []); assert.deepEqual(f.trace, ["getSlot", "build"]);
  } finally { process.off("unhandledRejection", observer); }
}
for (const options of [{ pending: true }, { malformedBuild: true }]) {
  const f = fixture(options), p = started(f); f.resolveSlot(1100); await assert.rejects(p.promise);
  assert(!f.trace.includes("reserve") && !f.trace.includes("packet") && !f.trace.includes("submitShieldedPayment"));
  if (options.pending) assert.deepEqual(f.trace, []);
}
{
  const f = fixture({ lostReply: true }), p = started(f); await flush(); f.resolveSlot(1100);
  const result = await p.promise; assert.equal(result.responseLost, true); assert.equal(result.paymentOutcome, "accepted");
  assert.equal(f.trace.filter(x => x === "submitShieldedPayment").length, 1);
  assert(f.trace.indexOf("reserve") < f.trace.indexOf("packet"));
}
for (const [submitCode, expected] of [["member_payment_limit", "member"], ["network_payment_limit", "network"], ["other", null]]) {
  const f = fixture({ submitCode, recoveryUnknown: true }), p = started(f);
  await flush(); f.resolveSlot(1100);
  const result = await p.promise;
  assert.equal(result.submissionLimit, expected);
  assert.equal(result.pendingPayment, true);
  assert.equal(result.paymentOutcome, "unknown");
  assert.equal(f.trace.filter(x => x === "submitShieldedPayment").length, 1);
  assert.equal(f.trace.filter(x => x === "reserve").length, 1);
  assert.equal(f.trace.filter(x => x === "canonical-recovery").length, 1);
}
console.log("PASS: fresh-slot read overlaps local build; exact slot/expiry/session required before durable reserve, packet or single submit; expired/invalid/read/lock/build errors never write or submit, no unhandled late rejection or lost-reply retry.");
