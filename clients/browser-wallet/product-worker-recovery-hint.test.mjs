// Actual recovery scheduling with public fixtures; no network, wallet or timers.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
const source = await loadWorkerSource();
const packetId = "a".repeat(64);
function fixture(hints, canonicalUnknown = false) {
  const trace = [], queried = [], sleeps = []; let clock = 0, index = 0;
  const context = createWorkerContext({ TextEncoder, Uint8Array, packetId, canonicalUnknown, trace,
    WalletStorageError: class extends Error {}, performance: { now: () => ++clock },
    self: { postMessage() {} },
    setTimeout(resolve, ms) { sleeps.push(ms); resolve(); },
    nextHint: () => { const hint = hints[Math.min(index++, hints.length - 1)];
      if (hint instanceof Error) throw hint; return hint; },
    remember: params => queried.push(JSON.parse(JSON.stringify(params))) });
  vm.runInContext(`${source}
    configuration = { label: "fixture", environment: "testnet" };
    session.vault = { identity: () => "{}" }; session.store = {};
    session.savedPending = true;
    rpc = async (method, params) => {
      if (method !== "getShieldedPaymentStatus") throw new Error("recovery must never submit");
      trace.push("hint"); remember(params); return nextHint();
    };
    let canonicalScans = 0;
    syncWallet = async () => { trace.push("canonical");
      if (canonicalUnknown === true || Number.isInteger(canonicalUnknown) && canonicalScans++ < canonicalUnknown) throw publicFailure("pending_unknown", "original unresolved");
      return { lastOutcome: { packetId, decision: "accepted" } };
    };
    globalThis.recover = recoverPending;
  `, context);
  return { context, trace, queried, sleeps };
}
{
  const { context, trace, queried, sleeps } = fixture([
    { id: packetId, state: "pending" }, { id: packetId, state: "pending" }, { id: packetId, state: "accepted" },
  ]);
  const result = await context.recover({ attempts: 8, packetId });
  assert.equal(result.lastOutcome.decision, "accepted");
  assert.deepEqual(trace, ["hint", "hint", "hint", "canonical"]);
  assert(queried.every(params => params.length === 1 && params[0] === packetId));
  assert.deepEqual(sleeps, [500, 500]);
}
{
  const { context, trace, queried, sleeps } = fixture([
    { id: packetId, state: "pending" }, { id: packetId, state: "pending" }, { id: packetId, state: "accepted" },
  ], 1);
  const result = await context.recover({ attempts: 8, packetId });
  assert.equal(result.lastOutcome.decision, "accepted");
  assert.deepEqual(trace, ["hint", "hint", "hint", "canonical", "hint", "canonical"]);
  assert.deepEqual(sleeps, [500, 500, 500]); assert(queried.every(params => params.length === 1 && params[0] === packetId));
}
{
  const { context, trace, sleeps } = fixture([{ id: packetId, state: "pending" }], true);
  const result = await context.recover({ attempts: 8, packetId });
  assert.equal(result.pendingPayment, true); assert.equal(result.pendingOutcome, "unknown");
  assert.equal(trace.filter(v => v === "hint").length, 8);
  assert.equal(trace.filter(v => v === "canonical").length, 1);
  assert.deepEqual(sleeps, Array(7).fill(500));
}
for (const hint of [
  { id: packetId, state: "unknown" }, { id: packetId, state: "accepted" }, { id: packetId, state: "aborted" },
  { id: "b".repeat(64), state: "pending" }, { id: packetId, state: "pending", extra: true },
  null, [], { id: packetId }, new Error("fixture transport/refusal"),
]) {
  const { context, trace, sleeps } = fixture([hint], 1);
  await context.recover({ attempts: 8, packetId });
  assert.deepEqual(trace, ["hint", "canonical", "hint", "canonical"]); assert.deepEqual(sleeps, [500]);
}
{
  const { context, trace, sleeps } = fixture([{ id: packetId, state: "accepted" }], true);
  const result = await context.recover({ attempts: 8, packetId });
  assert.equal(result.pendingPayment, true); assert.equal(result.pendingOutcome, "unknown");
  assert.equal(result.lastOutcome, null);
  assert.equal(trace.filter(v => v === "canonical").length, 8);
  assert.deepEqual(sleeps, Array(7).fill(500)); // No hint can settle the journal.
}
for (const options of [undefined, { attempts: 1, packetId }, { attempts: 8 }, { attempts: 8, packetId: "invalid" }]) {
  const { context, trace } = fixture([{ id: packetId, state: "pending" }]);
  await context.recover(options); assert.deepEqual(trace, ["canonical"]);
}
{
  const { context, trace } = fixture([new Error("fixture connection failure")], 1);
  vm.runInContext("rpc = async () => { trace.push('hint'); session.generation++; throw new Error('locked'); };", context);
  await assert.rejects(context.recover({ attempts: 8, packetId }), error => error.code === "locked");
  assert.deepEqual(trace, ["hint"]);
}
{
  const { context, trace } = fixture([{ id: packetId, state: "accepted" }]);
  vm.runInContext("syncWallet = async () => { trace.push('canonical'); throw publicFailure('history', 'verification refused'); };", context);
  await assert.rejects(context.recover({ attempts: 8, packetId }), error => error.code === "history");
  assert.deepEqual(trace, ["hint", "canonical"]); // Verification failures do not become retries or status acceptance.
}
console.log("PASS: stable readiness hints postpone scans only for exact original pending ID; max8 hints/7 bounded waits and final canonical verification; malformed/error hints use canonical verification; unknown preserves original recovery; hints never settle journals; explicit recovery unchanged; lock/finality failure cancels.");
