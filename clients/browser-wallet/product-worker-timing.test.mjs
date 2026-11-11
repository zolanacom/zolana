// Actual worker control flow with inert public fixtures. No WASM, browser,
// wallet, network, credentials or payment is opened by these checks.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
import { hintAccount } from "./product-worker-pool-fixture.mjs";
const source = await loadWorkerSource();
const phases = ["quote_snapshot", "quote_sync", "quote_fresh_snapshot", "proof_key_prepare", "quote_fee", "quote_slot", "quote_checkpoint_digest",
  "send_snapshot", "send_checkpoint_digest", "send_slot", "send_build", "send_reserve", "send_packet", "send_submit", "send_recovery", "recovery_sync", "sync_open", "sync_snapshot_fetch", "sync_history_fetch", "sync_history_verify", "sync_finish"];
const buildPhases = ["checkpoint", "wallet_build", "validation", "anchor", "keys", "inputs", "bundle", "authorization", "proof", "signatures", "encoding", "seal"];
function fixture(options = {}) {
  const events = [], trace = []; let tick = 0;
  const context = createWorkerContext({ hintAccount, atob, btoa, TextEncoder, Uint8Array, BigInt, options, trace,
    WalletStorageError: class extends Error {}, crypto: { randomUUID: () => "fixture-review" },
    performance: { now: () => tick += 7.25 },
    self: { postMessage(value) {
      if (value.event === "timing" && options.telemetryFailure) throw new Error("observation unavailable");
      events.push(JSON.parse(JSON.stringify(value)));
    } } });
  vm.runInContext(`${source}
    configuration = { network: { network: Array(32).fill(7), genesis_hash: "1".repeat(32) }, label: "fixture", environment: "testnet" };
    engineMode = "parallel"; engineThreads = 8;
    engineRuntime = { crossOriginIsolated: true, hardwareConcurrency: 12 };
    transport = { program: hintAccount().owner, pool: "fixture-pool" }; session.admission = { admitted: true };
    globalThis.originalSync = syncWallet;
    let reserved = false, snapshots = 0;
    session.store = {
      async snapshot() { trace.push("snapshot"); return { revision: snapshots++ ? 9 : 1,
        encryptedCheckpoint: new Uint8Array([snapshots > 1 ? 2 : 1]), pending: options.pending ? {} : null }; },
      async reservePending() { trace.push("reserve"); if (options.reserveFailure) throw new Error("fixture reservation failed"); reserved = true; },
      async commitCheckpoint() { trace.push("commit"); }
    };
    session.vault = {
      identity() { return "{}"; },
      build_payment(recipient, amount, fee, quote, expiry) { trace.push("build");
        if (options.buildFailure) throw new Error("SENSITIVE-BUILD-FIXTURE");
        return JSON.stringify({ packet_id: "a".repeat(64), amount: amount.toString(), fee: fee.toString(),
          expires_at: Number(expiry), encrypted_pending: Array(48).fill(1), build_timings_ms: options.buildTimings }); },
      pending_packet() { trace.push("packet"); if (!reserved) throw new Error("packet before durable reservation");
        return JSON.stringify({ id: "a".repeat(64), packet: { public: "fixture" } }); }
    };
    session.verifiedStatus = { slot: 1000, balance: "10", max_payment: "10" };
    session.reviewedQuote = { reviewId: "fixture-review", recipient: "npriv1" + "1".repeat(58), amountUnits: "5", maximumFeeUnits: "3",
      quote: {}, expiry: 1612, revision: 1, checkpointDigest: "digest-1" };
    sha = async bytes => { trace.push("digest"); return "digest-" + bytes[0]; };
    core = async () => ({ prepare_wallet_prover() { trace.push("prepare"); } });
    rpc = async method => {
      trace.push(method);
      if (method === "getSlot") return options.expired ? 1612 : 1100;
      if (method === "getShieldedFeeQuote") return { format: "native-shielded-fee-quote-v1", fee: 3, network: configuration.network,
        transport: "native-inline-v1", pool_format: "NPOOL004" };
      if (method === "submitShieldedPayment") { if (!reserved) throw new Error("submit before reservation");
        if (options.lostReply) throw new Error("SENSITIVE-REPLY-FIXTURE"); return { accepted: true }; }
      if (method === "getShieldedPaymentStatus") { if (!reserved) throw new Error("hint before reservation");
        return { id: "a".repeat(64), state: "unknown" }; }
      throw new Error("unexpected RPC");
    };
    syncWallet = async opts => { trace.push("sync");
      if (opts && opts.rejectPending !== true) throw new Error("review recovery enabled");
      if (options.syncFailure) throw new Error("SENSITIVE-SYNC-FIXTURE");
      session.verifiedStatus = { slot: 1000, balance: "10", max_payment: "10" };
      return { lastOutcome: { packetId: "a".repeat(64), decision: "accepted" } };
    };
    globalThis.quote = quotePayment; globalThis.send = sendPayment;
    globalThis.measure = measureSync; globalThis.measureAwaited = measureAsync;
    globalThis.emitTiming = timing;
    globalThis.diagnostics = engineDiagnostics;
    globalThis.publicStatus = currentStatus;
  `, context);
  return { context, events, trace, timings: () => events.filter(value => value.event === "timing") };
}
function safeTimings(items) {
  for (const item of items) {
    assert.deepEqual(Object.keys(item).sort(), ["elapsedMs", "event", "phase"]);
    assert.equal(item.event, "timing"); assert(phases.includes(item.phase));
    assert(Number.isInteger(item.elapsedMs) && item.elapsedMs >= 0 && item.elapsedMs <= 3600000);
  }
  assert(!JSON.stringify(items).includes("SENSITIVE"));
}
{
  const { context, trace, timings } = fixture();
  const quote = await context.quote({ recipient: "npriv1" + "1".repeat(58), amountUnits: "5" });
  assert.deepEqual(trace, ["snapshot", "sync", "snapshot", "prepare", "getShieldedFeeQuote", "getSlot", "digest"]);
  assert.deepEqual(timings().map(v => v.phase), phases.slice(0, 7));
  safeTimings(timings());
  assert.deepEqual(JSON.parse(JSON.stringify(quote.diagnostics)), { format: "zolana-browser-engine-diagnostics-v1",
    engineMode: "parallel", engineThreads: 8, crossOriginIsolated: true, hardwareConcurrency: 12 });
  assert.deepEqual(JSON.parse(JSON.stringify(context.publicStatus().diagnostics)), JSON.parse(JSON.stringify(quote.diagnostics)));
}
{
  const metrics = Object.fromEntries(buildPhases.map((phase, index) => [phase, index === 8 ? 1234 : index]));
  const { context, trace } = fixture({ buildTimings: metrics, lostReply: true });
  const result = await context.send({ reviewId: "fixture-review" });
  assert.deepEqual(JSON.parse(JSON.stringify(result.diagnostics.buildTimingsMs)), metrics);
  assert.equal(result.paymentOutcome, "accepted"); assert.equal(result.responseLost, true);
  assert.equal(trace.filter(value => value === "submitShieldedPayment").length, 1);
  assert(trace.indexOf("reserve") < trace.indexOf("packet"));
}
for (const buildTimings of ["SENSITIVE-METRICS", {}, { checkpoint: 1 },
  { ...Object.fromEntries(buildPhases.map(phase => [phase, 0])), proof: -1 },
  { ...Object.fromEntries(buildPhases.map(phase => [phase, 0])), proof: 3600001 },
  { ...Object.fromEntries(buildPhases.map(phase => [phase, 0])), proof: "SENSITIVE-METRICS" },
  { ...Object.fromEntries(buildPhases.map(phase => [phase, 0])), packet: "SENSITIVE-METRICS" }]) {
  const { context, trace } = fixture({ buildTimings });
  const result = await context.send({ reviewId: "fixture-review" });
  assert.equal(result.paymentOutcome, "accepted");
  assert.equal(result.diagnostics.buildTimingsMs, undefined);
  assert(!JSON.stringify(result.diagnostics).includes("SENSITIVE"));
  assert.equal(trace.filter(value => value === "submitShieldedPayment").length, 1);
}
for (const options of [{}, { lostReply: true }, { telemetryFailure: true }]) {
  const { context, trace, timings } = fixture(options);
  const result = await context.send({ reviewId: "fixture-review" });
  assert.equal(result.paymentOutcome, "accepted"); assert.equal(result.responseLost, !!options.lostReply);
  assert.deepEqual(trace, ["snapshot", "digest", "getSlot", "build", "reserve", "packet", "submitShieldedPayment", "getShieldedPaymentStatus", "sync"]);
  assert.equal(trace.filter(v => v === "submitShieldedPayment").length, 1);
  if (!options.telemetryFailure) {
    assert.deepEqual(timings().map(v => v.phase), ["send_snapshot", "send_checkpoint_digest", "send_build", "send_slot", "send_reserve", "send_packet", "send_submit", "recovery_sync", "send_recovery"]);
    safeTimings(timings());
  } else assert.deepEqual(timings(), []);
}
for (const options of [{ reserveFailure: true }, { buildFailure: true }, { expired: true }, { pending: true }]) {
  const { context, trace, timings } = fixture(options);
  await assert.rejects(context.send({ reviewId: "fixture-review" }));
  assert(!trace.includes("submitShieldedPayment")); assert(!trace.includes("packet"));
  safeTimings(timings());
}
{
  const { context, timings } = fixture();
  const failure = new Error("SENSITIVE-SAME-ERROR-FIXTURE");
  assert.throws(() => context.measure("send_build", () => { throw failure; }), error => error === failure);
  await assert.rejects(context.measureAwaited("send_submit", async () => { throw failure; }), error => error === failure);
  context.emitTiming("unapproved-phase-SENSITIVE", 0);
  context.emitTiming("send_build", -4000000);
  context.emitTiming("send_build", Infinity);
  assert.equal(timings().length, 2); safeTimings(timings());
}
{
  // Execute the ordinary sync with a module lacking any PK interface. A real
  // VK-only begin_sync is supplied by the separately reviewed WASM build.
  const { context, trace, timings } = fixture();
  vm.runInContext(`
    core = async () => ({});
    session.vault = { identity: () => "{}", checkpoint_info: () => '{"slot":0}',
      begin_sync: () => { trace.push("begin_sync"); return '{"slot":0,"target":0}'; },
      apply_compact_history_page() {}, apply_canonical_blocks() {},
      finish_sync: () => new Uint8Array([2]),
      payment_status: () => '{"verified":true,"balance":"10","max_payment":"10","slot":0}' };
    checkAccess = async () => { session.admission = { admitted: true }; };
    rpc = async method => {
      if (method === "getWalletSyncSnapshot") throw publicFailure("rpc_method_missing", "fixture legacy method");
      if (method === "getGenesisHash") return configuration.network.genesis_hash;
      if (method === "getAccountInfo") return { context: { slot: 0 }, value: { ...hintAccount(), lamports: 0 } };
      if (method === "getBlock") return {};
      throw new Error("unexpected sync RPC");
    };
    globalThis.syncOnly = () => originalSync();
  `, context);
  await context.syncOnly();
  assert.deepEqual(trace, ["snapshot", "begin_sync", "commit"]);
  assert.equal(timings().filter(value => value.phase === "sync_snapshot_fetch").length, 1);
  safeTimings(timings());
}
for (const setup of [
  { isolated: true, sab: true, hardware: 12, mode: "parallel", threads: 8 },
  { isolated: true, sab: true, hardware: 4, mode: "parallel", threads: 4 },
  { isolated: false, sab: true, hardware: 12, mode: "scalar", threads: 1 },
  { isolated: true, sab: false, hardware: 12, mode: "scalar", threads: 1 },
  { isolated: true, sab: true, hardware: undefined, mode: "parallel", threads: 1 }
]) {
  const calls = [];
  // Replace only the module loader, then execute the actual engine selection
  // and awaited thread-pool code with an inert module. No WASM is loaded.
  const originalImport = 'await import(parallel ? "/wasm-parallel/browser_core.js" : "/wasm/browser_core.js")';
  assert.equal(source.split(originalImport).length, 2);
  const context = createWorkerContext({ hintAccount, atob, btoa, TextEncoder, Uint8Array, BigInt,
    SharedArrayBuffer: setup.sab ? function FixtureSharedArrayBuffer() {} : undefined,
    navigator: { hardwareConcurrency: setup.hardware },
    self: { crossOriginIsolated: setup.isolated, postMessage() {} },
    loadCore: async parallel => {
      calls.push(parallel ? "parallel-module" : "scalar-module");
      return { default: async () => { calls.push("memory-ready"); },
        initThreadPool: async threads => { calls.push(`pool-ready:${threads}`); },
        BrowserVault: { create() {}, restore() {} } };
    }
  });
  vm.runInContext(`${source.replace(originalImport, "await globalThis.loadCore(parallel)")}
    globalThis.initializeEngine = core; globalThis.engineReport = engineDiagnostics;
  `, context);
  await context.initializeEngine(); await context.initializeEngine();
  assert.deepEqual(calls, setup.mode === "parallel" ? ["parallel-module", "memory-ready", `pool-ready:${setup.threads}`] : ["scalar-module", "memory-ready"]);
  assert.deepEqual(JSON.parse(JSON.stringify(context.engineReport())), {
    format: "zolana-browser-engine-diagnostics-v1", engineMode: setup.mode, engineThreads: setup.threads,
    crossOriginIsolated: setup.isolated, hardwareConcurrency: setup.hardware ?? null });
}
console.log("PASS: bounded engine/build diagnostics; actual scalar/parallel selection and awaited pool; unchanged timing events; fresh quote/preparation order; VK-only sync; durable reservation/one submit on success, lost reply and telemetry failure; malformed diagnostics omitted without changing acceptance.");
