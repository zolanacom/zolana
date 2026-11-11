// The real RPC/quote boundary with a synthetic HTTP reply. No network or keys.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";

const source = await loadWorkerSource();

function fixture(data, code = -32040) {
  const calls = [];
  const context = createWorkerContext({
    TextEncoder, TextDecoder, Uint8Array, BigInt, AbortController,
    WalletStorageError: class extends Error {},
    self: { postMessage() {} },
    crypto: { randomUUID: () => "test-rpc-id" },
    setTimeout: () => 1, clearTimeout() {},
    performance: { now: () => 1 },
    fetch: async (_path, options) => {
      const request = JSON.parse(options.body); calls.push(request.method);
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id,
        error: { code, message: "UNTRUSTED-DO-NOT-ECHO", data } }),
      { headers: { "Content-Type": "application/json" } });
    },
  });
  vm.runInContext(`${source}
    configuration = { network: { network: Array(32).fill(7), genesis_hash: "1".repeat(32) } };
    transport = { rpc_audience: "https://fixture.invalid" };
    session.vault = { rpc_header: () => "inert-proof" };
    session.store = { snapshot: async () => ({ revision: 1, encryptedCheckpoint: new Uint8Array([1]), pending: null }) };
    session.verifiedStatus = { slot: 10, balance: "10", max_payment: "10" };
    core = async () => ({ prepare_wallet_prover() {} });
    syncWallet = async () => {};
    globalThis.call = method => rpc(method, [], session.generation, session.vault);
    globalThis.quote = () => quotePayment({ recipient: "npriv1" + "1".repeat(58), amountUnits: "5" });
    globalThis.review = () => session.reviewedQuote;
  `, context);
  return { context, calls };
}

for (const scope of ["member", "network"]) {
  const f = fixture({ scope });
  await assert.rejects(f.context.quote(), error => error.code === `${scope}_payment_limit`
    && !error.message.includes("UNTRUSTED"));
  assert.deepEqual(f.calls, ["getShieldedFeeQuote"]);
  assert.equal(f.context.review(), undefined);
  await assert.rejects(f.context.call("submitShieldedPayment"), error => error.code === `${scope}_payment_limit`);
}

for (const data of [null, [], { scope: "other" }, { scope: "member", detail: "private" }]) {
  const f = fixture(data);
  await assert.rejects(f.context.call("getShieldedFeeQuote"), error => error.code === "rpc"
    && !error.message.includes("UNTRUSTED"));
}
for (const [method, code] of [["getBlock", -32040], ["getShieldedFeeQuote", -32041]]) {
  const f = fixture({ scope: "member" }, code);
  await assert.rejects(f.context.call(method), error => error.code === "rpc");
}
console.log("PASS: typed payment limits stop review before construction/submission; malformed or unrelated errors stay generic.");
