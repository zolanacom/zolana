// Runs with `node --test sdk/js/*.test.mjs`. A loopback HTTP server stands in for the
// endpoint and applies the invited gateway's request rules. No network is used.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import {
  createRpcClient, FULL_BLOCK_CONFIG, GATEWAY_METHODS, HttpError, MAX_REQUEST_BYTES,
  RELAY_CAPACITY_CODE, RpcError, TransportError,
} from "./rpc.mjs";

const NETWORK = { network: Array(32).fill(7), genesis_hash: "1".repeat(32) };
const QUOTE = { format: "native-shielded-fee-quote-v1", network: NETWORK, payer: "1".repeat(32), fee: 3000000, transport: "native-inline-v1", pool_format: "NPOOL004" };
const JOB = "ab".repeat(32);
/** @type {{ method: string, params: unknown[], access: string | undefined, id: unknown }[]} */
let seen = [];
/** Per-test override of the answer: (request) => [status, headers, bodyText] or undefined. */
let override;
let server, url;

// The same checks, in the same order, as Handler._read_rpc_request and
// _authorize_rpc_request in tools/testnet_gateway.py.
function gateway(request, raw) {
  const denied = [403, JSON.stringify({ error: "access_denied" })];
  if (request.method !== "POST" || request.url !== "/" || request.headers.origin !== undefined) return denied;
  if (request.headers["content-type"] !== "application/json" || raw.length < 1 || raw.length > 32768) return denied;
  let body;
  try { body = JSON.parse(raw.toString("utf8")); } catch { return denied; }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some(key => !["jsonrpc", "id", "method", "params"].includes(key)) ||
      body.jsonrpc !== "2.0" || !GATEWAY_METHODS.includes(body.method) || !["string", "number"].includes(typeof body.id) ||
      String(body.id).length > 64 || !(body.params === undefined || Array.isArray(body.params))) return denied;
  const access = request.headers["x-testnet-access"];
  seen.push({ method: body.method, params: body.params, access, id: body.id });
  if (body.method !== "getGenesisHash" && access !== "member-proof") return access === "over-quota" ? [429, JSON.stringify({ error: "request_limit" })] : denied;
  const answer = result => [200, JSON.stringify({ jsonrpc: "2.0", id: body.id, result })];
  const custom = override?.(body);
  if (custom) return custom;
  switch (body.method) {
    case "getGenesisHash": return answer(NETWORK.genesis_hash);
    case "getSlot": return answer(41);
    case "getAccountInfo": return answer({ context: { slot: 41 }, value: { owner: "1".repeat(32), lamports: 5, data: ["", "base64"] } });
    case "getBlock": return answer({ parentSlot: 40, blockhash: "b", previousBlockhash: "a", blockHeight: 9, transactions: [] });
    case "getShieldedFeeQuote": return answer(QUOTE);
    case "submitShieldedPayment": return answer({ id: JOB });
    case "getShieldedPaymentStatus": return answer({ id: body.params[0], state: "pending" });
    case "getWalletHistoryBlocks": return answer(body.params[0].map(slot => ({ slot, block: { parentSlot: slot - 1, blockhash: "b", previousBlockhash: "a", blockHeight: slot, transactions: [] } })));
    case "getWalletReadBatch": return answer(body.params[0].map(call => ({ request: call, result: 41 })));
    default: return answer(null);
  }
}

before(async () => {
  server = createServer((request, response) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => {
      const [status, text, headers = { "Content-Type": "application/json" }, delay = 0] = gateway(request, Buffer.concat(chunks));
      setTimeout(() => { response.writeHead(status, headers); response.end(text); }, delay);
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  url = `http://127.0.0.1:${server.address().port}/`;
});
after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));

const member = options => createRpcClient({ url, accessHeader: () => "member-proof", ...options });
const reset = () => { seen = []; override = undefined; };

test("the handshake carries no proof and every other method does", async () => {
  reset();
  const client = member();
  assert.equal(await client.getGenesisHash(), NETWORK.genesis_hash);
  assert.equal(await client.getSlot(), 41);
  assert.deepEqual(seen.map(item => [item.method, item.access]), [["getGenesisHash", undefined], ["getSlot", "member-proof"]]);
  assert.deepEqual(seen[1].params, [{ commitment: "finalized" }]);
  assert.notEqual(seen[0].id, seen[1].id);
});

test("typed methods send the parameters the gateway validates", async () => {
  reset();
  const client = member();
  const pool = await client.getAccountInfo("1".repeat(32));
  assert.equal(pool.context.slot, 41);
  assert.equal((await client.getBlock(41))?.blockHeight, 9);
  assert.deepEqual(await client.getShieldedFeeQuote(), QUOTE);
  assert.deepEqual(await client.submitShieldedPayment({ network: NETWORK, payload: "AAAA" }), { id: JOB });
  assert.deepEqual(await client.getShieldedPaymentStatus(JOB), { id: JOB, state: "pending" });
  assert.deepEqual((await client.getWalletHistoryBlocks([5, 6, 9])).map(item => item.slot), [5, 6, 9]);
  const batch = await client.getWalletReadBatch([{ method: "getSlot", params: [{ commitment: "confirmed" }] }]);
  assert.deepEqual(batch, [{ request: { method: "getSlot", params: [{ commitment: "confirmed" }] }, result: 41 }]);
  assert.equal(await client.getWalletRetainedHistoryV3(0, 41, null, 32768), null);
  assert.equal(await client.getWalletCanonicalHistory(0, 41, null), null);
  assert.deepEqual(seen.map(item => item.params), [
    ["1".repeat(32), { commitment: "finalized", encoding: "base64" }],
    [41, { ...FULL_BLOCK_CONFIG }],
    [],
    [{ network: NETWORK, payload: "AAAA" }],
    [JOB],
    [[5, 6, 9]],
    [[{ method: "getSlot", params: [{ commitment: "confirmed" }] }]],
    [0, 41, null, 32768],
    [0, 41, null],
  ]);
});

test("a wallet outside the cohort is refused, and a quota is reported as such", async () => {
  reset();
  const outsider = createRpcClient({ url });
  assert.equal(await outsider.getGenesisHash(), NETWORK.genesis_hash);
  const denied = await outsider.getSlot().catch(error => error);
  assert.ok(denied instanceof HttpError && denied.accessDenied && !denied.rateLimited);
  assert.deepEqual(denied.body, { error: "access_denied" });
  const limited = await createRpcClient({ url, accessHeader: () => "over-quota" }).getSlot().catch(error => error);
  assert.ok(limited instanceof HttpError && limited.rateLimited);
  assert.equal(limited.status, 429);
  // A method outside the allow-list is refused the same way.
  const unlisted = await member().call("requestAirdrop", []).catch(error => error);
  assert.ok(unlisted instanceof HttpError && unlisted.status === 403);
});

test("JSON-RPC errors keep their code and the relay capacity scope", async () => {
  reset();
  override = body => [200, JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: RELAY_CAPACITY_CODE, message: "Testnet private payment capacity reached", data: { scope: "member" } } })];
  const error = await member().getShieldedFeeQuote().catch(error => error);
  assert.ok(error instanceof RpcError);
  assert.equal(error.code, -32040);
  assert.equal(error.capacityScope, "member");
  assert.match(error.message, /capacity reached/);
  override = body => [200, JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32601, message: "Method not found" } })];
  const missing = await member().getWalletSyncSnapshot(0).catch(error => error);
  assert.ok(missing instanceof RpcError && missing.code === -32601 && missing.capacityScope === undefined);
});

test("an answer that is not this request's answer is rejected", async () => {
  reset();
  const client = member();
  for (const text of [
    JSON.stringify({ jsonrpc: "2.0", id: "another", result: 1 }),
    JSON.stringify({ jsonrpc: "2.0", id: 1, result: 1, error: { code: 1 } }),
    JSON.stringify({ jsonrpc: "1.0", id: 1, result: 1 }),
    "[]",
    "not json",
  ]) {
    override = () => [200, text];
    const error = await createRpcClient({ url, accessHeader: () => "member-proof" }).getSlot().catch(error => error);
    assert.ok(error instanceof TransportError && error.kind === "response", text);
  }
  override = () => [200, "<html>", { "Content-Type": "text/html" }];
  const html = await client.getSlot().catch(error => error);
  assert.ok(html instanceof TransportError && html.kind === "response");
});

test("bounds: request size, response size and time, without a retry", async () => {
  reset();
  const client = member({ timeoutMs: 200, maxResponseBytes: 64 });
  await assert.rejects(() => client.submitShieldedPayment({ network: NETWORK, payload: "A".repeat(MAX_REQUEST_BYTES) }), RangeError);
  assert.equal(seen.length, 0, "an oversized request is never sent");
  override = body => [200, JSON.stringify({ jsonrpc: "2.0", id: body.id, result: "x".repeat(100) })];
  const large = await client.getSlot().catch(error => error);
  assert.ok(large instanceof TransportError && large.kind === "response");
  override = body => [200, JSON.stringify({ jsonrpc: "2.0", id: body.id, result: 1 }), { "Content-Type": "application/json" }, 600];
  seen = [];
  const slow = await client.submitShieldedPayment({ network: NETWORK, payload: "AAAA" }).catch(error => error);
  assert.ok(slow instanceof TransportError && slow.kind === "timeout");
  assert.equal(seen.length, 1, "a timed-out submit is not sent again");
  const closed = await createRpcClient({ url: "http://127.0.0.1:9/" }).getGenesisHash().catch(error => error);
  assert.ok(closed instanceof TransportError && closed.kind === "network");
});

test("invalid arguments are refused before any request", async () => {
  reset();
  const client = member();
  assert.throws(() => client.getWalletHistoryBlocks([]), TypeError);
  assert.throws(() => client.getWalletHistoryBlocks([3, 3]), TypeError);
  assert.throws(() => client.getWalletHistoryBlocks([0]), TypeError);
  assert.throws(() => client.getWalletHistoryBlocks(Array.from({ length: 257 }, (_, index) => index + 1)), TypeError);
  assert.throws(() => client.getShieldedPaymentStatus("AB".repeat(32)), TypeError);
  assert.throws(() => client.submitShieldedPayment({ network: NETWORK, payload: "AAAA", extra: 1 }), TypeError);
  assert.throws(() => client.getWalletReadBatch([{ method: "sendTransaction", params: [] }]), TypeError);
  assert.throws(() => client.getWalletReadBatch(Array(17).fill({ method: "getSlot", params: [{ commitment: "finalized" }] })), TypeError);
  assert.throws(() => client.getWalletRetainedHistoryV3(0, 41, { segments: 0, sha256: "0".repeat(64) }), TypeError);
  assert.throws(() => client.getWalletRetainedHistoryV3(0, 41, null, 4096), TypeError);
  assert.throws(() => client.getWalletCanonicalHistory(5, 41, null), TypeError);
  assert.throws(() => client.getWalletSyncSnapshot(-1), TypeError);
  assert.throws(() => createRpcClient({ url: "" }), TypeError);
  assert.equal(seen.length, 0);
});

test("the method list and the declaration file match their sources", () => {
  // The allow-list is copied from the gateway; fail when the two differ.
  const gatewaySource = readFileSync(new URL("../../tools/testnet_gateway.py", import.meta.url), "utf8");
  const block = gatewaySource.slice(gatewaySource.indexOf("METHODS = {"), gatewaySource.indexOf("}", gatewaySource.indexOf("METHODS = {")));
  assert.deepEqual([...block.matchAll(/"([A-Za-z0-9]+)"/g)].map(match => match[1]).sort(), [...GATEWAY_METHODS].sort());
  // rpc.d.mts is generated from rpc.mjs; fail when a client method is missing from it.
  const declarations = readFileSync(new URL("./rpc.d.mts", import.meta.url), "utf8");
  for (const name of Object.keys(createRpcClient({ url }))) assert.match(declarations, new RegExp(`\\b${name}: \\(`), name);
});
