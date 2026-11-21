// The wallet worker's network pin against a local gateway on another network.
//
// The worker's own transport code talks HTTP to a loopback server. That server
// answers with the configuration and transport documents the Python browser
// gateway produces for a profile, and with a scripted RPC. The pin module is
// the output of tools/browser_wallet_pin.py. Vault and store are inert doubles:
// no Wasm, no browser storage, no wallet secret and no chain are involved.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, webcrypto } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource, sendWorkerMessage } from "./product-worker-harness.mjs";
import { hintAccount } from "./product-worker-pool-fixture.mjs";

const source = await loadWorkerSource();
const tools = fileURLToPath(new URL("../../tools/", import.meta.url));
const pinned = { network: Array(32).fill(7), genesis_hash: "1".repeat(32) };
const other = { network: Array(32).fill(9), genesis_hash: "2".repeat(32) };

// What the real gateway serves for a profile of each network, and the pin
// module the build tool writes for the pinned one.
const prepared = JSON.parse(execFileSync(process.env.PYTHON || "python3", ["-B", "-c", String.raw`
import json,sys
sys.path.insert(0,sys.argv[1])
import browser_gateway as gateway
import browser_wallet_pin as pin
def served(network):
    profile=dict(format="native-wallet-profile-v1",key_mode="user-wallet-v1",network=network["network"],
        genesis_hash=network["genesis_hash"],label="Local fixture",invite_required=True,program="7"*32,pool="8"*32,
        pool_format="NPOOL004",private_send_transport="native-inline-v1",
        rpc=dict(transport="loopback-http",url="http://127.0.0.1:9/"),
        faucet=dict(transport="loopback-http",url="http://127.0.0.1:9/"),
        access_audiences=dict(format="native-access-audiences-v1",**network,
            rpc="https://rpc.fixture.invalid/",faucet="https://admission.fixture.invalid/"))
    app=gateway.BrowserGateway(profile,{},fixture_http=True)
    try:return dict(config=app.config(),transport=app.transport())
    finally:app.close()
request=json.load(sys.stdin)
print(json.dumps(dict(pinned=served(request["pinned"]),other=served(request["other"]),
    module=pin.render(request["pinned"],"testnet").decode(),
    mainnet_module=pin.render(request["pinned"],"mainnet").decode())))
`, tools], { input: JSON.stringify({ pinned, other }), encoding: "utf8", timeout: 20000 }));

const directory = await mkdtemp(join(tmpdir(), "zolana-network-pin-"));
test.after(() => rm(directory, { recursive: true, force: true }));
await writeFile(join(directory, "package.json"), '{"type":"module"}\n');
async function pinModule(name, text) {
  await writeFile(join(directory, name), text);
  const location = pathToFileURL(join(directory, name)).href;
  return async () => (await import(location)).default;
}
const loadPinned = await pinModule("network-pin.js", prepared.module);
const loadMainnet = await pinModule("network-pin-mainnet.js", prepared.mainnet_module);

const header = slot => ({ blockhash: "1".repeat(31) + String(slot + 1), blockHeight: slot });
function snapshot(network) {
  return { format: "zolana-wallet-sync-snapshot-v1", network, genesis: network.genesis_hash,
    pool: { context: { slot: 1 }, value: { ...hintAccount(), owner: prepared.pinned.transport.program, lamports: 1000 } },
    target_header: header(1), saved_header: null,
    canonical_tail: { after_slot: 0, target_slot: 1, next_slot: 1, complete: true,
      blocks: [{ slot: 1, block: { ...header(1), parentSlot: 0, previousBlockhash: header(0).blockhash, transactions: [] } }] },
    fallback: null };
}

// A loopback gateway. `documents` are the served configuration and transport;
// `genesis` is what its RPC reports; `snapshotNetwork` is the network inside
// its sync snapshot.
async function gateway({ documents, genesis, snapshotNetwork = pinned }) {
  const seen = [];
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => {
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null;
      seen.push({ method: request.method, path: request.url, rpc: body?.method ?? null, access: request.headers["x-testnet-access"] ?? null });
      let value;
      if (request.method === "GET" && request.url === "/wallet-config.json") value = documents.config;
      else if (request.method === "GET" && request.url === "/transport.json") value = documents.transport;
      else if (request.method === "POST" && request.url === "/rpc" && body.method === "getGenesisHash") value = { jsonrpc: "2.0", id: body.id, result: genesis };
      else if (request.method === "POST" && request.url === "/rpc" && body.method === "getWalletSyncSnapshot") value = { jsonrpc: "2.0", id: body.id, result: snapshot(snapshotNetwork) };
      else if (request.method === "POST" && request.url === "/rpc") value = { jsonrpc: "2.0", id: body.id, error: { code: -32000 } };
      else if (request.method === "POST" && request.url.startsWith("/admission/")) value = { admitted: true };
      else { response.writeHead(404, { "Content-Type": "application/json" }).end('{"error":"not_found"}'); return; }
      response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(value));
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return { origin: `http://127.0.0.1:${server.address().port}`, seen,
    rpc: () => seen.filter(item => item.path === "/rpc").map(item => [item.rpc, item.access]),
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}

// The worker with its real transport, pointed at one gateway origin.
function wallet(origin, loadPin) {
  const responses = [], opened = [], writes = [], trace = [];
  const context = createWorkerContext({
    TypeError, URL, atob, btoa, crypto: webcrypto, performance: { now: () => 0 }, responses, opened, writes, trace, loadPin,
    WalletStorageError: class extends Error {},
    walletDatabaseName: (walletId, networkId) => `zolana-browser-wallet-${networkId}-${walletId}`,
    indexedDB: { open(name) {
      opened.push(name);
      const request = { result: { objectStoreNames: ["wallets"], close() {} } };
      queueMicrotask(() => request.onsuccess());
      return request;
    } },
    fetch: (path, options) => fetch(new URL(path, origin), options),
    self: { isSecureContext: true, postMessage: value => responses.push(value) },
  });
  vm.runInContext(`${source}
    if (loadPin) loadNetworkPin = loadPin;
    readRecord = async () => null; core = async () => ({});
    globalThis.inspect = () => ({ initialized: !!configuration, network: configuration?.network, environment: configuration?.environment,
      label: configuration?.label, networkId, networkJson, catalog: !!catalog, transport: !!transport });
    globalThis.adoptDoubles = () => {
      let slot = 0, target = 0;
      session.adopt({
        identity: () => "{}", rpc_header: () => "fixture-access", lock() {}, free() {},
        admission_status: () => { trace.push("signed-status"); return "{}"; },
        admission_request: () => { trace.push("signed-join"); return "{}"; }, admission_claim_id: () => "fixture",
        checkpoint_info: () => '{"slot":0}',
        begin_sync: pool => { trace.push("begin"); target = JSON.parse(pool).context.slot; return JSON.stringify({ slot, target }); },
        apply_compact_history_page: () => { trace.push("retained"); slot = target; return JSON.stringify({ slot, target }); },
        apply_canonical_blocks: text => { trace.push("canonical"); slot = JSON.parse(text).at(-1).slot; return JSON.stringify({ slot, target }); },
        finish_sync: () => { trace.push("finish"); return new Uint8Array([2]); },
        payment_status: () => JSON.stringify({ verified: true, balance: "0", max_payment: "0", slot }),
      }, {
        snapshot: async () => ({ revision: 0, encryptedCheckpoint: null, pending: null }), close() {},
        commitCheckpoint: async () => { writes.push("commitCheckpoint"); },
        settlePending: async () => { writes.push("settlePending"); },
        reservePending: async () => { writes.push("reservePending"); },
      }, session.generation);
    };
  `, context);
  const send = async (action, parameters = {}) => {
    await sendWorkerMessage(context, { id: action, action, ...parameters });
    return responses.findLast(item => item.id === action && typeof item.ok === "boolean");
  };
  // As the page does: read the configuration the site serves, then hand it to the worker.
  const start = async () => send("initialize", { configuration: await (await fetch(`${origin}/wallet-config.json`)).json() });
  return { context, responses, opened, writes, trace, send, start, inspect: () => context.inspect() };
}

async function withGateway(options, action) {
  const site = await gateway(options);
  try { await action(site); } finally { await site.close(); }
}

test("a gateway configured for another network is refused at start, before any storage is opened", async () => {
  await withGateway({ documents: prepared.other, genesis: other.genesis_hash, snapshotNetwork: other }, async site => {
    const f = wallet(site.origin, loadPinned), started = await f.start();
    assert.equal(started.ok, false);
    assert.equal(started.code, "network_mismatch");
    assert.match(started.error, /different network than the one this wallet build is pinned to/);
    assert.deepEqual(f.opened, [], "no wallet catalog or database is opened for the other network");
    assert.equal(f.inspect().initialized, false);
    assert.equal(f.inspect().catalog, false);
    for (const action of ["create", "unlock", "sync", "status"]) assert.equal((await f.send(action, { password: new Uint8Array(12).fill(1) })).code, "uninitialized");
    assert.deepEqual(site.seen.map(item => item.path), ["/wallet-config.json"], "the worker sent nothing to the other network's gateway");
    assert.deepEqual(f.writes, []);
  });
});

test("a gateway that copies the pinned identity but reports another genesis is refused before sync", async () => {
  await withGateway({ documents: prepared.pinned, genesis: other.genesis_hash, snapshotNetwork: other }, async site => {
    const f = wallet(site.origin, loadPinned);
    assert.equal((await f.start()).ok, true);
    f.context.adoptDoubles();
    for (const [action, parameters] of [["sync", {}], ["automatic_sync", {}], ["check_access", {}], ["payment_hint", {}],
      ["join", { invitation: `invite1_${"A".repeat(43)}` }]]) {
      const reply = await f.send(action, parameters);
      assert.equal(reply.ok, false, action);
      assert.equal(reply.code, "genesis", action);
      assert.match(reply.error, /different network than the one this wallet build is pinned to/);
      assert.notEqual(reply.retryableRead, true, "a different network is not retried as a connection problem");
    }
    // Each attempt asked only which network the gateway serves, without the wallet's access proof.
    assert.deepEqual(site.rpc(), Array(5).fill(["getGenesisHash", null]));
    assert(site.seen.every(item => !item.path.startsWith("/admission/")), "no membership or invitation request was sent");
    assert.deepEqual(f.trace, [], "no signed request was built and the wallet core never began a sync");
    assert.deepEqual(f.writes, [], "nothing was written to wallet storage");
    assert.equal(f.inspect().transport, false, "the gateway is asked again before any later use");
  });
});

test("a gateway that changes network after the first check is refused at the sync snapshot", async () => {
  await withGateway({ documents: prepared.pinned, genesis: pinned.genesis_hash, snapshotNetwork: other }, async site => {
    const f = wallet(site.origin, loadPinned);
    assert.equal((await f.start()).ok, true);
    f.context.adoptDoubles();
    const reply = await f.send("sync");
    assert.equal(reply.code, "genesis");
    assert.match(reply.error, /different network than the one this wallet build is pinned to/);
    assert.deepEqual(site.rpc(), [["getGenesisHash", null], ["getWalletSyncSnapshot", "fixture-access"]]);
    assert.deepEqual(f.trace, [], "the wallet core never began a sync");
    assert.deepEqual(f.writes, []);
  });
  // Only the genesis string differs: still named as another network, not as a malformed reply.
  await withGateway({ documents: prepared.pinned, genesis: pinned.genesis_hash,
    snapshotNetwork: { network: pinned.network, genesis_hash: other.genesis_hash } }, async site => {
    const f = wallet(site.origin, loadPinned);
    assert.equal((await f.start()).ok, true);
    f.context.adoptDoubles();
    assert.equal((await f.send("sync")).code, "genesis");
    assert.deepEqual(f.trace, []); assert.deepEqual(f.writes, []);
  });
});

test("a transport description for another network is refused before any RPC", async () => {
  await withGateway({ documents: { config: prepared.pinned.config, transport: prepared.other.transport }, genesis: pinned.genesis_hash }, async site => {
    const f = wallet(site.origin, loadPinned);
    assert.equal((await f.start()).ok, true);
    f.context.adoptDoubles();
    const reply = await f.send("sync");
    assert.equal(reply.code, "network_mismatch");
    assert.deepEqual(site.rpc(), []);
    assert.deepEqual(f.trace, []); assert.deepEqual(f.writes, []);
  });
});

test("a gateway that cannot say which network it serves is not synced against", async () => {
  await withGateway({ documents: prepared.pinned, genesis: null }, async site => {
    const f = wallet(site.origin, loadPinned);
    assert.equal((await f.start()).ok, true);
    f.context.adoptDoubles();
    assert.equal((await f.send("sync")).code, "rpc");
    assert.deepEqual(site.rpc(), [["getGenesisHash", null]]);
    assert.deepEqual(f.trace, []); assert.deepEqual(f.writes, []);
  });
});

test("the pinned network syncs as before and keeps the stored wallet's identifiers", async () => {
  await withGateway({ documents: prepared.pinned, genesis: pinned.genesis_hash }, async site => {
    const f = wallet(site.origin, loadPinned), started = await f.start();
    assert.equal(started.ok, true);
    assert.equal(started.result.label, "Local fixture");
    assert.equal(started.result.environment, "testnet");
    // The catalog key and database names derive from this exact text. It is the
    // text the worker hashed before the pin existed, so a saved wallet is found.
    const legacy = `["zolana-browser-product-network-v1",{"network":[${pinned.network.join(",")}],"genesis_hash":"${pinned.genesis_hash}"}]`;
    assert.equal(f.inspect().networkId, createHash("sha256").update(legacy).digest("hex"));
    assert.equal(f.inspect().networkJson, `{"network":[${pinned.network.join(",")}],"genesis_hash":"${pinned.genesis_hash}"}`);
    assert.deepEqual(f.opened, ["zolana-browser-product-v1"]);
    f.context.adoptDoubles();
    const reply = await f.send("sync");
    assert.equal(reply.ok, true, reply.error);
    assert.equal(reply.result.authoritativeSync, true);
    assert.deepEqual(f.trace, ["begin", "canonical", "finish"]);
    assert.deepEqual(f.writes, ["commitCheckpoint"]);
    assert.deepEqual(site.rpc(), [["getGenesisHash", null], ["getWalletSyncSnapshot", "fixture-access"]]);
    // The gateway is asked for its genesis once per worker, not once per sync.
    assert.equal((await f.send("sync")).ok, true);
    assert.deepEqual(site.rpc().map(item => item[0]), ["getGenesisHash", "getWalletSyncSnapshot", "getWalletSyncSnapshot"]);
  });
});

test("a build pinned to another environment refuses a testnet gateway", async () => {
  await withGateway({ documents: prepared.pinned, genesis: pinned.genesis_hash }, async site => {
    const f = wallet(site.origin, loadMainnet), started = await f.start();
    assert.equal(started.code, "network_mismatch");
    assert.deepEqual(f.opened, []);
  });
});

test("a bundle with no pin, or a malformed one, opens no wallet", async () => {
  const valid = { format: "zolana-browser-network-pin-v1", environment: "testnet", network: pinned };
  const cases = [
    undefined, // the module is missing: the worker's own import fails here
    async () => { throw new Error("module not found"); },
    async () => null,
    async () => ({ ...valid, format: "zolana-browser-network-pin-v0" }),
    async () => ({ ...valid, environment: "devnet" }),
    async () => ({ ...valid, extra: true }),
    async () => ({ format: valid.format, environment: valid.environment }),
    async () => ({ ...valid, network: { ...pinned, network: Array(32).fill(0) } }),
    async () => ({ ...valid, network: { ...pinned, network: Array(31).fill(7) } }),
    async () => ({ ...valid, network: { ...pinned, genesis_hash: "0".repeat(32) } }),
    async () => ({ ...valid, network: { ...pinned, label: "extra" } }),
  ];
  await withGateway({ documents: prepared.pinned, genesis: pinned.genesis_hash }, async site => {
    for (const loadPin of cases) {
      const f = wallet(site.origin, loadPin), started = await f.start();
      assert.equal(started.ok, false);
      assert.equal(started.code, "network_pin");
      assert.match(started.error, /network pin is missing or invalid/);
      assert.deepEqual(f.opened, []);
      assert.equal(f.inspect().initialized, false);
    }
    assert(site.seen.every(item => item.path === "/wallet-config.json"));
  });
});

test("the build tool's module is the pin the worker accepts", async () => {
  const value = await loadPinned();
  assert.deepEqual(JSON.parse(JSON.stringify(value)), { environment: "testnet", format: "zolana-browser-network-pin-v1",
    network: { genesis_hash: pinned.genesis_hash, network: pinned.network } });
  assert(Object.isFrozen(value));
  assert.match(prepared.module, /^\/\/ Network pin of this browser wallet bundle/);
});
