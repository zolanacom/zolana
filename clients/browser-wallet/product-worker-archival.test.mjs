// Actual worker/RPC consumer against the actual Python archival adapter, using
// inert finalized blocks and an explicit replay-contract double; no network,
// browser storage, wallet secrets, WASM build, proof or financial operation.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
import { hintAccount } from "./product-worker-pool-fixture.mjs";

const source = await loadWorkerSource();
const tools = fileURLToPath(new URL("../../tools/", import.meta.url));
const network = { network: Array(32).fill(7), genesis_hash: "1".repeat(32) };
const hash = "1".repeat(32);
const header = slot => ({ blockhash: hash, blockHeight: slot });
const fullBlock = slot => ({ ...header(slot), parentSlot: slot - 1, previousBlockhash: hash, transactions: [] });
const unavailable = { error: "upstream_unavailable", outcome: "unknown", automatic_retry: false };
const adapter = String.raw`
import json,sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
from gateway_archival import ArchiveRPC
request=json.load(sys.stdin)
network=dict(network=[7]*32,genesis_hash='1'*32)
gateway=SimpleNamespace(info=dict(network=network,rpc_audience='https://fixture.invalid/'),faucet=SimpleNamespace(root=Path('/unused')))
reader=ArchiveRPC(gateway,'http://127.0.0.1:18899',dict(policy={}))
def forward(raw,timeout):
    query=json.loads(raw);method=query['method'];params=query.get('params',[])
    if method=='getGenesisHash':result=network['genesis_hash']
    elif method=='getBlocksWithLimit':result=list(range(params[0],params[0]+params[1]))
    elif method=='getBlock':
        slot=params[0]
        result=dict(blockhash='1'*32,previousBlockhash='1'*32,parentSlot=slot-1,blockHeight=slot,transactions=[])
    else:raise AssertionError('unexpected adapter method')
    return json.dumps(dict(jsonrpc='2.0',id=1,result=result)).encode()
gateway.forward=forward;reader.forward=forward
try:sys.stdout.buffer.write(reader.page(request))
except ValueError:print(json.dumps(dict(jsonrpc='2.0',id=request['id'],error=dict(code=-32000))))
`;
function archiveReply(request) {
  return JSON.parse(execFileSync(process.env.PYTHON || "python3", ["-B", "-c", adapter, tools],
    { input: JSON.stringify(request), encoding: "utf8", timeout: 5000 }));
}
function reply(status, value) {
  const body = new TextEncoder().encode(JSON.stringify(value)); let read = false;
  return { status, ok: status >= 200 && status < 300, headers: { get: () => "application/json" },
    body: { getReader: () => ({ read: async () => read ? { done: true } : (read = true, { done: false, value: body }), releaseLock() {} }) } };
}
function fixture({ fromGenesis = false, partial = false, mutation, failure, lock, expired = false,
  outcome = "accepted", coreBeginFailure = false, originalAnchorBug = false } = {}) {
  const calls = [], trace = [], applied = [], commits = []; let id = 0, tick = 0, pages = 0, canonicalFetches = 0;
  const target = partial ? 300 : 20;
  let context;
  context = createWorkerContext({ hintAccount, atob, btoa, TextEncoder, TextDecoder, Uint8Array, BigInt, TypeError, AbortController,
    network, target, fromGenesis, coreBeginFailure, outcome, trace, applied, commits,
    WalletStorageError: class extends Error {}, performance: { now: () => ++tick },
    self: { postMessage() {} }, setTimeout: () => 1, clearTimeout() {},
    crypto: { randomUUID: () => `archive-fixture-${++id}` },
    fetch: async (_path, options) => {
      const request = JSON.parse(options.body); calls.push(structuredClone(request));
      if (request.method === "getWalletSyncSnapshot") return reply(200, { jsonrpc: "2.0", id: request.id, result: {
        format: "zolana-wallet-sync-snapshot-v1", network, genesis: network.genesis_hash,
        pool: { context: { slot: target }, value: { ...hintAccount(), lamports: 1000 } }, target_header: header(target),
        saved_header: fromGenesis ? null : header(1), canonical_tail: null,
        fallback: fromGenesis ? "checkpoint-unavailable" : "tail-too-large" } });
      if (request.method === "getBlocks") {
        if (partial) return reply(200, { jsonrpc: "2.0", id: request.id,
          result: Array.from({ length: target - 1 }, (_, i) => i + 2) });
        return reply(200, { jsonrpc: "2.0", id: request.id, error: { code: -32000 } });
      }
      if (request.method === "getWalletHistoryBlocks") {
        if (canonicalFetches++ === 0) return reply(200, { jsonrpc: "2.0", id: request.id,
          result: request.params[0].map(slot => ({ slot, block: fullBlock(slot) })) });
        return reply(200, { jsonrpc: "2.0", id: request.id, error: { code: -32000 } });
      }
      assert.equal(request.method, "getWalletCanonicalHistory", "recovery cannot send, quote, grant, join or use retained history");
      pages++;
      if (lock === "before-response" && pages === 1) vm.runInContext("session.generation++; session.vault = undefined;", context);
      if (failure && pages === 1) {
        if (failure === "network") throw new TypeError("inert interruption");
        return reply(failure, failure === 502 ? unavailable : { error: "refused" });
      }
      if (expired && pages === 1) return reply(403, { error: "expired" });
      const response = archiveReply(request);
      if (response.result && mutation && (mutation !== "changed-second-anchor" || pages === 2)) {
        const page = response.result;
        if (mutation === "changed-anchor" || mutation === "changed-second-anchor") page.anchor.blockhash = "2".repeat(32);
        if (mutation === "changed-height") page.anchor.block_height++;
        if (mutation === "changed-target") page.anchor.slot++;
        if (mutation === "gap") page.blocks[0].block.parentSlot++;
        if (mutation === "empty") page.blocks = [];
        if (mutation === "incomplete-body") delete page.blocks[0].block.transactions;
        if (mutation === "wrong-next") page.next_slot++;
      }
      return reply(200, response);
    } });
  const workerSource = originalAnchorBug ? source.replace(
    "let anchor = { slot: target, blockhash: targetHeader.blockhash, block_height: targetHeader.blockHeight };", "let anchor = null;") : source;
  vm.runInContext(`${workerSource}
    configuration = { network, label: "fixture", environment: "testnet" };
    transport = { program: hintAccount().owner, pool: "1".repeat(32), rpc_audience: "https://fixture.invalid/" };
    let slot = 1, pinned, begun = false;
    const originalCheckpoint = new Uint8Array([1]), originalPacket = new Uint8Array([9]);
    session.store = {
      snapshot: async () => ({ revision: 7, encryptedCheckpoint: originalCheckpoint,
        pending: { packetId: "a".repeat(64), encryptedPacket: originalPacket } }),
      commitCheckpoint: async () => { throw new Error("pending recovery cannot replace its checkpoint alone"); },
      settlePending: async value => { commits.push(value); trace.push("settle"); }
    };
    function applyBlocks(blocks) {
      for (const block of blocks) {
        const body = block.block || block;
        const parent = body.parentSlot ?? body.parent_slot;
        const previous = body.previousBlockhash ?? body.previous_blockhash;
        const height = body.blockHeight ?? body.block_height;
        if (block.slot !== slot + 1 || parent !== slot || previous !== "1".repeat(32) ||
            height !== block.slot || !Array.isArray(body.transactions)) throw new Error("replay contract: incomplete block");
        slot = block.slot;
      }
    }
    session.vault = {
      identity: () => "{}", rpc_header: () => { if (!begun && trace.includes("begin")) throw new Error("invalid core session"); return "fixture-access"; },
      checkpoint_info: () => '{"slot":1}',
      validate_pending_checkpoint: (packet, checkpoint) => {
        if (packet !== originalPacket || checkpoint !== originalCheckpoint) throw new Error("original reservation changed");
        trace.push("validate_pending");
      },
      begin_sync: (pool, header, checkpoint) => {
        trace.push("begin");
        if (coreBeginFailure) throw new Error("core rejected finalized target");
        pinned = { slot: JSON.parse(pool).context.slot, blockhash: JSON.parse(header).blockhash, block_height: JSON.parse(header).blockHeight };
        if (pinned.slot !== target || pinned.block_height !== target || pinned.blockhash !== "1".repeat(32)) throw new Error("target substitution");
        slot = checkpoint.length ? 1 : 0; begun = true;
        return JSON.stringify({ slot, target });
      },
      apply_compact_history_page: () => { throw new Error("pending recovery cannot use retained ciphertext"); },
      apply_canonical_blocks: text => { trace.push("canonical"); applyBlocks(JSON.parse(text)); return JSON.stringify({ slot, target }); },
      apply_archival_page: text => {
        if (!begun) throw new Error("archive before core target verification");
        const page = JSON.parse(text); trace.push("archive");
        if (JSON.stringify(page.anchor) !== JSON.stringify(pinned) || page.after_slot !== slot ||
            page.blocks.length < 1 || page.blocks.length > 16 ||
            page.next_slot !== page.blocks.at(-1)?.slot || page.complete !== (page.next_slot === target)) throw new Error("replay contract: changed anchor or cursor");
        applyBlocks(page.blocks); applied.push(slot); return JSON.stringify({ slot, target });
      },
      finish_sync: () => { trace.push("finish"); if (slot !== target) throw new Error("incomplete finalized target"); return new Uint8Array([2]); },
      pending_outcome: () => { trace.push("outcome"); return JSON.stringify({ packet_id: "a".repeat(64), decision: outcome, encrypted_receipt: [8] }); },
      payment_status: () => JSON.stringify({ verified: true, balance: "20", max_payment: "20", slot })
    };
    checkAccess = async () => { session.admission = { admitted: true, state: "active", accessUntil: 1234 }; };
    core = async () => ({});
    globalThis.sync = syncWallet;
    globalThis.cancel = () => { session.generation++; };
  `, context);
  if (lock === "before-fetch") {
    // A lock arriving while the core module is awaited must stop before even
    // the first archive read, through syncWallet's existing assertSession.
    vm.runInContext("core = async () => { session.generation++; return {}; };", context);
  }
  return { context, calls, trace, applied, commits, target };
}
const archiveCalls = f => f.calls.filter(row => row.method === "getWalletCanonicalHistory");
function noFinancialRetry(f) {
  assert(f.calls.every(row => ["getWalletSyncSnapshot", "getBlocks", "getWalletHistoryBlocks", "getWalletCanonicalHistory"].includes(row.method)));
  assert(!f.trace.includes("reserve"));
}

// Regression witness: old code fails its first nonzero-cursor request under the
// unchanged real gateway contract, rather than relying on a permissive RPC stub.
{
  const f = fixture({ originalAnchorBug: true });
  await assert.rejects(f.context.sync(), error => error.code === "rpc");
  assert.deepEqual(archiveCalls(f).map(row => row.params), [[1, 20, null]]);
  assert.equal(f.commits.length, 0);
}
for (const options of [{ fromGenesis: true }, {}, { partial: true }, { outcome: "expired-absent" }]) {
  const f = fixture(options); await f.context.sync();
  const pages = archiveCalls(f);
  assert.equal(pages[0].params[0], options.fromGenesis ? 0 : options.partial ? 257 : 1);
  for (const page of pages) assert.deepEqual(page.params[2], { slot: f.target, blockhash: hash, block_height: f.target });
  assert.equal(f.applied.at(-1), f.target); assert.equal(f.commits.length, 1);
  assert(f.trace.indexOf("begin") < f.trace.indexOf("archive"));
  assert(f.trace.indexOf("finish") < f.trace.indexOf("outcome"));
  assert(f.trace.indexOf("outcome") < f.trace.indexOf("settle"));
  noFinancialRetry(f);
}
for (const mutation of ["changed-anchor", "changed-height", "changed-target", "changed-second-anchor", "gap", "empty", "incomplete-body", "wrong-next"]) {
  const f = fixture({ mutation }); await assert.rejects(f.context.sync());
  assert.equal(f.commits.length, 0); assert(!f.trace.includes("finish"));
  assert.equal(archiveCalls(f).length, mutation === "changed-second-anchor" ? 2 : 1);
  noFinancialRetry(f);
}
for (const failure of [502, 500, "network"]) {
  const f = fixture({ failure }); await assert.rejects(f.context.sync());
  assert.equal(archiveCalls(f).length, 1); assert.equal(f.commits.length, 0);
  assert.deepEqual(f.applied, []); noFinancialRetry(f);
}
for (const options of [{ lock: "before-fetch" }, { lock: "before-response" }, { expired: true }, { coreBeginFailure: true }, { outcome: "unknown" }]) {
  const f = fixture(options); await assert.rejects(f.context.sync(), error => options.lock ? error.code === "locked" : true);
  assert.equal(f.commits.length, 0); noFinancialRetry(f);
  if (options.lock === "before-fetch" || options.coreBeginFailure) assert.equal(archiveCalls(f).length, 0);
  if (options.lock === "before-response" || options.expired) {
    assert.equal(archiveCalls(f).length, 1); assert.deepEqual(f.applied, []);
  }
}
console.log("PASS: actual worker uses the core-pinned finalized anchor on first genesis/checkpoint/partial-tail archive request; actual unchanged Python adapter accepts valid cursors; changed/incomplete pages, first-read failures, lock, expired access and unknown outcomes preserve the reservation without fallback or financial retry.");
