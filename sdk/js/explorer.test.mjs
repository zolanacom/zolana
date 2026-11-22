// Runs with `node --test sdk/js/*.test.mjs`. Offline. Uses the sample feeds in
// clients/devnet-explorer and starts python3 once to ask the repository's own feed check
// (validate_feed in tools/devnet_explorer/explorer_pull_v0.py) about the same documents,
// so the JavaScript check and the Python check cannot drift apart unnoticed.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { EXPLORER_FEED_FORMAT, FeedError, findTransaction, MAX_FEED_BLOCKS, MAX_FEED_TRANSACTIONS, validateExplorerFeed } from "./explorer.mjs";

const read = name => readFileSync(new URL(`../../clients/devnet-explorer/${name}`, import.meta.url), "utf8");
const sample = () => JSON.parse(read("feed.sample.json"));
const accepts = document => { try { validateExplorerFeed(document); return true; } catch (error) { assert.ok(error instanceof FeedError, String(error)); return false; } };

/** Asks the Python check about each document; returns one boolean per document. */
function pythonAccepts(documents) {
  const script = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import explorer_pull_v0 as puller",
    "def accepted(document):",
    "    try:",
    "        puller.validate_feed(document)",
    "        return True",
    "    except puller.PullError:",
    "        return False",
    "print(json.dumps([accepted(document) for document in json.load(sys.stdin)]))",
  ].join("\n");
  const tools = fileURLToPath(new URL("../../tools/devnet_explorer", import.meta.url));
  const run = spawnSync("python3", ["-I", "-B", "-c", script, tools], { input: JSON.stringify(documents), encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  assert.equal(run.status, 0, run.stderr);
  return JSON.parse(run.stdout);
}

// [description, change applied to a copy of the sample, whether the contract still accepts it]
const CHANGES = [
  ["unchanged", () => {}, true],
  ["another format", feed => { feed.format = "zolana-explorer-feed-v1"; }, false],
  ["an unknown top-level key", feed => { feed.extra = 1; }, false],
  ["a missing top-level key", feed => { delete feed.stats; }, false],
  ["a feed that is a list", () => [], false],
  ["no genesis hash yet", feed => { feed.genesis_hash = null; }, true],
  ["a genesis hash with punctuation", feed => { feed.genesis_hash = "<b>"; }, false],
  ["a string of 127 characters", feed => { feed.genesis_hash = "a".repeat(127); }, true],
  ["a string of 128 characters", feed => { feed.genesis_hash = "a".repeat(128); }, false],
  ["a negative generation time", feed => { feed.generated_at = -1; }, false],
  ["a fractional generation time", feed => { feed.generated_at += 0.5; }, false],
  ["a generation time as text", feed => { feed.generated_at = String(feed.generated_at); }, false],
  ["an integer of 2**53", feed => { feed.generated_at = 2 ** 53; }, false],
  ["the largest integer", feed => { feed.generated_at = 2 ** 53 - 1; }, true],
  ["an unknown network status", feed => { feed.network.status = "paused"; }, false],
  ["the status unavailable", feed => { feed.network.status = "unavailable"; }, true],
  ["no slots known", feed => { Object.assign(feed.network, { tip_slot: null, finalized_slot: null, block_height: null, slot_time_ms: null, last_block_at: null }); }, true],
  ["a fractional slot time", feed => { feed.network.slot_time_ms = 402.6; }, true],
  ["a negative slot time", feed => { feed.network.slot_time_ms = -0.5; }, false],
  ["a slot time as a boolean", feed => { feed.network.slot_time_ms = true; }, false],
  ["a slot time of 2**53", feed => { feed.network.slot_time_ms = 2 ** 53; }, false],
  ["a fractional finalized slot", feed => { feed.network.finalized_slot = 1.5; }, false],
  ["an unknown network key", feed => { feed.network.rpc = "x"; }, false],
  ["validators that are not a list", feed => { feed.network.validators = {}; }, false],
  ["a validator without a vote account", feed => { feed.network.validators[0].vote_account = null; feed.network.validators[0].last_vote = null; }, true],
  ["a validator without an identity", feed => { feed.network.validators[0].identity = null; }, false],
  ["a validator whose active flag is a number", feed => { feed.network.validators[0].active = 1; }, false],
  ["no blocks and no transactions", feed => { feed.blocks = []; feed.transactions = []; }, true],
  ["one block more than the limit", feed => { feed.blocks.push({ ...feed.blocks[0] }); }, false],
  ["a block without a parent slot", feed => { feed.blocks[0].parent_slot = null; feed.blocks[0].block_time = null; feed.blocks[0].block_height = null; }, true],
  ["a block without a slot", feed => { feed.blocks[0].slot = null; }, false],
  ["a block with an extra key", feed => { feed.blocks[0].leader = "x"; }, false],
  ["a block missing a key", feed => { delete feed.blocks[3].tx_count; }, false],
  ["a block that is a list", feed => { feed.blocks[1] = []; }, false],
  ["a transaction of another kind", feed => { feed.transactions[0].kind = "transfer"; }, false],
  ["a vote transaction", feed => { feed.transactions[0].kind = "vote"; }, true],
  ["a failed transaction", feed => { feed.transactions[0].ok = false; }, true],
  ["a transaction whose ok flag is text", feed => { feed.transactions[0].ok = "true"; }, false],
  ["a transaction with a negative fee", feed => { feed.transactions[0].fee = -1; }, false],
  ["a transaction without a signature", feed => { feed.transactions[0].signature = null; }, false],
  ["a transaction with a memo key", feed => { feed.transactions[0].memo = "x"; }, false],
  ["more transactions than the limit", feed => { while (feed.transactions.length <= MAX_FEED_TRANSACTIONS) feed.transactions.push({ ...feed.transactions[0] }); }, false],
  ["stats with a missing counter", feed => { delete feed.stats.since; }, false],
  ["stats with a null counter", feed => { feed.stats.blocks_seen = null; }, false],
];
const changed = () => CHANGES.map(([, change]) => { const feed = sample(); return change(feed) ?? feed; });

test("the sample feeds follow the contract, in JavaScript and in the Python check", () => {
  const documents = [sample(), JSON.parse(read("feed.paused.json"))];
  assert.deepEqual(documents.map(accepts), [true, true]);
  assert.deepEqual(pythonAccepts(documents), [true, true]);
  const feed = validateExplorerFeed(documents[0]);
  assert.equal(feed.format, EXPLORER_FEED_FORMAT);
  assert.equal(feed.blocks.length, MAX_FEED_BLOCKS);
  assert.ok(feed.transactions.length > 0 && feed.transactions.length <= MAX_FEED_TRANSACTIONS);
});

test("every change to the sample is accepted or refused by both checks alike", () => {
  const documents = changed();
  const javascript = documents.map(accepts);
  assert.deepEqual(javascript, CHANGES.map(([, , accepted]) => accepted), CHANGES.filter((item, index) => item[2] !== javascript[index]).map(item => item[0]).join("; "));
  const python = pythonAccepts(documents);
  assert.deepEqual(python, javascript, CHANGES.filter((_, index) => python[index] !== javascript[index]).map(item => item[0]).join("; "));
  assert.ok(CHANGES.filter(item => item[2]).length >= 10 && CHANGES.filter(item => !item[2]).length >= 25);
});

test("a refusal names the field", () => {
  const feed = sample();
  feed.transactions[2].fee = "5000";
  assert.throws(() => validateExplorerFeed(feed), error => error instanceof FeedError && error.path === "transactions[2].fee" && /must be an integer/.test(error.message));
  assert.throws(() => validateExplorerFeed(null), error => error instanceof FeedError && error.path === "feed");
  const missing = sample();
  delete missing.network.tip_slot;
  assert.throws(() => validateExplorerFeed(missing), /network is missing key tip_slot/);
});

test("a signature is found with its slot, its outcome and its place against the finalized slot", () => {
  const feed = validateExplorerFeed(sample());
  const finalized = feed.network.finalized_slot;
  const above = feed.transactions.find(item => item.slot > finalized), below = feed.transactions.find(item => item.slot <= finalized);
  assert.ok(above && below, "the sample holds transactions on both sides of the finalized slot");
  const found = findTransaction(feed, above.signature);
  assert.deepEqual([found.transaction, found.atOrBelowFinalized], [above, false]);
  assert.equal(found.block?.slot, above.slot);
  assert.equal(findTransaction(feed, below.signature).atOrBelowFinalized, true);
  // Only the whole signature matches, and absence is reported as absence.
  assert.equal(findTransaction(feed, above.signature.slice(0, 20)), null);
  assert.equal(findTransaction(feed, "1".repeat(64)), null);
  // A feed that knows no finalized slot cannot place the transaction.
  feed.network.finalized_slot = null;
  assert.equal(findTransaction(feed, above.signature).atOrBelowFinalized, null);
  // A transaction whose block has left the block window is still reported.
  feed.blocks = [];
  assert.equal(findTransaction(feed, above.signature).block, null);
});
