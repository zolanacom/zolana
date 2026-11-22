// Runs with `node --test sdk/js/*.test.mjs`. Offline. Uses the sample feeds in
// clients/devnet-explorer and starts python3 once to ask the repository's own feed check
// (validate_feed in tools/devnet_explorer/explorer_pull_v0.py) about the same documents,
// so the JavaScript check and the Python check cannot drift apart unnoticed.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PROGRAM_ID, toBase58 } from "./formats.mjs";
import { EXPLORER_FEED_FORMAT, FeedError, findTransaction, marksPayments, MAX_FEED_BLOCKS, MAX_FEED_TRANSACTIONS, PAYMENT_INSTRUCTIONS, paymentStep, validateExplorerFeed } from "./explorer.mjs";

const read = name => readFileSync(new URL(`../../clients/devnet-explorer/${name}`, import.meta.url), "utf8");
const sample = () => JSON.parse(read("feed.sample.json"));
// The same window in the shape that marks payment-program transactions.
const marked = () => JSON.parse(read("feed.payments.json"));
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

/** Asks the feed service (tools/devnet_explorer/explorer_feed_v0.py) for the rows it writes for one getBlock reply. */
function serviceRows(slot, block, voteAccounts) {
  const script = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import explorer_feed_v0 as service",
    "slot, block, accounts = json.load(sys.stdin)",
    "parsed = service.parse_block(slot, block)",
    "print(json.dumps({'block': parsed.row, 'transactions': service.select_transactions(parsed.program, parsed.votes),",
    "                  'validators': service.parse_validators(accounts)}))",
  ].join("\n");
  const tools = fileURLToPath(new URL("../../tools/devnet_explorer", import.meta.url));
  const run = spawnSync("python3", ["-I", "-B", "-c", script, tools], { input: JSON.stringify([slot, block, voteAccounts]), encoding: "utf8" });
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
const changed = (make = sample) => CHANGES.map(([, change]) => { const feed = make(); return change(feed) ?? feed; });

// The same triples for the fields of a feed that marks payment-program transactions,
// applied to a copy of feed.payments.json. Block 3 holds 5 transactions, 1 of them of the
// payment program, which executed a payment.
const MARKED_CHANGES = [
  ["unchanged", () => {}, true],
  ["a validator without a root slot", feed => { feed.network.validators[0].root_slot = null; }, true],
  ["a validator missing its root slot key", feed => { delete feed.network.validators[0].root_slot; }, false],
  ["a root slot as text", feed => { feed.network.validators[0].root_slot = "12"; }, false],
  ["a negative root slot", feed => { feed.network.validators[0].root_slot = -1; }, false],
  ["a block the service read without its instructions", feed => { feed.blocks[3].payment_tx_count = null; feed.blocks[3].executed_payment_count = null; }, true],
  ["a block with one payment count only", feed => { feed.blocks[3].payment_tx_count = null; }, false],
  ["a block with the other payment count only", feed => { feed.blocks[3].executed_payment_count = null; }, false],
  ["a block missing a payment count key", feed => { delete feed.blocks[3].executed_payment_count; }, false],
  ["more payments executed than payment transactions", feed => { feed.blocks[3].executed_payment_count = 2; }, false],
  ["more payment transactions than transactions", feed => { feed.blocks[3].payment_tx_count = 6; }, false],
  ["every transaction of a block a payment that executed", feed => { feed.blocks[3].payment_tx_count = 5; feed.blocks[3].executed_payment_count = 5; }, true],
  ["a payment count as text", feed => { feed.blocks[3].payment_tx_count = "1"; }, false],
  ["a fractional payment count", feed => { feed.blocks[3].executed_payment_count = 0.5; }, false],
  ["a payment count as a boolean", feed => { feed.blocks[3].executed_payment_count = true; }, false],
  ["a transaction the feed does not mark", feed => { feed.transactions[0].payment_instructions = null; }, true],
  ["a transaction missing its mark key", feed => { delete feed.transactions[0].payment_instructions; }, false],
  ["a transaction of no payment instruction", feed => { feed.transactions[0].payment_instructions = []; }, true],
  ["every instruction name, in order", feed => { feed.transactions[0].payment_instructions = [...PAYMENT_INSTRUCTIONS]; }, true],
  ["instruction names out of order", feed => { feed.transactions[0].payment_instructions = ["close", "finalize"]; }, false],
  ["an instruction named twice", feed => { feed.transactions[0].payment_instructions = ["write", "write"]; }, false],
  ["an instruction name the contract does not know", feed => { feed.transactions[0].payment_instructions = ["deposit"]; }, false],
  ["an instruction name in another case", feed => { feed.transactions[0].payment_instructions = ["Finalize"]; }, false],
  ["an opcode in place of a name", feed => { feed.transactions[0].payment_instructions = [3]; }, false],
  ["a null in place of a name", feed => { feed.transactions[0].payment_instructions = [null]; }, false],
  ["a nested list of names", feed => { feed.transactions[0].payment_instructions = [["finalize"]]; }, false],
  ["a mark that is a string", feed => { feed.transactions[0].payment_instructions = "finalize"; }, false],
  ["a mark that is an object", feed => { feed.transactions[0].payment_instructions = { finalize: true }; }, false],
  ["a mark that is false", feed => { feed.transactions[0].payment_instructions = false; }, false],
  ["more names than there are", feed => { feed.transactions[0].payment_instructions = [...PAYMENT_INSTRUCTIONS, "unknown"]; }, false],
  ["stats missing one payment counter", feed => { delete feed.stats.payments_since; }, false],
  ["stats with a null payment counter", feed => { feed.stats.payment_transactions_seen = null; }, false],
  ["stats with a negative payment counter", feed => { feed.stats.executed_payments_seen = -1; }, false],
  ["more payments executed than payment transactions seen", feed => { feed.stats.executed_payments_seen = 15; }, false],
  ["payment counters at zero", feed => { feed.stats.payment_transactions_seen = 0; feed.stats.executed_payments_seen = 0; }, true],
  ["stats without any payment counter while the rows carry marks", feed => { delete feed.stats.payments_since; delete feed.stats.payment_transactions_seen; delete feed.stats.executed_payments_seen; }, false],
];
// A feed of the first shape that carries one field of the second.
const MIXED = [
  ["a root slot", feed => { feed.network.validators[0].root_slot = 5; }],
  ["payment counts in one block", feed => { feed.blocks[0].payment_tx_count = 0; feed.blocks[0].executed_payment_count = 0; }],
  ["a mark on one transaction", feed => { feed.transactions[0].payment_instructions = []; }],
  ["a payment counter in the stats", feed => { feed.stats.payments_since = feed.stats.since; }],
  ["all three payment counters in the stats", feed => { Object.assign(feed.stats, { payments_since: feed.stats.since, payment_transactions_seen: 0, executed_payments_seen: 0 }); }],
];

test("the sample feeds follow the contract, in JavaScript and in the Python check", () => {
  const documents = [sample(), JSON.parse(read("feed.paused.json")), marked()];
  assert.deepEqual(documents.map(accepts), [true, true, true]);
  assert.deepEqual(pythonAccepts(documents), [true, true, true]);
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

test("a feed that marks payments is held to the same list of changes, and to its own", () => {
  // Every change of the first list has the same verdict on a feed of the second shape.
  const general = changed(marked);
  const expected = CHANGES.map(([, , accepted]) => accepted);
  assert.deepEqual(general.map(accepts), expected);
  assert.deepEqual(pythonAccepts(general), expected);
  // The changes to the payment fields.
  const documents = MARKED_CHANGES.map(([, change]) => { const feed = marked(); return change(feed) ?? feed; });
  const javascript = documents.map(accepts);
  assert.deepEqual(javascript, MARKED_CHANGES.map(([, , accepted]) => accepted), MARKED_CHANGES.filter((item, index) => item[2] !== javascript[index]).map(item => item[0]).join("; "));
  const python = pythonAccepts(documents);
  assert.deepEqual(python, javascript, MARKED_CHANGES.filter((_, index) => python[index] !== javascript[index]).map(item => item[0]).join("; "));
  assert.ok(MARKED_CHANGES.filter(item => item[2]).length >= 8 && MARKED_CHANGES.filter(item => !item[2]).length >= 25);
});

test("a feed carries the payment fields everywhere or nowhere", () => {
  const mixed = MIXED.map(([, change]) => { const feed = sample(); change(feed); return feed; });
  assert.deepEqual(mixed.map(accepts), MIXED.map(() => false), MIXED.map(item => item[0]).join("; "));
  assert.deepEqual(pythonAccepts(mixed), MIXED.map(() => false));
  assert.equal(marksPayments(validateExplorerFeed(sample())), false);
  assert.equal(marksPayments(validateExplorerFeed(marked())), true);
  // A refusal names the row that lacks its field, or the field that is malformed.
  const lacking = marked();
  delete lacking.blocks[7].payment_tx_count;
  assert.throws(() => validateExplorerFeed(lacking), /blocks\[7\] is missing key payment_tx_count/);
  const extra = sample();
  extra.transactions[4].payment_instructions = ["finalize"];
  assert.throws(() => validateExplorerFeed(extra), /transactions\[4\] has unexpected key payment_instructions/);
  const disordered = marked();
  disordered.transactions[1].payment_instructions = ["close", "finalize"];
  assert.throws(() => validateExplorerFeed(disordered), error => error instanceof FeedError && error.path === "transactions[1].payment_instructions" && /each instruction once, in the order initialize, write, seal, finalize, close, inline, unknown/.test(error.message));
  const unknown = marked();
  unknown.transactions[1].payment_instructions = ["finalize", "refund"];
  assert.throws(() => validateExplorerFeed(unknown), error => error instanceof FeedError && error.path === "transactions[1].payment_instructions[1]");
});

test("the mark of a transaction says what it did at the payment program", () => {
  const feed = validateExplorerFeed(marked());
  const steps = feed.transactions.map(paymentStep);
  const count = name => steps.filter(step => step === name).length;
  assert.deepEqual([count("executed"), count("failed"), count("staging"), count("other"), count("none"), count("not-marked")], [4, 1, 8, 1, 23, 0]);
  // What the listed transactions say agrees with the counters of the feed that lists them all.
  assert.equal(feed.stats.payment_transactions_seen, feed.transactions.filter(item => (item.payment_instructions ?? []).length > 0).length);
  assert.equal(feed.stats.executed_payments_seen, count("executed"));
  for (const block of feed.blocks) {
    const listed = feed.transactions.filter(item => item.slot === block.slot);
    assert.equal(block.payment_tx_count, listed.filter(item => (item.payment_instructions ?? []).length > 0).length, String(block.slot));
    assert.equal(block.executed_payment_count, listed.filter(item => paymentStep(item) === "executed").length, String(block.slot));
  }
  const step = (payment_instructions, ok = true) => paymentStep({ signature: "1", slot: 1, block_time: null, ok, fee: 0, kind: "program", payment_instructions });
  assert.deepEqual([step(["finalize"]), step(["finalize", "close"]), step(["inline"]), step(["finalize"], false), step(["inline"], false)], ["executed", "executed", "executed", "failed", "failed"]);
  assert.deepEqual([step(["initialize", "write"]), step(["seal"]), step(["close"]), step(["write", "unknown"]), step(["unknown"]), step([]), step(null), step(undefined)], ["staging", "staging", "staging", "staging", "other", "none", "not-marked", "not-marked"]);
  // A feed of the first shape marks nothing, and a lookup says so.
  const plain = validateExplorerFeed(sample());
  assert.deepEqual([...new Set(plain.transactions.map(paymentStep))], ["not-marked"]);
  assert.equal(findTransaction(plain, plain.transactions[0].signature).payment, "not-marked");
  const executed = feed.transactions.find(item => paymentStep(item) === "executed"), failed = feed.transactions.find(item => paymentStep(item) === "failed");
  assert.equal(findTransaction(feed, executed.signature).payment, "executed");
  assert.equal(findTransaction(feed, failed.signature).payment, "failed");
  assert.deepEqual(PAYMENT_INSTRUCTIONS, ["initialize", "write", "seal", "finalize", "close", "inline", "unknown"]);
});

test("the rows the feed service writes for payment-program transactions pass both checks and read back", () => {
  // One block as a node returns it: a vote, a transfer that only names the payment program
  // among its accounts, and five transactions with instructions addressed to it. The
  // program address is the SDK's own constant, and the instruction data is base58 as in
  // a getBlock reply; the bytes after the first one stand for a payment's bytes.
  const base = sample(), signatures = base.transactions.map(item => item.signature), payer = base.network.validators[0].identity;
  const vote = "Vote111111111111111111111111111111111111111", other = base.network.validators[1].identity;
  const data = (opcode, size) => toBase58(Uint8Array.from({ length: size + 1 }, (_, index) => index === 0 ? opcode : (index * 31) % 251));
  const entry = (signature, keys, instructions, failed = false) => ({ transaction: { signatures: [signature], message: { accountKeys: keys, instructions } }, meta: { err: failed ? { InstructionError: [0, "InvalidInstructionData"] } : null, fee: 5000 }, version: "legacy" });
  const payment = (signature, opcodes, failed) => entry(signature, [payer, other, PROGRAM_ID], opcodes.map(opcode => ({ programIdIndex: 2, accounts: [1, 0], data: data(opcode, opcode === 1 ? 768 : 44) })), failed);
  const slot = base.blocks[0].slot + 1;
  const block = { blockhash: base.blocks[1].blockhash, previousBlockhash: base.blocks[0].blockhash, parentSlot: base.blocks[0].slot, blockTime: base.blocks[0].block_time + 1, blockHeight: base.blocks[0].block_height + 1, transactions: [
    entry(signatures[0], [payer, other, vote], [{ programIdIndex: 2, accounts: [1, 0], data: data(12, 60) }]),
    entry(signatures[1], [payer, PROGRAM_ID, other], [{ programIdIndex: 2, accounts: [0, 1], data: data(3, 0) }]),
    payment(signatures[2], [0, 1]), payment(signatures[3], [2]), payment(signatures[4], [3, 4]), payment(signatures[5], [3], true), payment(signatures[6], [5]),
  ] };
  const accounts = { current: [{ nodePubkey: payer, votePubkey: other, lastVote: slot, rootSlot: slot - 32, activatedStake: 1, commission: 0 }], delinquent: [] };
  const rows = serviceRows(slot, block, accounts);
  assert.deepEqual(rows.block, { slot, parent_slot: slot - 1, blockhash: block.blockhash, block_time: block.blockTime, block_height: block.blockHeight, tx_count: 7, non_vote_tx_count: 6, payment_tx_count: 5, executed_payment_count: 2 });
  assert.deepEqual(rows.validators, [{ identity: payer, vote_account: other, last_vote: slot, root_slot: slot - 32, active: true }]);
  // Newest first: the service lists a block's transactions from its last to its first.
  assert.deepEqual(rows.transactions.map(item => item.payment_instructions), [["inline"], ["finalize"], ["finalize", "close"], ["seal"], ["initialize", "write"], [], []]);
  assert.deepEqual(rows.transactions.map(item => item.kind), ["program", "program", "program", "program", "program", "program", "vote"]);
  // Put into a feed, the rows are a feed of the second shape for both checks.
  const feed = marked();
  feed.blocks = [rows.block];
  feed.transactions = rows.transactions;
  feed.network.validators = rows.validators;
  Object.assign(feed.stats, { payment_transactions_seen: rows.block.payment_tx_count, executed_payments_seen: rows.block.executed_payment_count });
  assert.deepEqual(pythonAccepts([feed]), [true]);
  const read = validateExplorerFeed(feed);
  assert.deepEqual(read.transactions.map(paymentStep), ["executed", "failed", "executed", "staging", "staging", "none", "none"]);
  // Nothing of the instruction data, and no account of a payment instruction, is in the rows.
  const text = JSON.stringify(rows);
  for (const item of block.transactions.slice(2)) for (const instruction of item.transaction.message.instructions) assert.ok(!text.includes(instruction.data.slice(0, 12)) && !text.includes(instruction.data.slice(-12)));
  assert.ok(!text.includes(PROGRAM_ID));
  assert.deepEqual(Object.keys(rows.transactions[0]), ["signature", "slot", "block_time", "ok", "fee", "kind", "payment_instructions"]);
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
