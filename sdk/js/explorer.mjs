// @ts-check
// Reads the devnet explorer feed (format zolana-explorer-feed-v0): the JSON
// document the recent-blocks page in clients/devnet-explorer shows.
//
// `validateExplorerFeed` applies the same contract as `validate_feed` in
// tools/devnet_explorer/explorer_pull_v0.py, the check the web host runs before
// it publishes a feed. `findTransaction` looks a signature up in a feed.
//
// The feed is a convenience view of a rolling window: at most 120 blocks and
// 200 transactions. It is not signed towards the reader and it is not history.
// A wallet settles a payment from finalized blocks, never from this feed.
//
// A feed has one of two shapes under the same format name. The second also
// marks the transactions that invoke the native payment program: it names the
// instructions each one carries and counts them per block. `marksPayments`
// tells the shapes apart and `paymentStep` reads one transaction's mark.
//
// Version 0.1, experimental. No dependencies.

export const EXPLORER_FEED_FORMAT = "zolana-explorer-feed-v0";
/** The most blocks and transactions a feed may list. */
export const MAX_FEED_BLOCKS = 120;
export const MAX_FEED_TRANSACTIONS = 200;
/**
 * The names a feed gives the payment program's instructions, in the order it
 * lists them: the first byte of the instruction data, 0 to 5, and "unknown"
 * for any other first byte or no data.
 */
export const PAYMENT_INSTRUCTIONS = /** @type {const} */ (["initialize", "write", "seal", "finalize", "close", "inline", "unknown"]);

/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 * @typedef {"initialize" | "write" | "seal" | "finalize" | "close" | "inline" | "unknown"} PaymentInstruction
 * @typedef {{ identity: string, vote_account: string | null, last_vote: number | null, active: boolean, root_slot?: number | null }} FeedValidator
 * @typedef {{ status: "live" | "unavailable", tip_slot: number | null, finalized_slot: number | null, block_height: number | null, slot_time_ms: number | null, last_block_at: number | null, validators: FeedValidator[] }} FeedNetwork
 * @typedef {{ slot: number, parent_slot: number | null, blockhash: string, block_time: number | null, block_height: number | null, tx_count: number, non_vote_tx_count: number, payment_tx_count?: number | null, executed_payment_count?: number | null }} FeedBlock
 * @typedef {{ signature: string, slot: number, block_time: number | null, ok: boolean, fee: number, kind: "vote" | "program", payment_instructions?: PaymentInstruction[] | null }} FeedTransaction
 * @typedef {{ since: number, blocks_seen: number, transactions_seen: number, non_vote_transactions_seen: number, payments_since?: number, payment_transactions_seen?: number, executed_payments_seen?: number }} FeedStats
 * @typedef {{ format: "zolana-explorer-feed-v0", generated_at: number, genesis_hash: string | null, network: FeedNetwork, blocks: FeedBlock[], transactions: FeedTransaction[], stats: FeedStats }} ExplorerFeed
 */
/**
 * What a feed says about one transaction. `atOrBelowFinalized` is `null` when
 * the feed reports no finalized slot. `payment` is `paymentStep` of the
 * transaction.
 * @typedef {{ transaction: FeedTransaction, block: FeedBlock | null, atOrBelowFinalized: boolean | null, payment: PaymentStep }} FoundTransaction
 */
/**
 * What a feed's mark says about a transaction and the payment program:
 * - "not-marked": the feed does not say (a feed of the first shape, or a block the service read without its instructions);
 * - "none": the transaction carries no instruction of the payment program;
 * - "executed": it succeeded and carries a finalize or inline instruction, the two that execute a payment;
 * - "failed": it carries one of those two and failed, so no payment was executed;
 * - "staging": it carries neither of those two, only instructions that initialize, write, seal or close a staging account;
 * - "other": it carries only an instruction the feed could not name.
 * @typedef {"not-marked" | "none" | "executed" | "failed" | "staging" | "other"} PaymentStep
 */

/** The document does not follow the feed contract. `path` names the field. */
export class FeedError extends Error {
  /** @param {string} path @param {string} problem */
  constructor(path, problem) {
    super(`${path} ${problem}`);
    this.name = "FeedError";
    this.path = path;
  }
}

const integer = (/** @type {unknown} */ value) => Number.isSafeInteger(value) && /** @type {number} */ (value) >= 0;
/** @type {Record<string, (value: unknown) => boolean>} */
const TYPES = {
  integer,
  number: value => typeof value === "number" && Number.isFinite(value) && value >= 0 && value < 2 ** 53,
  // Every string in the contract is a base58 identifier or hash.
  string: value => typeof value === "string" && value.length <= 127 && /^[0-9A-Za-z]*$/.test(value),
  boolean: value => typeof value === "boolean",
  status: value => value === "live" || value === "unavailable",
  kind: value => value === "vote" || value === "program",
};
const PROBLEMS = {
  integer: "must be an integer from 0 to 2**53 - 1", number: "must be a finite number from 0 to below 2**53",
  string: "must be a string of ASCII letters and digits shorter than 128 characters", boolean: "must be true or false",
  status: "must be one of live, unavailable", kind: "must be one of vote, program",
};
// Field name -> type; a trailing "?" allows null.
const NETWORK = { status: "status", tip_slot: "integer?", finalized_slot: "integer?", block_height: "integer?", slot_time_ms: "number?", last_block_at: "integer?", validators: "" };
const VALIDATOR = { identity: "string", vote_account: "string?", last_vote: "integer?", active: "boolean" };
const BLOCK = { slot: "integer", parent_slot: "integer?", blockhash: "string", block_time: "integer?", block_height: "integer?", tx_count: "integer", non_vote_tx_count: "integer" };
const TRANSACTION = { signature: "string", slot: "integer", block_time: "integer?", ok: "boolean", fee: "integer", kind: "kind" };
const STATS = { since: "integer", blocks_seen: "integer", transactions_seen: "integer", non_vote_transactions_seen: "integer" };
// What a feed that marks payment-program transactions adds. It carries all of
// these, in every row, or none of them.
const VALIDATOR_PAYMENTS = { root_slot: "integer?" };
const BLOCK_PAYMENTS = { payment_tx_count: "integer?", executed_payment_count: "integer?" };
const TRANSACTION_PAYMENTS = { payment_instructions: "" };
const STATS_PAYMENTS = { payments_since: "integer", payment_transactions_seen: "integer", executed_payments_seen: "integer" };

/** Exactly the keys of `fields`, each of its type. @param {unknown} value @param {string} path @param {Record<string, string>} fields */
function object(value, path, fields) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new FeedError(path, "must be an object");
  const record = /** @type {Record<string, unknown>} */ (value);
  for (const key of Object.keys(record)) if (!Object.hasOwn(fields, key)) throw new FeedError(path, `has unexpected key ${key.slice(0, 48)}`);
  for (const [key, type] of Object.entries(fields)) {
    if (!Object.hasOwn(record, key)) throw new FeedError(path, `is missing key ${key}`);
    const name = /** @type {keyof typeof PROBLEMS} */ (type.replace("?", ""));
    if (type === "" || (type.endsWith("?") && record[key] === null)) continue;
    if (!TYPES[name](record[key])) throw new FeedError(`${path}.${key}`, PROBLEMS[name]);
  }
  return record;
}
/** @param {unknown} value @param {string} path @param {Record<string, string>} fields @param {number} [limit] @param {(row: Record<string, any>, path: string) => void} [check] */
function rows(value, path, fields, limit, check) {
  if (!Array.isArray(value)) throw new FeedError(path, "must be an array");
  if (limit !== undefined && value.length > limit) throw new FeedError(path, `has ${value.length} entries; at most ${limit} are allowed`);
  value.forEach((item, index) => { const row = object(item, `${path}[${index}]`, fields); check?.(row, `${path}[${index}]`); });
}
/** Both payment counts or null for both, and neither above what it is part of. @param {Record<string, any>} block @param {string} path */
function paymentCounts(block, path) {
  const payment = block.payment_tx_count, executed = block.executed_payment_count;
  if ((payment === null) !== (executed === null)) throw new FeedError(path, "must give both payment counts or null for both");
  if (payment !== null && !(executed <= payment && payment <= block.tx_count)) throw new FeedError(path, "must have executed_payment_count <= payment_tx_count <= tx_count");
}
/** null, or instruction names, each once, in the listed order. @param {Record<string, any>} transaction @param {string} path */
function paymentInstructions(transaction, path) {
  const value = transaction.payment_instructions, field = `${path}.payment_instructions`;
  if (value === null) return;
  if (!Array.isArray(value)) throw new FeedError(field, "must be an array");
  if (value.length > PAYMENT_INSTRUCTIONS.length) throw new FeedError(field, `has ${value.length} entries; at most ${PAYMENT_INSTRUCTIONS.length} are allowed`);
  let position = -1;
  value.forEach((name, index) => {
    const found = typeof name === "string" ? PAYMENT_INSTRUCTIONS.indexOf(/** @type {PaymentInstruction} */ (name)) : -1;
    if (found < 0) throw new FeedError(`${field}[${index}]`, `must be one of ${PAYMENT_INSTRUCTIONS.join(", ")}`);
    if (found <= position) throw new FeedError(field, `must name each instruction once, in the order ${PAYMENT_INSTRUCTIONS.join(", ")}`);
    position = found;
  });
}

/**
 * Checks a parsed feed against the feed contract and returns it typed. Unknown
 * keys, missing keys and values of the wrong type are refused.
 *
 * Both shapes of the feed are accepted. A feed whose stats carry a payment
 * counter must carry the payment fields in every validator, block and
 * transaction; a feed whose stats carry none must carry none anywhere.
 *
 * The check runs on the parsed value, so it cannot see what `JSON.parse` has
 * already folded away: a duplicated key, or `1.0` written for `1`.
 * @param {unknown} document The result of `JSON.parse` on the feed text.
 * @returns {ExplorerFeed}
 */
export function validateExplorerFeed(document) {
  const feed = object(document, "feed", { format: "", generated_at: "integer", genesis_hash: "string?", network: "", blocks: "", transactions: "", stats: "" });
  if (feed.format !== EXPLORER_FEED_FORMAT) throw new FeedError("format", `must be exactly ${EXPLORER_FEED_FORMAT}`);
  const rawStats = feed.stats;
  const marked = rawStats !== null && typeof rawStats === "object" && !Array.isArray(rawStats) && Object.keys(STATS_PAYMENTS).some(key => Object.hasOwn(rawStats, key));
  const network = object(feed.network, "network", NETWORK);
  rows(network.validators, "network.validators", marked ? { ...VALIDATOR, ...VALIDATOR_PAYMENTS } : VALIDATOR);
  rows(feed.blocks, "blocks", marked ? { ...BLOCK, ...BLOCK_PAYMENTS } : BLOCK, MAX_FEED_BLOCKS, marked ? paymentCounts : undefined);
  rows(feed.transactions, "transactions", marked ? { ...TRANSACTION, ...TRANSACTION_PAYMENTS } : TRANSACTION, MAX_FEED_TRANSACTIONS, marked ? paymentInstructions : undefined);
  const stats = object(rawStats, "stats", marked ? { ...STATS, ...STATS_PAYMENTS } : STATS);
  if (marked && /** @type {number} */ (stats.executed_payments_seen) > /** @type {number} */ (stats.payment_transactions_seen)) throw new FeedError("stats", "must have executed_payments_seen <= payment_transactions_seen");
  return /** @type {ExplorerFeed} */ (/** @type {unknown} */ (feed));
}

/**
 * Whether a validated feed marks payment-program transactions: its stats
 * carry the payment counters, and every row its payment fields.
 * @param {ExplorerFeed} feed
 */
export function marksPayments(feed) {
  return feed.stats.payments_since !== undefined;
}

/**
 * Reads the mark of one transaction of a validated feed.
 *
 * The mark is what the ledger shows to anyone who reads the block: that the
 * transaction has an instruction addressed to the payment program, and the
 * first byte of that instruction's data, which names the instruction. It does
 * not say whether a payment is a deposit, a private send or a withdrawal, and
 * it carries no amount, account, nullifier, commitment or ciphertext.
 * @param {FeedTransaction} transaction
 * @returns {PaymentStep}
 */
export function paymentStep(transaction) {
  const names = transaction.payment_instructions;
  if (names === undefined || names === null) return "not-marked";
  if (names.length === 0) return "none";
  if (names.includes("finalize") || names.includes("inline")) return transaction.ok ? "executed" : "failed";
  return names.length === 1 && names[0] === "unknown" ? "other" : "staging";
}

/**
 * Looks a transaction up by its full signature in a validated feed.
 *
 * A match means the feed service read a block that lists this signature.
 * `ok` and `fee` come from the node's execution record when the service read
 * the block in full; when the node returned signatures only, the service
 * reports `ok: true` and `fee: 0` for every transaction of that block.
 *
 * No match means only that the signature is not in the current window. It
 * does not mean the transaction failed or was never sent.
 * @param {ExplorerFeed} feed @param {string} signature Base58, as returned by `sendTransaction` or by the relay's status method.
 * @returns {FoundTransaction | null}
 */
export function findTransaction(feed, signature) {
  const transaction = feed.transactions.find(item => item.signature === signature);
  if (!transaction) return null;
  const finalized = feed.network.finalized_slot;
  return {
    transaction,
    block: feed.blocks.find(block => block.slot === transaction.slot) ?? null,
    atOrBelowFinalized: finalized === null ? null : transaction.slot <= finalized,
    payment: paymentStep(transaction),
  };
}
