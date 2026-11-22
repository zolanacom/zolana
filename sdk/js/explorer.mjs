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
// Version 0.1, experimental. No dependencies.

export const EXPLORER_FEED_FORMAT = "zolana-explorer-feed-v0";
/** The most blocks and transactions a feed may list. */
export const MAX_FEED_BLOCKS = 120;
export const MAX_FEED_TRANSACTIONS = 200;

/**
 * @typedef {{ identity: string, vote_account: string | null, last_vote: number | null, active: boolean }} FeedValidator
 * @typedef {{ status: "live" | "unavailable", tip_slot: number | null, finalized_slot: number | null, block_height: number | null, slot_time_ms: number | null, last_block_at: number | null, validators: FeedValidator[] }} FeedNetwork
 * @typedef {{ slot: number, parent_slot: number | null, blockhash: string, block_time: number | null, block_height: number | null, tx_count: number, non_vote_tx_count: number }} FeedBlock
 * @typedef {{ signature: string, slot: number, block_time: number | null, ok: boolean, fee: number, kind: "vote" | "program" }} FeedTransaction
 * @typedef {{ since: number, blocks_seen: number, transactions_seen: number, non_vote_transactions_seen: number }} FeedStats
 * @typedef {{ format: "zolana-explorer-feed-v0", generated_at: number, genesis_hash: string | null, network: FeedNetwork, blocks: FeedBlock[], transactions: FeedTransaction[], stats: FeedStats }} ExplorerFeed
 */
/**
 * What a feed says about one transaction. `atOrBelowFinalized` is `null` when
 * the feed reports no finalized slot.
 * @typedef {{ transaction: FeedTransaction, block: FeedBlock | null, atOrBelowFinalized: boolean | null }} FoundTransaction
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
/** @param {unknown} value @param {string} path @param {Record<string, string>} fields @param {number} [limit] */
function rows(value, path, fields, limit) {
  if (!Array.isArray(value)) throw new FeedError(path, "must be an array");
  if (limit !== undefined && value.length > limit) throw new FeedError(path, `has ${value.length} entries; at most ${limit} are allowed`);
  value.forEach((item, index) => object(item, `${path}[${index}]`, fields));
}

/**
 * Checks a parsed feed against the feed contract and returns it typed. Unknown
 * keys, missing keys and values of the wrong type are refused.
 *
 * The check runs on the parsed value, so it cannot see what `JSON.parse` has
 * already folded away: a duplicated key, or `1.0` written for `1`.
 * @param {unknown} document The result of `JSON.parse` on the feed text.
 * @returns {ExplorerFeed}
 */
export function validateExplorerFeed(document) {
  const feed = object(document, "feed", { format: "", generated_at: "integer", genesis_hash: "string?", network: "", blocks: "", transactions: "", stats: "" });
  if (feed.format !== EXPLORER_FEED_FORMAT) throw new FeedError("format", `must be exactly ${EXPLORER_FEED_FORMAT}`);
  const network = object(feed.network, "network", NETWORK);
  rows(network.validators, "network.validators", VALIDATOR);
  rows(feed.blocks, "blocks", BLOCK, MAX_FEED_BLOCKS);
  rows(feed.transactions, "transactions", TRANSACTION, MAX_FEED_TRANSACTIONS);
  object(feed.stats, "stats", STATS);
  return /** @type {ExplorerFeed} */ (/** @type {unknown} */ (feed));
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
  };
}
