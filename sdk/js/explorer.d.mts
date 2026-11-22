// Generated from explorer.mjs. Do not edit; regenerate with TypeScript 5.9:
//   tsc --allowJs --checkJs --strict --target ES2022 --module NodeNext --lib ES2022,DOM --declaration --emitDeclarationOnly explorer.mjs
/**
 * Checks a parsed feed against the feed contract and returns it typed. Unknown
 * keys, missing keys and values of the wrong type are refused.
 *
 * The check runs on the parsed value, so it cannot see what `JSON.parse` has
 * already folded away: a duplicated key, or `1.0` written for `1`.
 * @param {unknown} document The result of `JSON.parse` on the feed text.
 * @returns {ExplorerFeed}
 */
export function validateExplorerFeed(document: unknown): ExplorerFeed;
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
export function findTransaction(feed: ExplorerFeed, signature: string): FoundTransaction | null;
export const EXPLORER_FEED_FORMAT: "zolana-explorer-feed-v0";
/** The most blocks and transactions a feed may list. */
export const MAX_FEED_BLOCKS: 120;
export const MAX_FEED_TRANSACTIONS: 200;
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
    constructor(path: string, problem: string);
    path: string;
}
export type FeedValidator = {
    identity: string;
    vote_account: string | null;
    last_vote: number | null;
    active: boolean;
};
export type FeedNetwork = {
    status: "live" | "unavailable";
    tip_slot: number | null;
    finalized_slot: number | null;
    block_height: number | null;
    slot_time_ms: number | null;
    last_block_at: number | null;
    validators: FeedValidator[];
};
export type FeedBlock = {
    slot: number;
    parent_slot: number | null;
    blockhash: string;
    block_time: number | null;
    block_height: number | null;
    tx_count: number;
    non_vote_tx_count: number;
};
export type FeedTransaction = {
    signature: string;
    slot: number;
    block_time: number | null;
    ok: boolean;
    fee: number;
    kind: "vote" | "program";
};
export type FeedStats = {
    since: number;
    blocks_seen: number;
    transactions_seen: number;
    non_vote_transactions_seen: number;
};
export type ExplorerFeed = {
    format: "zolana-explorer-feed-v0";
    generated_at: number;
    genesis_hash: string | null;
    network: FeedNetwork;
    blocks: FeedBlock[];
    transactions: FeedTransaction[];
    stats: FeedStats;
};
/**
 * What a feed says about one transaction. `atOrBelowFinalized` is `null` when
 * the feed reports no finalized slot.
 */
export type FoundTransaction = {
    transaction: FeedTransaction;
    block: FeedBlock | null;
    atOrBelowFinalized: boolean | null;
};
