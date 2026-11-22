// Generated from explorer.mjs. Do not edit; regenerate with TypeScript 5.9:
//   tsc --allowJs --checkJs --strict --target ES2022 --module NodeNext --lib ES2022,DOM --declaration --emitDeclarationOnly explorer.mjs
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
export function validateExplorerFeed(document: unknown): ExplorerFeed;
/**
 * Whether a validated feed marks payment-program transactions: its stats
 * carry the payment counters, and every row its payment fields.
 * @param {ExplorerFeed} feed
 */
export function marksPayments(feed: ExplorerFeed): boolean;
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
export function paymentStep(transaction: FeedTransaction): PaymentStep;
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
 * The names a feed gives the payment program's instructions, in the order it
 * lists them: the first byte of the instruction data, 0 to 5, and "unknown"
 * for any other first byte or no data.
 */
export const PAYMENT_INSTRUCTIONS: readonly ["initialize", "write", "seal", "finalize", "close", "inline", "unknown"];
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
    constructor(path: string, problem: string);
    path: string;
}
/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 */
export type PaymentInstruction = "initialize" | "write" | "seal" | "finalize" | "close" | "inline" | "unknown";
/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 */
export type FeedValidator = {
    identity: string;
    vote_account: string | null;
    last_vote: number | null;
    active: boolean;
    root_slot?: number | null;
};
/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 */
export type FeedNetwork = {
    status: "live" | "unavailable";
    tip_slot: number | null;
    finalized_slot: number | null;
    block_height: number | null;
    slot_time_ms: number | null;
    last_block_at: number | null;
    validators: FeedValidator[];
};
/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 */
export type FeedBlock = {
    slot: number;
    parent_slot: number | null;
    blockhash: string;
    block_time: number | null;
    block_height: number | null;
    tx_count: number;
    non_vote_tx_count: number;
    payment_tx_count?: number | null;
    executed_payment_count?: number | null;
};
/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 */
export type FeedTransaction = {
    signature: string;
    slot: number;
    block_time: number | null;
    ok: boolean;
    fee: number;
    kind: "vote" | "program";
    payment_instructions?: PaymentInstruction[] | null;
};
/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 */
export type FeedStats = {
    since: number;
    blocks_seen: number;
    transactions_seen: number;
    non_vote_transactions_seen: number;
    payments_since?: number;
    payment_transactions_seen?: number;
    executed_payments_seen?: number;
};
/**
 * The fields after `active`, `non_vote_tx_count`, `kind` and
 * `non_vote_transactions_seen` are present only in a feed that marks
 * payment-program transactions; see `marksPayments`.
 */
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
 * the feed reports no finalized slot. `payment` is `paymentStep` of the
 * transaction.
 */
export type FoundTransaction = {
    transaction: FeedTransaction;
    block: FeedBlock | null;
    atOrBelowFinalized: boolean | null;
    payment: PaymentStep;
};
/**
 * What a feed's mark says about a transaction and the payment program:
 * - "not-marked": the feed does not say (a feed of the first shape, or a block the service read without its instructions);
 * - "none": the transaction carries no instruction of the payment program;
 * - "executed": it succeeded and carries a finalize or inline instruction, the two that execute a payment;
 * - "failed": it carries one of those two and failed, so no payment was executed;
 * - "staging": it carries neither of those two, only instructions that initialize, write, seal or close a staging account;
 * - "other": it carries only an instruction the feed could not name.
 */
export type PaymentStep = "not-marked" | "none" | "executed" | "failed" | "staging" | "other";
