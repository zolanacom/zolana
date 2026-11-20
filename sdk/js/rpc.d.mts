// Generated from rpc.mjs. Do not edit; regenerate with TypeScript 5.9:
//   tsc --allowJs --checkJs --strict --target ES2022 --module NodeNext --lib ES2022,DOM --declaration --emitDeclarationOnly rpc.mjs
/**
 * Creates a client. Every method sends exactly one request and never retries.
 * @param {ClientOptions} options
 */
export function createRpcClient(options: ClientOptions): {
    call: (method: string, params?: unknown[]) => Promise<any>;
    /** @returns {Promise<string>} The base58 genesis hash. Compare it with your network before anything else. */
    getGenesisHash: () => Promise<string>;
    /** @param {Commitment} [commitment] @returns {Promise<number>} */
    getSlot: (commitment?: Commitment) => Promise<number>;
    /** @param {Commitment} [commitment] @returns {Promise<number>} */
    getBlockHeight: (commitment?: Commitment) => Promise<number>;
    /** @param {string} address @param {Commitment} [commitment] @returns {Promise<WithContext<AccountInfo | null>>} */
    getAccountInfo: (address: string, commitment?: Commitment) => Promise<WithContext<AccountInfo | null>>;
    /** @param {string} address @param {Commitment} [commitment] @returns {Promise<WithContext<number>>} */
    getBalance: (address: string, commitment?: Commitment) => Promise<WithContext<number>>;
    /** @param {Commitment} [commitment] @returns {Promise<WithContext<{ blockhash: string, lastValidBlockHeight: number }>>} */
    getLatestBlockhash: (commitment?: Commitment) => Promise<WithContext<{
        blockhash: string;
        lastValidBlockHeight: number;
    }>>;
    /** @param {number} slot @param {object} [config] Defaults to {@link FULL_BLOCK_CONFIG}. @returns {Promise<Block | null>} */
    getBlock: (slot: number, config?: object) => Promise<Block | null>;
    /** @param {number} start @param {number} end @returns {Promise<number[]>} Produced finalized slots in the inclusive range. */
    getBlocks: (start: number, end: number) => Promise<number[]>;
    /**
     * Forwards a signed transaction. Gateways do not inspect it. The browser gateway does not offer this method.
     * @param {string} transaction Base64 of the signed transaction. @param {object} [config] @returns {Promise<string>} The signature.
     */
    sendTransaction: (transaction: string, config?: object) => Promise<string>;
    /** @returns {Promise<ShieldedFeeQuote>} */
    getShieldedFeeQuote: () => Promise<ShieldedFeeQuote>;
    /**
     * Hands one shielded-fee payment to the relay. Sending the same packet again
     * returns the same id. Any failure leaves the outcome unknown: resolve the
     * saved payment from finalized history before building another.
     * @param {ShieldedPacket} packet @returns {Promise<{ id: string }>}
     */
    submitShieldedPayment: (packet: ShieldedPacket) => Promise<{
        id: string;
    }>;
    /** @param {string} id 64 lowercase hex digits. @returns {Promise<ShieldedPaymentStatus>} */
    getShieldedPaymentStatus: (id: string) => Promise<ShieldedPaymentStatus>;
    /**
     * Several small reads in one request. Each result repeats its request.
     * @param {ReadCall[]} calls 1 to 16 calls of {@link READ_BATCH_METHODS}.
     * @returns {Promise<{ request: ReadCall, result: unknown }[]>}
     */
    getWalletReadBatch: (calls: ReadCall[]) => Promise<{
        request: ReadCall;
        result: unknown;
    }[]>;
    /**
     * Full finalized blocks for the given slots.
     * @param {number[]} slots 1 to 256 strictly increasing slots, each at least 1.
     * @returns {Promise<{ slot: number, block: Block }[]>}
     */
    getWalletHistoryBlocks: (slots: number[]) => Promise<{
        slot: number;
        block: Block;
    }[]>;
    /**
     * One consistent view for a sync: the pool account, the target header, the
     * saved header and, when it fits, the canonical blocks in between.
     * @param {number} savedSlot The slot of the wallet's saved checkpoint, or 0.
     * @returns {Promise<{ format: "zolana-wallet-sync-snapshot-v1", network: NetworkIdentity, genesis: string, pool: WithContext<AccountInfo>, target_header: Block, saved_header: Block | null, canonical_tail: { after_slot: number, target_slot: number, next_slot: number, complete: true, blocks: { slot: number, block: Block }[] } | null, fallback: string | null }>}
     */
    getWalletSyncSnapshot: (savedSlot: number) => Promise<{
        format: "zolana-wallet-sync-snapshot-v1";
        network: NetworkIdentity;
        genesis: string;
        pool: WithContext<AccountInfo>;
        target_header: Block;
        saved_header: Block | null;
        canonical_tail: {
            after_slot: number;
            target_slot: number;
            next_slot: number;
            complete: true;
            blocks: {
                slot: number;
                block: Block;
            }[];
        } | null;
        fallback: string | null;
    }>;
    /**
     * One page of retained history in the compact form. The result is `null`
     * when the gateway keeps no retained history; otherwise it is the input of
     * `BrowserVault.apply_compact_history_page` after its `compact_headers.data_base64`
     * field is decoded into the binary headers argument.
     * @param {number} afterSlot @param {number} targetSlot @param {RetainedToken | null} token `null` on the first page.
     * @param {16384 | 32768} [maxBlocks] An explicit page bound; omit for the default.
     * @returns {Promise<Record<string, unknown> | null>}
     */
    getWalletRetainedHistoryV3: (afterSlot: number, targetSlot: number, token: RetainedToken | null, maxBlocks?: 16384 | 32768) => Promise<Record<string, unknown> | null>;
    /**
     * One page from a canonical archive, the input of `BrowserVault.apply_archival_page`.
     * The result is `null` when the gateway has no archive.
     * @param {number} afterSlot @param {number} targetSlot At least 1 and not below `afterSlot`.
     * @param {ArchiveAnchor | null} anchor May be `null` only when `afterSlot` is 0.
     * @returns {Promise<Record<string, unknown> | null>}
     */
    getWalletCanonicalHistory: (afterSlot: number, targetSlot: number, anchor: ArchiveAnchor | null) => Promise<Record<string, unknown> | null>;
};
/** The invited RPC gateway's allow-list (METHODS in tools/testnet_gateway.py). */
export const GATEWAY_METHODS: readonly string[];
/** Methods that getWalletReadBatch may aggregate (READ_METHODS in the gateway). */
export const READ_BATCH_METHODS: readonly string[];
/** The gateway refuses a request body above this many bytes. */
export const MAX_REQUEST_BYTES: 32768;
/** The gateway never sends a larger response; the client stops reading here. */
export const MAX_RESPONSE_BYTES: number;
/** The browser wallet's per-request timeout. */
export const DEFAULT_TIMEOUT_MS: 25000;
/** JSON-RPC error code: the relay's finite payment capacity is used up. */
export const RELAY_CAPACITY_CODE: -32040;
/** JSON-RPC error code: a history response would exceed the byte limit. */
export const HISTORY_SIZE_CODE: -32062;
/** The getBlock configuration the wallets use to read full finalized history. */
export const FULL_BLOCK_CONFIG: Readonly<{
    encoding: "base64";
    transactionDetails: "full";
    rewards: false;
    commitment: "finalized";
    maxSupportedTransactionVersion: 0;
}>;
/** The getBlock configuration the browser wallet uses to read a block header. */
export const HEADER_BLOCK_CONFIG: Readonly<{
    transactionDetails: "none";
    rewards: false;
    commitment: "finalized";
}>;
/**
 * @typedef {{ network: number[], genesis_hash: string }} NetworkIdentity
 * @typedef {"confirmed" | "finalized"} Commitment
 */
/**
 * @template T
 * @typedef {{ context: { slot: number, [field: string]: unknown }, value: T }} WithContext
 */
/**
 * Fields the wallets read from an account. Others pass through untyped.
 * @typedef {{ owner: string, lamports: number, data: [string, "base64"], [field: string]: unknown }} AccountInfo
 */
/**
 * Fields the wallets read from a block. `transactions` is absent for header reads.
 * @typedef {{ parentSlot: number, blockhash: string, previousBlockhash: string, blockHeight: number, transactions?: unknown[], [field: string]: unknown }} Block
 */
/**
 * `transport` and `pool_format` are present when the relay submits inline payments.
 * @typedef {{ format: "native-shielded-fee-quote-v1", network: NetworkIdentity, payer: string, fee: number, transport?: "native-inline-v1", pool_format?: "NPOOL004" }} ShieldedFeeQuote
 */
/**
 * `payload` is the base64 of the payment bytes (`BrowserVault.pending_packet().packet`).
 * @typedef {{ network: NetworkIdentity, payload: string }} ShieldedPacket
 */
/**
 * A hint only. It never settles a payment; finalized history does.
 * @typedef {{ id: string, state: "unknown" | "pending" } | { id: string, state: "accepted" | "aborted", signature: string | null }} ShieldedPaymentStatus
 */
/**
 * @typedef {{ method: string, params: unknown[] }} ReadCall
 * @typedef {{ segments: number, sha256: string }} RetainedToken
 * @typedef {{ slot: number, blockhash: string, block_height: number }} ArchiveAnchor
 */
/**
 * @typedef {object} ClientOptions
 * @property {string} url The endpoint: a local validator's RPC URL, an invited
 *   gateway's RPC URL, or "/rpc" from a page served by a browser gateway.
 * @property {(method: string) => string | undefined | Promise<string | undefined>} [accessHeader]
 *   Returns the X-Testnet-Access value (`BrowserVault.rpc_header(audience, now)`).
 *   Called for every method except getGenesisHash. Omit it for a local validator.
 * @property {typeof globalThis.fetch} [fetch] Defaults to the global fetch.
 * @property {number} [timeoutMs] Defaults to 25000.
 * @property {number} [maxResponseBytes] Defaults to 16 MiB.
 */
/** The endpoint answered with a JSON-RPC error object. */
export class RpcError extends Error {
    /** @param {string} method @param {{ code?: unknown, message?: unknown, data?: unknown }} error */
    constructor(method: string, error: {
        code?: unknown;
        message?: unknown;
        data?: unknown;
    });
    method: string;
    /** @type {number | undefined} */
    code: number | undefined;
    data: unknown;
    /** "member" or "network" when the relay's capacity is used up, otherwise undefined. */
    get capacityScope(): "network" | "member" | undefined;
}
/** The endpoint answered with an HTTP status other than 2xx. */
export class HttpError extends Error {
    /** @param {string} method @param {number} status @param {unknown} body */
    constructor(method: string, status: number, body: unknown);
    method: string;
    status: number;
    /** The parsed JSON body, for example `{ error: "access_denied" }`. */
    body: unknown;
    /** 403 from a gateway: no valid proof, not a member, or a method or request it does not allow. */
    get accessDenied(): boolean;
    /** 429 from a gateway: a quota was reached. */
    get rateLimited(): boolean;
}
/**
 * No usable answer arrived: a timeout, a network failure or a malformed response.
 * After a submit this means the outcome is unknown, not that the payment failed.
 */
export class TransportError extends Error {
    /** @param {string} method @param {"timeout" | "network" | "response"} kind @param {string} detail @param {unknown} [cause] */
    constructor(method: string, kind: "timeout" | "network" | "response", detail: string, cause?: unknown);
    method: string;
    kind: "network" | "timeout" | "response";
}
export type NetworkIdentity = {
    network: number[];
    genesis_hash: string;
};
export type Commitment = "confirmed" | "finalized";
export type WithContext<T> = {
    context: {
        slot: number;
        [field: string]: unknown;
    };
    value: T;
};
/**
 * Fields the wallets read from an account. Others pass through untyped.
 */
export type AccountInfo = {
    owner: string;
    lamports: number;
    data: [string, "base64"];
    [field: string]: unknown;
};
/**
 * Fields the wallets read from a block. `transactions` is absent for header reads.
 */
export type Block = {
    parentSlot: number;
    blockhash: string;
    previousBlockhash: string;
    blockHeight: number;
    transactions?: unknown[];
    [field: string]: unknown;
};
/**
 * `transport` and `pool_format` are present when the relay submits inline payments.
 */
export type ShieldedFeeQuote = {
    format: "native-shielded-fee-quote-v1";
    network: NetworkIdentity;
    payer: string;
    fee: number;
    transport?: "native-inline-v1";
    pool_format?: "NPOOL004";
};
/**
 * `payload` is the base64 of the payment bytes (`BrowserVault.pending_packet().packet`).
 */
export type ShieldedPacket = {
    network: NetworkIdentity;
    payload: string;
};
/**
 * A hint only. It never settles a payment; finalized history does.
 */
export type ShieldedPaymentStatus = {
    id: string;
    state: "unknown" | "pending";
} | {
    id: string;
    state: "accepted" | "aborted";
    signature: string | null;
};
export type ReadCall = {
    method: string;
    params: unknown[];
};
export type RetainedToken = {
    segments: number;
    sha256: string;
};
export type ArchiveAnchor = {
    slot: number;
    blockhash: string;
    block_height: number;
};
export type ClientOptions = {
    /**
     * The endpoint: a local validator's RPC URL, an invited
     * gateway's RPC URL, or "/rpc" from a page served by a browser gateway.
     */
    url: string;
    /**
     * Returns the X-Testnet-Access value (`BrowserVault.rpc_header(audience, now)`).
     * Called for every method except getGenesisHash. Omit it for a local validator.
     */
    accessHeader?: ((method: string) => string | undefined | Promise<string | undefined>) | undefined;
    /**
     * Defaults to the global fetch.
     */
    fetch?: typeof fetch | undefined;
    /**
     * Defaults to 25000.
     */
    timeoutMs?: number | undefined;
    /**
     * Defaults to 16 MiB.
     */
    maxResponseBytes?: number | undefined;
};
