// @ts-check
// A small JSON-RPC client for the methods the Zolana wallets call.
//
// It follows the request rules of the invited RPC gateway (tools/testnet_gateway.py)
// and of the browser wallet's transport (clients/browser-wallet/product-worker.js):
// one JSON object per POST, exact Content-Type, a bounded body, a bounded
// response, a timeout, and no automatic retry. It also works against a local
// validator's loopback RPC, which needs no access header.
//
// The public devnet admits cohort wallets only. Without a membership every
// method except getGenesisHash is answered with HTTP 403. Use a local network.
//
// Version 0.1, experimental. The custom gateway methods are unversioned.
// No dependencies. Needs a runtime with fetch, AbortController and TextEncoder.

/** The invited RPC gateway's allow-list (METHODS in tools/testnet_gateway.py). */
export const GATEWAY_METHODS = Object.freeze([
  "getShieldedFeeQuote", "submitShieldedPayment", "getShieldedPaymentStatus",
  "getWalletReadBatch", "getWalletSyncSnapshot",
  "getWalletHistoryBlocks", "getWalletRetainedHistory", "getWalletRetainedHistoryV2",
  "getWalletRetainedHistoryV3", "getWalletCanonicalHistory",
  "getGenesisHash", "getHealth", "getVersion", "getAccountInfo", "getMultipleAccounts",
  "getBlocks", "getBlock", "getBlockHeight", "getSlot", "getEpochInfo", "getBalance",
  "getSignaturesForAddress", "getSignatureStatuses", "getTransaction", "getLatestBlockhash",
  "getMinimumBalanceForRentExemption", "getFeeForMessage", "sendTransaction", "getProgramAccounts",
]);
/** Methods that getWalletReadBatch may aggregate (READ_METHODS in the gateway). */
export const READ_BATCH_METHODS = Object.freeze([
  "getAccountInfo", "getBalance", "getLatestBlockhash", "getSlot",
  "getMinimumBalanceForRentExemption", "getFeeForMessage",
]);
/** The gateway refuses a request body above this many bytes. */
export const MAX_REQUEST_BYTES = 32768;
/** The gateway never sends a larger response; the client stops reading here. */
export const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
/** The browser wallet's per-request timeout. */
export const DEFAULT_TIMEOUT_MS = 25000;
/** JSON-RPC error code: the relay's finite payment capacity is used up. */
export const RELAY_CAPACITY_CODE = -32040;
/** JSON-RPC error code: a history response would exceed the byte limit. */
export const HISTORY_SIZE_CODE = -32062;
/** The getBlock configuration the wallets use to read full finalized history. */
export const FULL_BLOCK_CONFIG = Object.freeze({
  encoding: "base64", transactionDetails: "full", rewards: false,
  commitment: "finalized", maxSupportedTransactionVersion: 0,
});
/** The getBlock configuration the browser wallet uses to read a block header. */
export const HEADER_BLOCK_CONFIG = Object.freeze({ transactionDetails: "none", rewards: false, commitment: "finalized" });

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
  constructor(method, error) {
    super(`${method}: ${typeof error.message === "string" ? error.message : "JSON-RPC error"}`);
    this.name = "RpcError";
    this.method = method;
    /** @type {number | undefined} */
    this.code = typeof error.code === "number" ? error.code : undefined;
    this.data = error.data;
  }
  /** "member" or "network" when the relay's capacity is used up, otherwise undefined. */
  get capacityScope() {
    const data = /** @type {{ scope?: unknown } | null | undefined} */ (this.data);
    const scope = this.code === RELAY_CAPACITY_CODE && data && typeof data === "object" ? data.scope : undefined;
    return scope === "member" || scope === "network" ? scope : undefined;
  }
}

/** The endpoint answered with an HTTP status other than 2xx. */
export class HttpError extends Error {
  /** @param {string} method @param {number} status @param {unknown} body */
  constructor(method, status, body) {
    super(`${method}: HTTP ${status}`);
    this.name = "HttpError";
    this.method = method;
    this.status = status;
    /** The parsed JSON body, for example `{ error: "access_denied" }`. */
    this.body = body;
  }
  /** 403 from a gateway: no valid proof, not a member, or a method or request it does not allow. */
  get accessDenied() { return this.status === 403; }
  /** 429 from a gateway: a quota was reached. */
  get rateLimited() { return this.status === 429; }
}

/**
 * No usable answer arrived: a timeout, a network failure or a malformed response.
 * After a submit this means the outcome is unknown, not that the payment failed.
 */
export class TransportError extends Error {
  /** @param {string} method @param {"timeout" | "network" | "response"} kind @param {string} detail @param {unknown} [cause] */
  constructor(method, kind, detail, cause) {
    super(`${method}: ${detail}`, { cause });
    this.name = "TransportError";
    this.method = method;
    this.kind = kind;
  }
}

const natural = (/** @type {unknown} */ value) => Number.isSafeInteger(value) && /** @type {number} */ (value) >= 0;
/** @param {unknown} token @returns {token is RetainedToken} */
const retainedToken = token => !!token && typeof token === "object" &&
  natural(/** @type {RetainedToken} */ (token).segments) && /** @type {RetainedToken} */ (token).segments >= 1 &&
  /^[0-9a-f]{64}$/.test(/** @type {RetainedToken} */ (token).sha256);

/**
 * Creates a client. Every method sends exactly one request and never retries.
 * @param {ClientOptions} options
 */
export function createRpcClient(options) {
  const { url, accessHeader, timeoutMs = DEFAULT_TIMEOUT_MS, maxResponseBytes = MAX_RESPONSE_BYTES } = options;
  const send = options.fetch ?? globalThis.fetch;
  if (typeof url !== "string" || !url) throw new TypeError("url is required");
  if (typeof send !== "function") throw new TypeError("no fetch implementation available");
  let counter = 0;

  /**
   * Sends one JSON-RPC request and returns its result.
   * @param {string} method @param {unknown[]} [params] @returns {Promise<any>}
   */
  async function call(method, params = []) {
    if (typeof method !== "string" || !method) throw new TypeError("method is required");
    if (!Array.isArray(params)) throw new TypeError("params must be an array");
    const id = ++counter;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    if (new TextEncoder().encode(body).length > MAX_REQUEST_BYTES) throw new RangeError(`${method}: request exceeds ${MAX_REQUEST_BYTES} bytes`);
    /** @type {Record<string, string>} */
    const headers = { "Content-Type": "application/json" };
    // The gateway answers getGenesisHash without a proof; the wallets send none.
    const access = method === "getGenesisHash" || !accessHeader ? undefined : await accessHeader(method);
    if (access !== undefined) headers["X-Testnet-Access"] = access;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let status, value;
    try {
      const response = await send(url, { method: "POST", headers, body, credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal });
      status = response.status;
      if (!response.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) throw new TransportError(method, "response", `HTTP ${status} without a JSON body`);
      value = await boundedJSON(method, response, maxResponseBytes);
    } catch (error) {
      if (error instanceof TransportError) throw error;
      if (controller.signal.aborted) throw new TransportError(method, "timeout", `no answer within ${timeoutMs} ms`, error);
      throw new TransportError(method, "network", "request failed", error);
    } finally { clearTimeout(timer); }
    if (status < 200 || status > 299) throw new HttpError(method, status, value);
    if (!value || typeof value !== "object" || value.jsonrpc !== "2.0" || value.id !== id ||
        Object.hasOwn(value, "result") === Object.hasOwn(value, "error")) throw new TransportError(method, "response", "response is not the answer to this request");
    if (Object.hasOwn(value, "error")) throw new RpcError(method, value.error && typeof value.error === "object" ? value.error : {});
    return value.result;
  }

  return {
    call,
    // Standard methods. Results are passed through as the node returns them.
    /** @returns {Promise<string>} The base58 genesis hash. Compare it with your network before anything else. */
    getGenesisHash: () => call("getGenesisHash"),
    /** @param {Commitment} [commitment] @returns {Promise<number>} */
    getSlot: (commitment = "finalized") => call("getSlot", [{ commitment }]),
    /** @param {Commitment} [commitment] @returns {Promise<number>} */
    getBlockHeight: (commitment = "finalized") => call("getBlockHeight", [{ commitment }]),
    /** @param {string} address @param {Commitment} [commitment] @returns {Promise<WithContext<AccountInfo | null>>} */
    getAccountInfo: (address, commitment = "finalized") => call("getAccountInfo", [address, { commitment, encoding: "base64" }]),
    /** @param {string} address @param {Commitment} [commitment] @returns {Promise<WithContext<number>>} */
    getBalance: (address, commitment = "finalized") => call("getBalance", [address, { commitment }]),
    /** @param {Commitment} [commitment] @returns {Promise<WithContext<{ blockhash: string, lastValidBlockHeight: number }>>} */
    getLatestBlockhash: (commitment = "finalized") => call("getLatestBlockhash", [{ commitment }]),
    /** @param {number} slot @param {object} [config] Defaults to {@link FULL_BLOCK_CONFIG}. @returns {Promise<Block | null>} */
    getBlock: (slot, config = FULL_BLOCK_CONFIG) => call("getBlock", [slot, config]),
    /** @param {number} start @param {number} end @returns {Promise<number[]>} Produced finalized slots in the inclusive range. */
    getBlocks: (start, end) => call("getBlocks", [start, end, { commitment: "finalized" }]),
    /**
     * Forwards a signed transaction. Gateways do not inspect it. The browser gateway does not offer this method.
     * @param {string} transaction Base64 of the signed transaction. @param {object} [config] @returns {Promise<string>} The signature.
     */
    sendTransaction: (transaction, config = { encoding: "base64" }) => call("sendTransaction", [transaction, config]),

    // Relay methods, answered by a gateway with a shielded relay attached.
    /** @returns {Promise<ShieldedFeeQuote>} */
    getShieldedFeeQuote: () => call("getShieldedFeeQuote", []),
    /**
     * Hands one shielded-fee payment to the relay. Sending the same packet again
     * returns the same id. Any failure leaves the outcome unknown: resolve the
     * saved payment from finalized history before building another.
     * @param {ShieldedPacket} packet @returns {Promise<{ id: string }>}
     */
    submitShieldedPayment: packet => {
      if (!packet || typeof packet !== "object" || Object.keys(packet).sort().join("|") !== "network|payload" || typeof packet.payload !== "string") throw new TypeError("packet must be exactly { network, payload }");
      return call("submitShieldedPayment", [packet]);
    },
    /** @param {string} id 64 lowercase hex digits. @returns {Promise<ShieldedPaymentStatus>} */
    getShieldedPaymentStatus: id => {
      if (typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id)) throw new TypeError("id must be 64 lowercase hex digits");
      return call("getShieldedPaymentStatus", [id]);
    },

    // Bounded wallet reads, answered by a gateway.
    /**
     * Several small reads in one request. Each result repeats its request.
     * @param {ReadCall[]} calls 1 to 16 calls of {@link READ_BATCH_METHODS}.
     * @returns {Promise<{ request: ReadCall, result: unknown }[]>}
     */
    getWalletReadBatch: calls => {
      if (!Array.isArray(calls) || calls.length < 1 || calls.length > 16 || calls.some(item => !item || !READ_BATCH_METHODS.includes(item.method) || !Array.isArray(item.params))) throw new TypeError("1 to 16 calls of the bounded read methods are required");
      return call("getWalletReadBatch", [calls.map(({ method, params }) => ({ method, params }))]);
    },
    /**
     * Full finalized blocks for the given slots.
     * @param {number[]} slots 1 to 256 strictly increasing slots, each at least 1.
     * @returns {Promise<{ slot: number, block: Block }[]>}
     */
    getWalletHistoryBlocks: slots => {
      if (!Array.isArray(slots) || slots.length < 1 || slots.length > 256 || slots.some((slot, index) => !natural(slot) || slot < 1 || (index > 0 && slot <= slots[index - 1]))) throw new TypeError("1 to 256 strictly increasing slots are required");
      return call("getWalletHistoryBlocks", [slots]);
    },
    /**
     * One consistent view for a sync: the pool account, the target header, the
     * saved header and, when it fits, the canonical blocks in between.
     * @param {number} savedSlot The slot of the wallet's saved checkpoint, or 0.
     * @returns {Promise<{ format: "zolana-wallet-sync-snapshot-v1", network: NetworkIdentity, genesis: string, pool: WithContext<AccountInfo>, target_header: Block, saved_header: Block | null, canonical_tail: { after_slot: number, target_slot: number, next_slot: number, complete: true, blocks: { slot: number, block: Block }[] } | null, fallback: string | null }>}
     */
    getWalletSyncSnapshot: savedSlot => {
      if (!natural(savedSlot)) throw new TypeError("savedSlot must be a non-negative integer");
      return call("getWalletSyncSnapshot", [savedSlot]);
    },
    /**
     * One page of retained history in the compact form. The result is `null`
     * when the gateway keeps no retained history; otherwise it is the input of
     * `BrowserVault.apply_compact_history_page` after its `compact_headers.data_base64`
     * field is decoded into the binary headers argument.
     * @param {number} afterSlot @param {number} targetSlot @param {RetainedToken | null} token `null` on the first page.
     * @param {16384 | 32768} [maxBlocks] An explicit page bound; omit for the default.
     * @returns {Promise<Record<string, unknown> | null>}
     */
    getWalletRetainedHistoryV3: (afterSlot, targetSlot, token, maxBlocks) => {
      if (!natural(afterSlot) || !natural(targetSlot) || !(token === null || retainedToken(token)) ||
          !(maxBlocks === undefined || maxBlocks === 16384 || maxBlocks === 32768)) throw new TypeError("invalid retained history request");
      const cursor = token === null ? null : { segments: token.segments, sha256: token.sha256 };
      return call("getWalletRetainedHistoryV3", maxBlocks === undefined ? [afterSlot, targetSlot, cursor] : [afterSlot, targetSlot, cursor, maxBlocks]);
    },
    /**
     * One page from a canonical archive, the input of `BrowserVault.apply_archival_page`.
     * The result is `null` when the gateway has no archive.
     * @param {number} afterSlot @param {number} targetSlot At least 1 and not below `afterSlot`.
     * @param {ArchiveAnchor | null} anchor May be `null` only when `afterSlot` is 0.
     * @returns {Promise<Record<string, unknown> | null>}
     */
    getWalletCanonicalHistory: (afterSlot, targetSlot, anchor) => {
      if (!natural(afterSlot) || !natural(targetSlot) || targetSlot === 0 || afterSlot > targetSlot || (anchor === null && afterSlot !== 0)) throw new TypeError("invalid canonical history request");
      return call("getWalletCanonicalHistory", [afterSlot, targetSlot, anchor]);
    },
  };
}

/** @param {string} method @param {Response} response @param {number} limit */
async function boundedJSON(method, response, limit) {
  const reader = response.body?.getReader();
  if (!reader) throw new TransportError(method, "response", "response has no body");
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.length;
      if (size > limit) { await reader.cancel(); throw new TransportError(method, "response", `response exceeds ${limit} bytes`); }
      chunks.push(next.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch (error) { throw new TransportError(method, "response", "response is not JSON", error); }
}
