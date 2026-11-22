// Generated from formats.mjs. Do not edit; regenerate with TypeScript 5.9:
//   tsc --allowJs --checkJs --strict --target ES2022 --module NodeNext --lib ES2022,DOM --declaration --emitDeclarationOnly formats.mjs
/** @param {Uint8Array} bytes @returns {string} Lowercase hex. */
export function toHex(bytes: Uint8Array): string;
/** @param {string} text Hex digits; whitespace is ignored. @returns {Uint8Array} */
export function fromHex(text: string): Uint8Array;
/** @param {Uint8Array} bytes @returns {string} Base58, the form public accounts are written in. */
export function toBase58(bytes: Uint8Array): string;
/** @param {string} text @returns {Uint8Array} */
export function fromBase58(text: string): Uint8Array;
/**
 * Unkeyed BLAKE2b (RFC 7693), with the optional 16-byte personalization the
 * protocol uses for domain separation.
 * @param {Uint8Array} input
 * @param {{ length?: number, personal?: string | Uint8Array }} [options] `length` is 1 to 64 bytes, 64 by default.
 * @returns {Uint8Array}
 */
export function blake2b(input: Uint8Array, options?: {
    length?: number;
    personal?: string | Uint8Array;
}): Uint8Array;
/**
 * The identifier of a payment: BLAKE2b-256 of its bytes with the
 * personalization `NativeStageV1!!!` (`staging::payload_digest`). The relay
 * returns it from `submitShieldedPayment`, and the inline envelope carries it.
 * @param {Uint8Array | string} payment Payment bytes, or their hex.
 * @returns {string} 64 hex digits.
 */
export function paymentId(payment: Uint8Array | string): string;
/**
 * Reads the public fields of a payment, following `wire::decode`.
 *
 * The network is read from the bytes; pass `options.network` to refuse a
 * payment made for any other network. Decoding is not verification: the result
 * says what the bytes claim, not that the claim is authorized or proven.
 * @param {Uint8Array | string} payment Payment bytes, or their hex.
 * @param {{ network?: Uint8Array | string }} [options]
 * @returns {DecodedPayment}
 */
export function decodePayment(payment: Uint8Array | string, options?: {
    network?: Uint8Array | string;
}): DecodedPayment;
/**
 * Opens an inline envelope and reads the payment inside, following
 * `envelope::decode`. Pass `options.currentSlot` to apply the expiry rule the
 * program applies; without it the expiry is not checked.
 *
 * Unlike the Rust decoder this does not re-encode the payment to prove its
 * encoding canonical. A decoded envelope is not a verified payment.
 * @param {Uint8Array | string} envelope Envelope bytes, or their hex.
 * @param {{ network?: Uint8Array | string, currentSlot?: bigint | number }} [options]
 * @returns {DecodedEnvelope}
 */
export function decodeEnvelope(envelope: Uint8Array | string, options?: {
    network?: Uint8Array | string;
    currentSlot?: bigint | number;
}): DecodedEnvelope;
/**
 * Reads the pool account, following `PoolState::decode`. `data` is the
 * account's data: for a `getAccountInfo` result in Node,
 * `new Uint8Array(Buffer.from(info.value.data[0], "base64"))`.
 *
 * This checks the layout and the bookkeeping rules. It does not recompute the
 * root of the note tree from the frontier, which the Rust decoder does, and an
 * account is only as trustworthy as the endpoint that served it.
 * @param {Uint8Array | string} data Account data, or its hex.
 * @returns {PoolAccount}
 */
export function decodePoolAccount(data: Uint8Array | string): PoolAccount;
/**
 * The roots a payment may be anchored to when it executes at `slot`, following
 * `PoolState::accepted_roots`: for `NPOOL004` the roots of completed earlier
 * slots younger than {@link ANCHOR_WINDOW_SLOTS}, plus the empty root during the
 * first window; for `NPOOL003` the stored roots.
 * @param {PoolAccount} pool @param {bigint | number} slot
 * @returns {string[]} Distinct roots as hex, sorted.
 */
export function acceptedRoots(pool: PoolAccount, slot: bigint | number): string[];
/**
 * Checks the text of a shielded address (`npriv1…`), following
 * `native_wallet_core::decode_address`: the prefix, the length, the version,
 * the 4-byte checksum and, when `options` names a network, the network tag.
 * It catches a mistyped address and an address for another network.
 *
 * It does not check that the 43 address bytes are a valid shielded address;
 * the Rust decoder does that last step.
 * @param {string} text
 * @param {{ network: Uint8Array | string, genesisHash: string }} [options] The 32-byte network domain and the base58 genesis hash. Without it the network is not checked.
 * @returns {CheckedAddress}
 */
export function checkAddress(text: string, options?: {
    network: Uint8Array | string;
    genesisHash: string;
}): CheckedAddress;
/**
 * The 32-byte tag that binds a shielded address to one network: BLAKE2b-256 of
 * the network domain and the genesis hash text, personalized `NPayWalletAddrV1`.
 * @param {Uint8Array | string} network The 32-byte network domain, or its hex.
 * @param {string} genesisHash The base58 genesis hash, as `getGenesisHash` returns it.
 * @returns {string} 64 hex digits.
 */
export function addressNetworkTag(network: Uint8Array | string, genesisHash: string): string;
/** Tags of the three payment layouts (`native_payments::wire`). */
export const PAYMENT_TAGS: Readonly<{
    plain: "NPAY0001";
    withdrawal: "NPAY0002";
    shieldedFee: "NPAY0003";
}>;
/** Every payment carries exactly this many actions. */
export const ACTION_COUNT: 2;
/** Encoded size of one action. */
export const ACTION_BYTES: 884;
/** Bytes before the first action of an `NPAY0001` payment. */
export const HEADER_BYTES: 122;
/** Size of the proof of a two-action payment. */
export const PROOF_BYTES: 7264;
/** No payment is longer than this (`staging::MAX_PAYLOAD_BYTES`). */
export const MAX_PAYLOAD_BYTES: 16384;
/** The verifier accepts a payment only while its expiry is at most this many slots ahead. */
export const MAX_EXPIRY_WINDOW: 1024n;
/** Tag and header size of the inline envelope (`native_payments::envelope`). */
export const ENVELOPE_TAG: "ZOLNPAY1";
export const ENVELOPE_HEADER_BYTES: 102;
/** Sizes of the two pool account formats (`native_payments::state`). */
export const POOL_BYTES: Readonly<{
    NPOOL003: 3137;
    NPOOL004: 25728;
}>;
/** A slot root is accepted while it is younger than this many slots. */
export const ANCHOR_WINDOW_SLOTS: 512n;
/** The native payment program and its single pool account (`native_payments::native_accounts`). Development values. */
export const PROGRAM_ID: "78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh";
export const POOL_ADDRESS: "4mJMnxFhRVMQ3aNcyn2LgW8fztTjgckUvaaWrXggdAAL";
/** Root of the empty note tree, the anchor of the first payments on a network. */
export const EMPTY_ROOT: "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f";
/**
 * A refusal. For a payment, an envelope or a pool account, `code` is the name
 * of the `native_payments::Error` variant the Rust decoder returns for the
 * same input. The Rust address decoder returns text instead; for an address
 * the message carries that text and `code` is the nearest variant.
 */
export class FormatError extends Error {
    /** @param {FormatErrorCode} code @param {string} detail */
    constructor(code: FormatErrorCode, detail: string);
    code: FormatErrorCode;
}
export type FormatErrorCode = "InvalidLength" | "UnsupportedVersion" | "WrongNetwork" | "InvalidContext" | "InvalidEncoding" | "InvalidShape" | "DigestMismatch" | "Expired";
export type PaymentKind = "deposit" | "private-send" | "sponsor-withdrawal" | "recipient-withdrawal" | "shielded-fee-payment";
/**
 * The public values of one action. Every action carries a nullifier and a
 * commitment whether or not it spends or creates a real note.
 */
export type PaymentAction = {
    nullifier: string;
    randomizedKey: string;
    commitment: string;
    valueCommitment: string;
};
export type DecodedPayment = {
    /**
     * One of {@link PAYMENT_TAGS}.
     */
    tag: string;
    /**
     * What the tag and the value balance say the payment is.
     */
    kind: PaymentKind;
    /**
     * Length of the payment.
     */
    bytes: number;
    /**
     * The 32-byte network domain the payment names, as hex.
     */
    network: string;
    /**
     * {@link paymentId} of the bytes.
     */
    paymentId: string;
    /**
     * The last slot at which the verifier accepts it.
     */
    expirySlot: bigint;
    /**
     * Negative: value enters the pool. Positive: it leaves.
     */
    publicValueBalance: bigint;
    /**
     * Present for `NPAY0003` only; equal to the value balance.
     */
    shieldedFee: bigint | null;
    /**
     * Base58 of the public account debited by a deposit and paid by a sponsor withdrawal or a shielded fee.
     */
    sponsor: string;
    /**
     * Base58, present for `NPAY0002` only.
     */
    withdrawalRecipient: string | null;
    /**
     * The note tree root the proof was built against, as hex.
     */
    anchor: string;
    actions: PaymentAction[];
};
export type DecodedEnvelope = {
    bytes: number;
    paymentId: string;
    expirySlot: bigint;
    payment: DecodedPayment;
};
export type SlotAnchor = {
    slot: bigint;
    noteCount: bigint;
    root: string;
};
export type PoolAccount = {
    tag: "NPOOL003" | "NPOOL004";
    network: string;
    rentFloor: bigint;
    /**
     * Public coins held for the notes in the pool.
     */
    backing: bigint;
    /**
     * Commitments in the note tree: two per payment.
     */
    noteCount: bigint;
    /**
     * `NPOOL004`: one root per completed slot, oldest first.
     */
    slotAnchors: SlotAnchor[];
    /**
     * `NPOOL003`: the most recent roots, oldest first.
     */
    roots: string[];
};
export type CheckedAddress = {
    version: 1;
    networkTag: string;
    rawAddress: string;
};
