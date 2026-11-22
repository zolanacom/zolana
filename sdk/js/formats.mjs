// @ts-check
// Offline readers for Zolana's public byte formats: a payment, the inline
// envelope around one, the pool account and the shielded address text.
//
// Each reader follows the Rust decoder it names, check for check, as far as
// plain JavaScript can: lengths, tags, the network, the public fields and the
// canonical encoding of field elements. None of them verifies a signature or a
// proof, and none checks that a 32-byte key is a valid curve point or
// recomputes a tree root. The Rust decoders do; to verify a payment use the
// `inspect-payment` command in sdk/rust-examples.
//
// Version 0.1, experimental. The formats are not a released protocol.
// No dependencies. Needs BigInt, TextEncoder and Uint8Array (Node or a browser).

/** Tags of the three payment layouts (`native_payments::wire`). */
export const PAYMENT_TAGS = Object.freeze({ plain: "NPAY0001", withdrawal: "NPAY0002", shieldedFee: "NPAY0003" });
/** Every payment carries exactly this many actions. */
export const ACTION_COUNT = 2;
/** Encoded size of one action. */
export const ACTION_BYTES = 884;
/** Bytes before the first action of an `NPAY0001` payment. */
export const HEADER_BYTES = 122;
/** Size of the proof of a two-action payment. */
export const PROOF_BYTES = 7264;
/** No payment is longer than this (`staging::MAX_PAYLOAD_BYTES`). */
export const MAX_PAYLOAD_BYTES = 16384;
/** The verifier accepts a payment only while its expiry is at most this many slots ahead. */
export const MAX_EXPIRY_WINDOW = 1024n;
/** Tag and header size of the inline envelope (`native_payments::envelope`). */
export const ENVELOPE_TAG = "ZOLNPAY1";
export const ENVELOPE_HEADER_BYTES = 102;
/** Sizes of the two pool account formats (`native_payments::state`). */
export const POOL_BYTES = Object.freeze({ NPOOL003: 3137, NPOOL004: 25728 });
/** A slot root is accepted while it is younger than this many slots. */
export const ANCHOR_WINDOW_SLOTS = 512n;
/** The native payment program and its single pool account (`native_payments::native_accounts`). Development values. */
export const PROGRAM_ID = "78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh";
export const POOL_ADDRESS = "4mJMnxFhRVMQ3aNcyn2LgW8fztTjgckUvaaWrXggdAAL";
/** Root of the empty note tree, the anchor of the first payments on a network. */
export const EMPTY_ROOT = "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f";

/**
 * A refusal. For a payment, an envelope or a pool account, `code` is the name
 * of the `native_payments::Error` variant the Rust decoder returns for the
 * same input. The Rust address decoder returns text instead; for an address
 * the message carries that text and `code` is the nearest variant.
 */
export class FormatError extends Error {
  /** @param {FormatErrorCode} code @param {string} detail */
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.name = "FormatError";
    this.code = code;
  }
}
/** @typedef {"InvalidLength" | "UnsupportedVersion" | "WrongNetwork" | "InvalidContext" | "InvalidEncoding" | "InvalidShape" | "DigestMismatch" | "Expired"} FormatErrorCode */
/** @typedef {"deposit" | "private-send" | "sponsor-withdrawal" | "recipient-withdrawal" | "shielded-fee-payment"} PaymentKind */
/**
 * The public values of one action. Every action carries a nullifier and a
 * commitment whether or not it spends or creates a real note.
 * @typedef {{ nullifier: string, randomizedKey: string, commitment: string, valueCommitment: string }} PaymentAction
 */
/**
 * @typedef {object} DecodedPayment
 * @property {string} tag One of {@link PAYMENT_TAGS}.
 * @property {PaymentKind} kind What the tag and the value balance say the payment is.
 * @property {number} bytes Length of the payment.
 * @property {string} network The 32-byte network domain the payment names, as hex.
 * @property {string} paymentId {@link paymentId} of the bytes.
 * @property {bigint} expirySlot The last slot at which the verifier accepts it.
 * @property {bigint} publicValueBalance Negative: value enters the pool. Positive: it leaves.
 * @property {bigint | null} shieldedFee Present for `NPAY0003` only; equal to the value balance.
 * @property {string} sponsor Base58 of the public account debited by a deposit and paid by a sponsor withdrawal or a shielded fee.
 * @property {string | null} withdrawalRecipient Base58, present for `NPAY0002` only.
 * @property {string} anchor The note tree root the proof was built against, as hex.
 * @property {PaymentAction[]} actions
 */
/** @typedef {{ bytes: number, paymentId: string, expirySlot: bigint, payment: DecodedPayment }} DecodedEnvelope */
/** @typedef {{ slot: bigint, noteCount: bigint, root: string }} SlotAnchor */
/**
 * @typedef {object} PoolAccount
 * @property {"NPOOL003" | "NPOOL004"} tag
 * @property {string} network
 * @property {bigint} rentFloor
 * @property {bigint} backing Public coins held for the notes in the pool.
 * @property {bigint} noteCount Commitments in the note tree: two per payment.
 * @property {SlotAnchor[]} slotAnchors `NPOOL004`: one root per completed slot, oldest first.
 * @property {string[]} roots `NPOOL003`: the most recent roots, oldest first.
 */
/** @typedef {{ version: 1, networkTag: string, rawAddress: string }} CheckedAddress */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const U64 = (1n << 64n) - 1n;
const I64_MAX = (1n << 63n) - 1n;
/** Order of the field that nullifiers, commitments and roots are elements of. */
const FIELD_MODULUS = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;
/** `state::MAX_COMMITMENTS`. */
const MAX_COMMITMENTS = (1n << 32n) - 2n;
const ascii = (/** @type {string} */ text) => new TextEncoder().encode(text);

/** @param {Uint8Array} bytes @returns {string} Lowercase hex. */
export function toHex(bytes) {
  let text = "";
  for (const byte of bytes) text += byte.toString(16).padStart(2, "0");
  return text;
}
/** @param {string} text Hex digits; whitespace is ignored. @returns {Uint8Array} */
export function fromHex(text) {
  const digits = typeof text === "string" ? text.replace(/\s+/g, "") : "";
  if (typeof text !== "string" || digits.length % 2 !== 0 || /[^0-9a-fA-F]/.test(digits)) throw new TypeError("not hex");
  const bytes = new Uint8Array(digits.length / 2);
  for (let index = 0; index < bytes.length; index++) bytes[index] = parseInt(digits.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}
/** @param {Uint8Array} bytes @returns {string} Base58, the form public accounts are written in. */
export function toBase58(bytes) {
  let number = 0n, zeros = 0, text = "";
  for (const byte of bytes) number = (number << 8n) | BigInt(byte);
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  for (; number > 0n; number /= 58n) text = ALPHABET[Number(number % 58n)] + text;
  return "1".repeat(zeros) + text;
}
/** @param {string} text @returns {Uint8Array} */
export function fromBase58(text) {
  if (typeof text !== "string") throw new TypeError("not base58");
  let number = 0n, zeros = 0;
  for (const character of text) {
    const digit = ALPHABET.indexOf(character);
    if (digit < 0) throw new TypeError("not base58");
    number = number * 58n + BigInt(digit);
  }
  while (zeros < text.length && text[zeros] === "1") zeros++;
  const tail = [];
  for (; number > 0n; number >>= 8n) tail.unshift(Number(number & 0xffn));
  const bytes = new Uint8Array(zeros + tail.length);
  bytes.set(tail, zeros);
  return bytes;
}

const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const rotate = (/** @type {bigint} */ word, /** @type {bigint} */ by) => ((word >> by) | (word << (64n - by))) & U64;

/**
 * Unkeyed BLAKE2b (RFC 7693), with the optional 16-byte personalization the
 * protocol uses for domain separation.
 * @param {Uint8Array} input
 * @param {{ length?: number, personal?: string | Uint8Array }} [options] `length` is 1 to 64 bytes, 64 by default.
 * @returns {Uint8Array}
 */
export function blake2b(input, options = {}) {
  const { length = 64 } = options;
  const personal = typeof options.personal === "string" ? ascii(options.personal) : options.personal ?? new Uint8Array(0);
  if (!(input instanceof Uint8Array)) throw new TypeError("input must be a Uint8Array");
  if (!Number.isInteger(length) || length < 1 || length > 64) throw new RangeError("length must be 1 to 64");
  if (personal.length !== 0 && personal.length !== 16) throw new RangeError("personal must be 16 bytes");
  const parameters = new Uint8Array(64);
  parameters.set([length, 0, 1, 1]);
  parameters.set(personal, 48);
  const view = new DataView(parameters.buffer);
  const state = IV.map((word, index) => word ^ view.getBigUint64(index * 8, true));
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  const block = new Uint8Array(128), words = new DataView(block.buffer);
  for (let index = 0; index < blocks; index++) {
    const chunk = input.subarray(index * 128, index * 128 + 128);
    block.fill(0);
    block.set(chunk);
    const last = index === blocks - 1;
    const v = [...state, ...IV];
    v[12] ^= BigInt(index * 128 + chunk.length);
    if (last) v[14] ^= U64;
    const m = Array.from({ length: 16 }, (_, word) => words.getBigUint64(word * 8, true));
    const mix = (/** @type {number} */ a, /** @type {number} */ b, /** @type {number} */ c, /** @type {number} */ d, /** @type {bigint} */ x, /** @type {bigint} */ y) => {
      v[a] = (v[a] + v[b] + x) & U64; v[d] = rotate(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & U64; v[b] = rotate(v[b] ^ v[c], 24n);
      v[a] = (v[a] + v[b] + y) & U64; v[d] = rotate(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & U64; v[b] = rotate(v[b] ^ v[c], 63n);
    };
    for (let round = 0; round < 12; round++) {
      const s = SIGMA[round % 10];
      mix(0, 4, 8, 12, m[s[0]], m[s[1]]); mix(1, 5, 9, 13, m[s[2]], m[s[3]]);
      mix(2, 6, 10, 14, m[s[4]], m[s[5]]); mix(3, 7, 11, 15, m[s[6]], m[s[7]]);
      mix(0, 5, 10, 15, m[s[8]], m[s[9]]); mix(1, 6, 11, 12, m[s[10]], m[s[11]]);
      mix(2, 7, 8, 13, m[s[12]], m[s[13]]); mix(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let word = 0; word < 8; word++) state[word] ^= v[word] ^ v[word + 8];
  }
  const digest = new Uint8Array(64), out = new DataView(digest.buffer);
  state.forEach((word, index) => out.setBigUint64(index * 8, word, true));
  return digest.slice(0, length);
}

/** Reads consecutive fields and refuses to run past the end. */
class Reader {
  /** @param {Uint8Array} bytes */
  constructor(bytes) { this.bytes = bytes; this.offset = 0; }
  get remaining() { return this.bytes.length - this.offset; }
  /** @param {number} count */
  take(count) {
    if (count > this.remaining) throw new FormatError("InvalidLength", "the bytes end early");
    this.offset += count;
    return this.bytes.subarray(this.offset - count, this.offset);
  }
  /** @param {number} count */
  text(count) { return String.fromCharCode(...this.take(count)); }
  u16() { return this.take(2).reduce((value, byte, index) => value | (byte << (8 * index)), 0); }
  u32() { return this.take(4).reduce((value, byte, index) => value + byte * 2 ** (8 * index), 0); }
  u64() { return this.take(8).reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n); }
  i64() { return BigInt.asIntN(64, this.u64()); }
  /** A canonical field element, as hex: 32 little-endian bytes below the field order. */
  element() {
    const bytes = this.take(32);
    if (bytes.reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n) >= FIELD_MODULUS) throw new FormatError("InvalidEncoding", "a field element is not canonical");
    return toHex(bytes);
  }
}
const zero = (/** @type {Uint8Array} */ bytes) => bytes.every(byte => byte === 0);
/** @param {unknown} value @param {string} name @returns {Uint8Array} */
function input(value, name) {
  if (typeof value === "string") return fromHex(value);
  if (value instanceof Uint8Array) return value;
  throw new TypeError(`${name} must be a Uint8Array or hex`);
}
/** @param {Uint8Array} named @param {unknown} expected */
function checkNetwork(named, expected) {
  if (zero(named)) throw new FormatError("WrongNetwork", "the network is all zeros");
  if (expected === undefined) return;
  const wanted = input(expected, "network");
  if (wanted.length !== 32 || toHex(wanted) !== toHex(named)) throw new FormatError("WrongNetwork", "the bytes name another network");
}

/**
 * The identifier of a payment: BLAKE2b-256 of its bytes with the
 * personalization `NativeStageV1!!!` (`staging::payload_digest`). The relay
 * returns it from `submitShieldedPayment`, and the inline envelope carries it.
 * @param {Uint8Array | string} payment Payment bytes, or their hex.
 * @returns {string} 64 hex digits.
 */
export function paymentId(payment) {
  return toHex(blake2b(input(payment, "payment"), { length: 32, personal: "NativeStageV1!!!" }));
}

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
export function decodePayment(payment, options = {}) {
  const bytes = input(payment, "payment");
  const tag = String.fromCharCode(...bytes.subarray(0, 8));
  const extra = tag === PAYMENT_TAGS.shieldedFee ? 8 : tag === PAYMENT_TAGS.withdrawal ? 32 : 0;
  const expected = HEADER_BYTES + extra + ACTION_COUNT * ACTION_BYTES + 4 + PROOF_BYTES + 64;
  if (bytes.length !== expected || bytes.length > MAX_PAYLOAD_BYTES) throw new FormatError("InvalidLength", `a payment with this tag is ${expected} bytes`);
  if (!(/** @type {readonly string[]} */ (Object.values(PAYMENT_TAGS))).includes(tag)) throw new FormatError("UnsupportedVersion", "unknown payment tag");
  const reader = new Reader(bytes);
  reader.take(8);
  const network = reader.take(32);
  checkNetwork(network, options.network);
  const expirySlot = reader.u64(), publicValueBalance = reader.i64(), sponsor = reader.take(32);
  const shieldedFee = tag === PAYMENT_TAGS.shieldedFee ? reader.u64() : null;
  const recipient = tag === PAYMENT_TAGS.withdrawal ? reader.take(32) : null;
  if (shieldedFee !== null && (shieldedFee === 0n || shieldedFee > I64_MAX || publicValueBalance !== shieldedFee)) throw new FormatError("InvalidContext", "the shielded fee must be positive and equal to the value balance");
  if (zero(sponsor)) throw new FormatError("InvalidContext", "the sponsor is all zeros");
  if (recipient !== null && (zero(recipient) || publicValueBalance <= 0n)) throw new FormatError("InvalidContext", "a withdrawal needs a recipient and a positive value balance");
  const anchor = reader.element();
  if (reader.take(1)[0] !== 3 || reader.take(1)[0] !== ACTION_COUNT) throw new FormatError("InvalidShape", "unexpected flags or action count");
  /** @type {PaymentAction[]} */
  const actions = [];
  for (let index = 0; index < ACTION_COUNT; index++) {
    const nullifier = reader.element(), randomizedKey = toHex(reader.take(32)), commitment = reader.element();
    reader.take(32 + 580 + 80); // the ephemeral key and the two ciphertexts
    actions.push({ nullifier, randomizedKey, commitment, valueCommitment: toHex(reader.take(32)) });
    reader.take(64); // the spend authorization signature
  }
  if (reader.u32() !== PROOF_BYTES) throw new FormatError("InvalidLength", "unexpected proof length");
  reader.take(PROOF_BYTES + 64); // the proof and the binding signature
  /** @type {PaymentKind} */
  const kind = shieldedFee !== null ? "shielded-fee-payment" : recipient !== null ? "recipient-withdrawal" :
    publicValueBalance < 0n ? "deposit" : publicValueBalance === 0n ? "private-send" : "sponsor-withdrawal";
  return {
    tag, kind, bytes: bytes.length, network: toHex(network), paymentId: paymentId(bytes), expirySlot, publicValueBalance, shieldedFee,
    sponsor: toBase58(sponsor), withdrawalRecipient: recipient && toBase58(recipient), anchor, actions,
  };
}

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
export function decodeEnvelope(envelope, options = {}) {
  const bytes = input(envelope, "envelope");
  if (bytes.length <= ENVELOPE_HEADER_BYTES || bytes.length > MAX_PAYLOAD_BYTES) throw new FormatError("InvalidLength", "not the size of an envelope");
  const reader = new Reader(bytes);
  if (reader.text(8) !== ENVELOPE_TAG || reader.u16() !== 1) throw new FormatError("UnsupportedVersion", "unknown envelope tag or version");
  if (reader.text(16) !== "ZolanaNativePay!") throw new FormatError("InvalidContext", "unknown framing domain");
  const network = reader.take(32);
  checkNetwork(network, options.network);
  const expirySlot = reader.u64(), id = toHex(reader.take(32)), length = reader.u32();
  if (length === 0 || length > MAX_PAYLOAD_BYTES - ENVELOPE_HEADER_BYTES || reader.remaining !== length) throw new FormatError("InvalidLength", "the payment length does not match the envelope");
  const payload = reader.take(length);
  if (paymentId(payload) !== id) throw new FormatError("DigestMismatch", "the payment is not the one the envelope names");
  const decoded = decodePayment(payload, { network });
  if (decoded.shieldedFee === null) throw new FormatError("UnsupportedVersion", "only a payment with a shielded fee has an envelope");
  if (decoded.expirySlot !== expirySlot) throw new FormatError("InvalidContext", "the envelope and the payment disagree on the expiry");
  if (options.currentSlot !== undefined) {
    const slot = BigInt(options.currentSlot);
    if (expirySlot < slot) throw new FormatError("Expired", `the payment expired at slot ${expirySlot}`);
    if (expirySlot - slot > MAX_EXPIRY_WINDOW) throw new FormatError("InvalidContext", "the expiry is too far ahead");
  }
  return { bytes: bytes.length, paymentId: id, expirySlot, payment: decoded };
}

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
export function decodePoolAccount(data) {
  const bytes = input(data, "data");
  const tag = String.fromCharCode(...bytes.subarray(0, 8));
  const refuse = (/** @type {string} */ detail) => new FormatError("InvalidEncoding", detail);
  if (tag !== "NPOOL003" && tag !== "NPOOL004" || bytes.length !== POOL_BYTES[tag]) throw refuse("not a pool account");
  const reader = new Reader(bytes);
  reader.take(8);
  const network = reader.take(32), rentFloor = reader.u64(), backing = reader.u64(), noteCount = reader.u64();
  const rootCount = tag === "NPOOL003" ? reader.take(1)[0] : 0;
  if (zero(network) || backing > I64_MAX || noteCount > MAX_COMMITMENTS || noteCount % 2n !== 0n) throw refuse("invalid pool header");
  if (tag === "NPOOL003" && (rootCount === 0 || rootCount > 64)) throw refuse("invalid root count");
  // The frontier holds one node for every set bit of the note count.
  for (let level = 0n; level < 32n; level++) {
    if ((noteCount >> level) & 1n) reader.element();
    else if (!zero(reader.take(32))) throw refuse("unexpected frontier node");
  }
  /** @type {PoolAccount} */
  const pool = { tag, network: toHex(network), rentFloor, backing, noteCount, slotAnchors: [], roots: [] };
  if (tag === "NPOOL003") {
    for (let index = 0; index < 64; index++) {
      if (index < rootCount) pool.roots.push(reader.element());
      else if (!zero(reader.take(32))) throw refuse("unexpected root");
    }
    return pool;
  }
  const historyBytes = reader.u32();
  if (historyBytes > 60 + 512 * 48) throw new FormatError("InvalidLength", "the anchor history is too long");
  const history = new Reader(reader.take(historyBytes));
  if (!zero(reader.take(reader.remaining))) throw refuse("the padding is not zero");
  // The anchor history (`AnchorHistory::decode`): a header, then one entry per slot.
  if (historyBytes < 60) throw new FormatError("InvalidLength", "the anchor history is too short");
  if (history.text(8) !== "ZOLANCH1" || history.u16() !== 1) throw new FormatError("UnsupportedVersion", "unknown anchor history");
  if (history.text(16) !== "ZolanaSlotRoots1") throw new FormatError("InvalidContext", "unknown anchor history domain");
  if (toHex(history.take(32)) !== pool.network) throw new FormatError("WrongNetwork", "the anchor history names another network");
  const count = history.u16();
  if (count > 512 || history.remaining !== count * 48) throw new FormatError("InvalidLength", "the anchor history length does not match its count");
  for (let index = 0; index < count; index++) {
    const entry = { slot: history.u64(), noteCount: history.u64(), root: history.element() };
    const previous = pool.slotAnchors.at(-1);
    if (entry.noteCount > MAX_COMMITMENTS || entry.noteCount % 2n !== 0n || /^0+$/.test(entry.root) || (entry.noteCount === 0n) !== (entry.root === EMPTY_ROOT)) throw refuse("invalid slot anchor");
    if (previous && (entry.slot <= previous.slot || entry.noteCount < previous.noteCount || (entry.noteCount === previous.noteCount) !== (entry.root === previous.root))) throw refuse("slot anchors do not progress");
    if (pool.slotAnchors.some(other => other.root === entry.root && other.noteCount !== entry.noteCount)) throw refuse("a root is reused for another tree");
    pool.slotAnchors.push(entry);
  }
  const first = pool.slotAnchors[0], last = pool.slotAnchors.at(-1);
  if (first && last && last.slot - first.slot >= ANCHOR_WINDOW_SLOTS) throw refuse("the slot anchors span more than the window");
  if (last && last.noteCount > noteCount) throw refuse("a slot anchor is ahead of the pool");
  return pool;
}

/**
 * The roots a payment may be anchored to when it executes at `slot`, following
 * `PoolState::accepted_roots`: for `NPOOL004` the roots of completed earlier
 * slots younger than {@link ANCHOR_WINDOW_SLOTS}, plus the empty root during the
 * first window; for `NPOOL003` the stored roots.
 * @param {PoolAccount} pool @param {bigint | number} slot
 * @returns {string[]} Distinct roots as hex, sorted.
 */
export function acceptedRoots(pool, slot) {
  if (pool.tag === "NPOOL003") return [...new Set(pool.roots)].sort();
  const at = BigInt(slot), last = pool.slotAnchors.at(-1);
  if (last && last.slot > at) throw new FormatError("InvalidContext", "the pool has already completed a later slot");
  const roots = new Set(at < ANCHOR_WINDOW_SLOTS ? [EMPTY_ROOT] : []);
  for (const entry of pool.slotAnchors) if (entry.slot < at && at - entry.slot < ANCHOR_WINDOW_SLOTS) roots.add(entry.root);
  return [...roots].sort();
}

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
export function checkAddress(text, options) {
  if (typeof text !== "string") throw new TypeError("address must be a string");
  if (text.length > 140) throw new FormatError("InvalidLength", "invalid receiving address length");
  if (!text.startsWith("npriv1")) throw new FormatError("InvalidEncoding", "invalid receiving address prefix");
  let bytes;
  try { bytes = fromBase58(text.slice(6)); } catch { throw new FormatError("InvalidEncoding", "the address is not base58"); }
  const mismatch = () => new FormatError("WrongNetwork", "receiving address checksum or network mismatch");
  if (bytes.length !== 80 || bytes[0] !== 1 || toHex(blake2b(bytes.subarray(0, 76)).subarray(0, 4)) !== toHex(bytes.subarray(76))) throw mismatch();
  const networkTag = toHex(bytes.subarray(1, 33));
  if (options !== undefined && networkTag !== addressNetworkTag(options.network, options.genesisHash)) throw mismatch();
  return { version: 1, networkTag, rawAddress: toHex(bytes.subarray(33, 76)) };
}

/**
 * The 32-byte tag that binds a shielded address to one network: BLAKE2b-256 of
 * the network domain and the genesis hash text, personalized `NPayWalletAddrV1`.
 * @param {Uint8Array | string} network The 32-byte network domain, or its hex.
 * @param {string} genesisHash The base58 genesis hash, as `getGenesisHash` returns it.
 * @returns {string} 64 hex digits.
 */
export function addressNetworkTag(network, genesisHash) {
  const domain = input(network, "network");
  if (domain.length !== 32 || typeof genesisHash !== "string") throw new TypeError("a network is 32 bytes and a genesis hash");
  const genesis = ascii(genesisHash), joined = new Uint8Array(32 + genesis.length);
  joined.set(domain);
  joined.set(genesis, 32);
  return toHex(blake2b(joined, { length: 32, personal: "NPayWalletAddrV1" }));
}
