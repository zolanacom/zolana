/**
 * Types for the Zolana browser core (`clients/browser-core`), built for the web
 * with `sh sdk/build-browser-core.sh`.
 *
 * wasm-bindgen writes its own `browser_core.d.ts` next to the build output. That
 * file is correct but types every JSON result as `string`. This file describes
 * the same exports and adds the JSON shapes, as far as the Rust source fixes
 * them. To use it, copy it over `clients/browser-core/pkg/browser_core.d.ts`.
 *
 * Written by hand from the `#[wasm_bindgen]` items in `clients/browser-core/src`
 * (`lib.rs`, `vault.rs`, `session.rs`, `access.rs`). `browser-core-types.test.mjs`
 * fails when the exported names here and there differ.
 *
 * Version 0.1, experimental. Names, shapes and formats can change without notice.
 *
 * Conventions that hold for every export:
 * - Rust `u64` arguments are `bigint`. `u64` values inside returned JSON are JSON
 *   numbers, so `JSON.parse` yields `number`.
 * - Byte arguments and byte results are `Uint8Array`. Byte fields inside returned
 *   JSON are arrays of numbers.
 * - A failing `BrowserVault` call throws a string of the form
 *   `zolana-wallet-error-v1:<code>` ({@link WalletErrorText}), not an `Error`.
 * - The core makes no network request and stores nothing. The caller owns
 *   transport and durable storage of the opaque encrypted records.
 */

/**
 * A string holding JSON whose parsed value has type `T`.
 * Read it with `JSON.parse(text) as T`.
 */
export type Json<T> = string & { readonly __json?: T };

/** The stable codes of {@link WalletErrorText}; see `clients/browser-core/src/error.rs`. */
export type WalletErrorCode =
  | "authentication"
  | "password"
  | "backup"
  | "network"
  | "configuration"
  | "locked"
  | "recovery"
  | "history"
  | "sync_required"
  | "review"
  | "internal";

/** What a failing `BrowserVault` call, `prepare_wallet_prover` or `vault_acceptance` throws. */
export type WalletErrorText = `zolana-wallet-error-v1:${WalletErrorCode}`;

/**
 * Identifies one network. `network` is the 32-byte domain as an array of
 * numbers; `genesis_hash` is the base58 genesis hash. No other field is accepted.
 */
export interface NetworkIdentity {
  network: number[];
  genesis_hash: string;
}

export interface PublicIdentity {
  format: "zolana-browser-vault-identity-v1";
  network: NetworkIdentity;
  /** The shielded receiving address, `npriv1…`. */
  private_address: string;
  /** Base58 public key derived from the seed. */
  public_address: string;
  /** Base58 public key that signs access proofs and identifies a cohort member. */
  fee_address: string;
}

export interface CheckpointInfo {
  slot: number;
  /** `null` exactly when `slot` is 0. */
  block_hash: string | null;
  block_height: number;
}

/** Identifies one retained-history snapshot across its pages. */
export interface RetainedToken {
  /** 1 to 16384. */
  segments: number;
  /** 64 lowercase hex digits. */
  sha256: string;
}

export interface SyncProgress {
  /** Last replayed slot. */
  slot: number;
  /** The finalized slot this sync must reach. */
  target: number;
  block_height: number;
  token: RetainedToken | null;
  complete: boolean;
}

/**
 * A transaction as `getBlock` returns it with `encoding: "base64"` and
 * `transactionDetails: "full"`. Only these fields are read.
 */
export interface HistoryTransaction {
  transaction: [base64: string, encoding: "base64"];
  meta: {
    /** `null` for a successful transaction. Failed transactions are skipped. */
    err: unknown;
    /** Read only when the transaction uses address lookup tables. */
    loadedAddresses?: { writable: string[]; readonly: string[] };
    [field: string]: unknown;
  };
  [field: string]: unknown;
}

/** One finalized block. No other field is accepted. */
export interface HistoryBlock {
  slot: number;
  parent_slot: number;
  blockhash: string;
  previous_blockhash: string;
  block_height: number;
  transactions: HistoryTransaction[];
}

/** Input of {@link BrowserVault.apply_history_page}. No other field is accepted. */
export interface RetainedHistoryPage {
  network: NetworkIdentity;
  checkpoint: RetainedToken;
  retained_tip: number;
  after_slot: number;
  through_slot: number;
  next_slot: number;
  complete: boolean;
  /** At most 32768 blocks. */
  blocks: HistoryBlock[];
}

/** Metadata input of {@link BrowserVault.apply_compact_history_page}. */
export interface CompactHistoryMetadata {
  network: NetworkIdentity;
  checkpoint: RetainedToken;
  retained_tip: number;
  after_slot: number;
  through_slot: number;
  next_slot: number;
  complete: boolean;
  compact_headers: {
    format: "zolana-retained-headers-v1";
    /** Number of block headers in the binary `headers` argument, at most 32768. */
    count: number;
    /** `null` exactly when `count` is 0. */
    parent_slot: number | null;
    /** `null` exactly when `count` is 0. */
    previous_blockhash: string | null;
  };
  /** Pairs of a header index and that block's transactions. */
  transactions: [headerIndex: number, transactions: HistoryTransaction[]][];
}

/** Input of {@link BrowserVault.apply_archival_page}. No other top-level field is accepted. */
export interface ArchivalPage {
  network: NetworkIdentity;
  anchor: { slot: number; blockhash: string; block_height: number };
  after_slot: number;
  next_slot: number;
  complete: boolean;
  /** 1 to 16 entries. `block` is a `getBlock` result; these fields are read. */
  blocks: {
    slot: number;
    block: {
      parentSlot: number;
      blockhash: string;
      previousBlockhash: string;
      blockHeight: number;
      transactions: HistoryTransaction[];
      [field: string]: unknown;
    };
  }[];
}

export interface PaymentStatus {
  /** Decimal string of native units. */
  balance: string;
  /** Decimal string: the most that the two largest unspent notes can pay. */
  max_payment: string;
  slot: number;
  block_height: number;
  verified: true;
  finality_source: string;
}

/**
 * The relay's answer to `getShieldedFeeQuote`, as `build_payment` requires it.
 * Other fields are ignored.
 */
export interface ShieldedFeeQuote {
  format: "native-shielded-fee-quote-v1";
  network: NetworkIdentity;
  /** Base58 account that receives the fee. */
  payer: string;
  /** Native units; above 0 and at most the caller's `maximum_fee`. */
  fee: number;
  transport: "native-inline-v1";
  pool_format: "NPOOL004";
}

export interface BuiltPayment {
  /** 64 hex digits: the digest of the payment bytes. */
  packet_id: string;
  /** Opaque encrypted record. Store it durably before submitting anything. */
  encrypted_pending: number[];
  /** Decimal string of native units. */
  amount: string;
  /** Decimal string of native units. */
  fee: string;
  expires_at: number;
  /** Milliseconds per build phase, keyed by phase name. */
  build_timings_ms: Record<string, number>;
}

export interface PendingPacket {
  /** 64 hex digits; equal to {@link BuiltPayment.packet_id}. */
  id: string;
  /** The single parameter of `submitShieldedPayment`. */
  packet: { network: NetworkIdentity; payload: string };
  created_slot: number;
  created_height: number;
  expires_at: number;
}

export type PendingOutcome =
  | {
      packet_id: string;
      decision: "accepted";
      /** Base58 signature of the transaction that carried the payment. */
      signature: string;
      slot: number;
      /** Opaque encrypted record. */
      encrypted_receipt: number[];
    }
  | { packet_id: string; decision: "expired-absent"; encrypted_receipt: number[] }
  | { packet_id: string; decision: "unknown" };

/** The decoded value of the `X-Testnet-Access` header and of admission proofs. */
export interface AccessProof {
  purpose: "rpc" | "join" | "status";
  network: NetworkIdentity;
  audience: string;
  fee_address: string;
  /** Seconds since the Unix epoch. */
  issued_at: number;
  /** `issued_at` plus 600. */
  expires_at: number;
  nonce: string;
  /** Hex BLAKE2b-256 of the request body the proof covers. */
  body_digest: string;
  /** Base58 Ed25519 signature by the fee key. */
  signature: string;
}

/** The request body for the admission service's join route. */
export interface AdmissionRequest {
  claim: {
    format: "native-test-grant-v1";
    network: NetworkIdentity;
    private_address: string;
    fee_address: string;
    signature: string;
  };
  invitation: string | null;
  proof: AccessProof;
}

/**
 * An owned handle to one wallet. The seed stays inside Wasm memory; no method
 * returns it. Call `free()` when done.
 */
export class BrowserVault {
  private constructor();
  /** Drops the handle and wipes the seed buffer. */
  free(): void;
  [Symbol.dispose](): void;

  /**
   * Creates a wallet with a new random seed.
   * @param network_json JSON of a {@link NetworkIdentity}, at most 1024 bytes.
   * @param password 12 to 1024 bytes. Wipe your copy after the call.
   */
  static create(network_json: string, password: Uint8Array): BrowserVault;
  /**
   * Restores a wallet from the bytes {@link BrowserVault.encrypted_backup} returned.
   * @param encrypted At most 4096 bytes.
   */
  static restore(network_json: string, encrypted: Uint8Array, password: Uint8Array): BrowserVault;
  /** Unlocks a locked handle. A wrong password leaves it locked. */
  unlock(password: Uint8Array): void;
  /** Destroys the seed buffer and any sync session. The encrypted backup remains. */
  lock(): void;
  is_locked(): boolean;
  identity(): Json<PublicIdentity>;
  /** The recovery file (`native-wallet-seed-v1` JSON) as bytes. */
  encrypted_backup(): Uint8Array;

  /** Reads the position of an encrypted checkpoint returned by {@link BrowserVault.finish_sync}. */
  checkpoint_info(checkpoint: Uint8Array): Json<CheckpointInfo>;
  /**
   * Starts a sync towards the finalized pool state.
   * @param pool_json The `getAccountInfo` result for the pool account, read at
   *   finalized commitment with base64 encoding: `{ context: { slot }, value: { owner, lamports, data } }`.
   * @param header_json The target block; `blockhash` and `blockHeight` are read.
   * @param checkpoint The saved encrypted checkpoint, or an empty array for a first sync.
   * @param cached_header_json The block at the checkpoint's slot; `blockhash` is
   *   read. Parsed only when `checkpoint` is not empty.
   */
  begin_sync(
    pool_json: string,
    header_json: string,
    checkpoint: Uint8Array,
    cached_header_json: string,
  ): Json<SyncProgress>;
  /** @param page_json JSON of a {@link RetainedHistoryPage}. */
  apply_history_page(page_json: string): Json<SyncProgress>;
  /**
   * @param metadata_json JSON of a {@link CompactHistoryMetadata}.
   * @param headers Per block: two varints (slot delta, height delta) and a 32-byte hash.
   */
  apply_compact_history_page(metadata_json: string, headers: Uint8Array): Json<SyncProgress>;
  /** @param blocks_json JSON array of 1 to 256 {@link HistoryBlock}. */
  apply_canonical_blocks(blocks_json: string): Json<SyncProgress>;
  /** @param page_json JSON of an {@link ArchivalPage}. */
  apply_archival_page(page_json: string): Json<SyncProgress>;
  /**
   * Completes a sync that reached its target and reconciled with the pool.
   * Returns the new encrypted checkpoint; store it before showing a balance.
   */
  finish_sync(): Uint8Array;
  /** Requires a finished sync on this unlocked handle. */
  payment_status(): Json<PaymentStatus>;

  /**
   * Builds a shielded-fee payment and its proof. Nothing is sent.
   * @param recipient An `npriv1…` address.
   * @param amount Native units.
   * @param maximum_fee The cap the user approved; at most 100000000.
   * @param quote_json JSON of a {@link ShieldedFeeQuote}, at most 8192 bytes.
   * @param expiry Expiry slot: after the synced slot and at most 1024 slots ahead.
   * @param saved_checkpoint The stored checkpoint of the current sync.
   */
  build_payment(
    recipient: string,
    amount: bigint,
    maximum_fee: bigint,
    quote_json: string,
    expiry: bigint,
    saved_checkpoint: Uint8Array,
  ): Json<BuiltPayment>;
  /** Reads the public packet out of a stored {@link BuiltPayment.encrypted_pending}. */
  pending_packet(encrypted_pending: Uint8Array): Json<PendingPacket>;
  /** Confirms that a checkpoint is the one a pending payment was built from. */
  validate_pending_checkpoint(encrypted_pending: Uint8Array, checkpoint: Uint8Array): Json<CheckpointInfo>;
  /** Decides a pending payment from the canonical history of the current finished sync. */
  pending_outcome(encrypted_pending: Uint8Array): Json<PendingOutcome>;

  /** 64 hex digits identifying this wallet's admission claim. */
  admission_claim_id(): string;
  /**
   * The value of the `X-Testnet-Access` header: base64url of a JSON {@link AccessProof}.
   * @param audience The gateway's RPC URL; must start with `https://`.
   * @param now Seconds since the Unix epoch.
   */
  rpc_header(audience: string, now: bigint): string;
  /** The request body for joining with an invitation code. */
  admission_request(audience: string, invitation: string | null | undefined, now: bigint): Json<AdmissionRequest>;
  /** The request body for the admission status route. */
  admission_status(audience: string, now: bigint): Json<{ proof: AccessProof }>;
}

/** Builds the proving key used by {@link BrowserVault.build_payment}, once per worker. */
export function prepare_wallet_prover(): Json<{ prepared: true; elapsed_ms: number }>;

/** Runs the vault's own create, lock, unlock and restore checks on disposable keys. */
export function vault_acceptance(): Json<{
  format: "zolana-browser-vault-acceptance-v1";
  fixture_only: true;
  ok: true;
  rounds: number;
  elapsed_ms: number;
  reference: {
    format: "zolana-browser-vault-reference-v1";
    fixture_only: true;
    identity: PublicIdentity;
    encrypted_backup: number[];
    rounds: number;
  };
  checks: string[];
}>;

export function version(): Json<{
  format: "zolana-browser-core-version-v1";
  orchard: string;
  circuit: string;
  multicore: boolean;
  fixture_only: true;
}>;

/**
 * The three functions below drive a synthetic proof fixture with disposable
 * keys. They make no payment. On failure they throw a plain message string.
 */
export function prepare_prover(): Json<{
  format: "zolana-browser-prover-ready-v1";
  fixture_only: true;
  proof_key_ms: number;
  cached: boolean;
}>;

export function synthetic_fixture(): Json<{
  format: "zolana-browser-synthetic-fixture-v1";
  fixture_only: boolean;
  network_hex: string;
  funding_payload_hex: string;
  payment_payload_hex: string;
  envelope_hex: string;
  timings_ms: { funding_proof: number; payment_proof: number; local_verify: number };
}>;

export function decrypt_fixture(): Json<{
  format: "zolana-browser-decryption-v1";
  fixture_only: true;
  recipient_value: number;
  change_value: number;
  recipient_note_count: number;
  change_note_count: number;
  wrong_key_notes: number;
  witness_root_verified: true;
  elapsed_ms: number;
}>;

/** The module loader that wasm-bindgen generates for `--target web`. */
export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
export type SyncInitInput = BufferSource | WebAssembly.Module;
/** The raw Wasm exports. Only `memory` is meant for callers. */
export interface InitOutput {
  readonly memory: WebAssembly.Memory;
}
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;
/** Call and await once before anything else. Without an argument it fetches `browser_core_bg.wasm` next to the script. */
export default function init(
  module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>,
): Promise<InitOutput>;
