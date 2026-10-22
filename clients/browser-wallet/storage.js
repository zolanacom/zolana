/* Encrypted browser persistence only. No keys, proving, RPC or automatic retry.
 * The worker must authenticate/decrypt blobs and verify canonical finality.
 * SHA-256 detects stored-byte corruption; it is not a MAC or origin-compromise
 * protection. Keep the returned instanceId outside this store when possible.
 */
const FORMAT = "zolana-browser-storage-v1";
const STORES = ["meta", "blobs"];
export const STORAGE_LIMITS = Object.freeze({
  wallet: 4096, checkpoint: 32 * 1024 * 1024 + 48,
  pending: 32768, receipt: 65536,
});

export class WalletStorageError extends Error {
  constructor(code, message, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = "WalletStorageError";
    this.code = code;
  }
}
const fail = (code, message) => { throw new WalletStorageError(code, message); };
const hex = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const uuid = value => typeof value === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const keys = (value, expected) => value && typeof value === "object" &&
  !Array.isArray(value) && Object.keys(value).sort().join("|") === [...expected].sort().join("|");
const octets = (value, count) => Array.isArray(value) && value.length === count &&
  value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255);

function options(value) {
  if (!value || typeof value.dbName !== "string" ||
      !hex(value.walletId) || !hex(value.networkId) ||
      value.dbName !== walletDatabaseName(value.walletId, value.networkId)) {
    fail("invalid_input", "Explicit browser-wallet database and identity digests required.");
  }
  if (!globalThis.crypto?.subtle || !value.indexedDB?.open) {
    fail("unsupported", "A secure context with Web Crypto and IndexedDB is required.");
  }
}

// One database per wallet/network in this origin. A caller cannot evade the
// same-wallet CAS by choosing another database name. Other origins/devices are
// outside this local coordination boundary and still require chain checks.
export function walletDatabaseName(walletId, networkId) {
  if (!hex(walletId) || !hex(networkId)) fail("invalid_input", "Wallet and network digests required.");
  return `zolana-browser-wallet-${networkId}-${walletId}`;
}

function blob(value, kind) {
  if (!(value instanceof Uint8Array) || value.length < 48 || value.length > STORAGE_LIMITS[kind]) {
    fail("invalid_input", `Bounded encrypted ${kind} bytes required.`);
  }
  return value.slice(); // Never retain caller-mutable buffers.
}

function walletBlob(value) {
  const bytes = blob(value, "wallet");
  let envelope;
  try { envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { fail("invalid_input", "Native encrypted recovery envelope required."); }
  if (!keys(envelope, ["format", "network", "rounds", "salt", "nonce", "ciphertext"]) ||
      envelope.format !== "native-wallet-seed-v1" || envelope.rounds !== 600000 ||
      !keys(envelope.network, ["network", "genesis_hash"]) || !octets(envelope.network.network, 32) ||
      !envelope.network.network.some(Boolean) || typeof envelope.network.genesis_hash !== "string" ||
      !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(envelope.network.genesis_hash) ||
      !octets(envelope.salt, 16) || !octets(envelope.nonce, 24) || !octets(envelope.ciphertext, 48)) {
    fail("invalid_input", "Native encrypted recovery envelope shape differs.");
  }
  return bytes; // Shape only: the Rust worker must authenticate the ciphertext.
}

async function digest(bytes) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function meta(value, binding) {
  const expected = ["format", "walletId", "networkId", "instanceId", "revision", "walletDigest",
    "checkpointDigest", "pendingId", "pendingDigest", "lastPacketId", "lastDecision", "receiptDigest"];
  if (!keys(value, expected) || value.format !== FORMAT || !uuid(value.instanceId) ||
      !Number.isSafeInteger(value.revision) || value.revision < 0 || !hex(value.walletDigest) ||
      !["checkpointDigest", "pendingDigest", "receiptDigest"].every(key => value[key] === null || hex(value[key])) ||
      !["pendingId", "lastPacketId"].every(key => value[key] === null || hex(value[key])) ||
      (value.pendingId === null) !== (value.pendingDigest === null) ||
      (value.lastPacketId === null) !== (value.receiptDigest === null) ||
      (value.lastPacketId === null ? value.lastDecision !== null : !["accepted", "expired-absent"].includes(value.lastDecision))) {
    fail("corrupt", "Wallet storage metadata is missing or inconsistent; preserve recovery files.");
  }
  if (value.walletId !== binding.walletId || value.networkId !== binding.networkId ||
      value.instanceId !== binding.expectedInstanceId) {
    fail("binding_mismatch", "Wallet, network or storage instance differs; no reset was performed.");
  }
  return value;
}

function openDB(configuration, create) {
  return new Promise((resolve, reject) => {
    const request = configuration.indexedDB.open(configuration.dbName, 1);
    let missing = false, blocked = false;
    request.onupgradeneeded = event => {
      if (!create || event.oldVersion !== 0) {
        missing = !create;
        request.transaction.abort();
        return;
      }
      for (const name of STORES) request.result.createObjectStore(name);
    };
    request.onerror = () => reject(new WalletStorageError(missing ? "missing" : "storage_failure",
      missing ? "Expected wallet storage is absent; restore explicitly, never silently create another wallet." :
        "Cannot open wallet storage; existing state was not reset.", request.error));
    request.onblocked = () => { blocked = true; reject(new WalletStorageError("blocked", "Another tab blocks the storage schema; close it before retrying.")); };
    request.onsuccess = () => {
      const db = request.result;
      if (blocked) { db.close(); return; }
      if ([...db.objectStoreNames].sort().join("|") !== [...STORES].sort().join("|")) {
        db.close(); reject(new WalletStorageError("corrupt", "Unexpected wallet storage schema.")); return;
      }
      resolve(db);
    };
  });
}

function transaction(db, mode, work, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new WalletStorageError("aborted", "Storage operation was cancelled before commit.")); return; }
    let tx, result, failure;
    try {
      tx = mode === "readwrite" ? db.transaction(STORES, mode, { durability: "strict" }) : db.transaction(STORES, mode);
      if (mode === "readwrite" && tx.durability !== "strict") {
        tx.abort(); fail("unsupported", "This browser does not expose strict IndexedDB transaction durability.");
      }
    } catch (error) { reject(error instanceof WalletStorageError ? error : new WalletStorageError("storage_failure", "Cannot start wallet transaction.", error)); return; }
    const abort = () => { failure = new WalletStorageError("aborted", "Storage operation cancelled; reopen to inspect its original state."); try { tx.abort(); } catch { /* Completion won the race; inspect the committed revision. */ } };
    signal?.addEventListener("abort", abort, { once: true });
    const finish = () => signal?.removeEventListener("abort", abort);
    tx.oncomplete = () => { finish(); resolve(result); };
    tx.onabort = () => { finish(); reject(failure || new WalletStorageError("storage_failure", "Wallet transaction did not commit; reopen original storage.", tx.error)); };
    tx.onerror = () => { /* Preserve IndexedDB's default atomic abort. */ };
    const stop = error => { failure = error; try { tx.abort(); } catch { /* Already aborted. */ } };
    const stateRequest = tx.objectStore("meta").get("state");
    const blobsRequest = tx.objectStore("blobs").getAll();
    const blobKeys = tx.objectStore("blobs").getAllKeys();
    blobKeys.onsuccess = () => {
      try { result = work(tx, stateRequest.result, new Map(blobKeys.result.map((key, index) => [key, blobsRequest.result[index]]))); }
      catch (error) { stop(error); }
    };
  });
}

class WalletStore {
  constructor(db, configuration) {
    this.db = db;
    this.binding = Object.freeze({ walletId: configuration.walletId, networkId: configuration.networkId,
      expectedInstanceId: configuration.expectedInstanceId });
    this.closed = false;
    db.onversionchange = () => this.close();
  }
  close() { this.closed = true; this.db.close(); }
  alive() { if (this.closed) fail("closed", "Wallet storage is closed; reopen its original instance."); }
  async read(signal) {
    this.alive();
    const raw = await transaction(this.db, "readonly", (_tx, state, blobs) => ({ state, blobs }), signal);
    if (raw.state === undefined) fail("missing", "Expected wallet state is absent; use explicit encrypted-backup recovery.");
    const state = meta(raw.state, this.binding);
    const expected = new Map([["wallet", state.walletDigest], ["checkpoint", state.checkpointDigest],
      ["pending", state.pendingDigest], ["receipt", state.receiptDigest]].filter(([, pin]) => pin !== null));
    if (raw.blobs.size !== expected.size || [...raw.blobs.keys()].some(key => !expected.has(key))) fail("corrupt", "Unexpected encrypted wallet records.");
    for (const [name, pin] of expected) {
      const bytes = name === "wallet" ? walletBlob(raw.blobs.get(name)) : blob(raw.blobs.get(name), name);
      if (await digest(bytes) !== pin) fail("corrupt", "Encrypted wallet record bytes changed; no automatic reset is allowed.");
      raw.blobs.set(name, bytes);
    }
    return raw;
  }
  async snapshot({ signal } = {}) {
    const { state, blobs } = await this.read(signal);
    return Object.freeze({ walletId: state.walletId, networkId: state.networkId, instanceId: state.instanceId,
      revision: state.revision, encryptedWallet: blobs.get("wallet"), encryptedCheckpoint: blobs.get("checkpoint") || null,
      pending: state.pendingId === null ? null : Object.freeze({ packetId: state.pendingId, encryptedPacket: blobs.get("pending") }),
      lastSettlement: state.lastPacketId === null ? null : Object.freeze({ packetId: state.lastPacketId,
        decision: state.lastDecision, encryptedReceipt: blobs.get("receipt") }) });
  }
  async change(expectedRevision, update, signal) {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) fail("invalid_input", "An explicit observed revision is required.");
    const previous = await this.read(signal);
    this.alive();
    return transaction(this.db, "readwrite", (tx, current, stored) => {
      meta(current, this.binding);
      if (current.revision !== expectedRevision || JSON.stringify(current) !== JSON.stringify(previous.state)) {
        fail("revision_conflict", "Another tab or operation changed this wallet; inspect and reconcile the current state.");
      }
      // No asynchronous crypto inside the write transaction. Compare the exact
      // ciphertext previously hashed, then atomically update metadata and blobs.
      if (stored.size !== previous.blobs.size || [...stored].some(([name, bytes]) => {
        const old = previous.blobs.get(name);
        return !(bytes instanceof Uint8Array) || !old || bytes.length !== old.length || bytes.some((byte, index) => byte !== old[index]);
      })) fail("corrupt", "Encrypted records changed during the storage operation.");
      if (current.revision >= Number.MAX_SAFE_INTEGER) fail("revision_exhausted", "Storage revision is exhausted; explicit recovery is required.");
      const next = { ...current, revision: current.revision + 1 };
      update(next, tx.objectStore("blobs"));
      meta(next, this.binding);
      tx.objectStore("meta").put(next, "state");
      return Object.freeze({ instanceId: next.instanceId, revision: next.revision, pendingId: next.pendingId });
    }, signal);
  }
  async commitCheckpoint({ expectedRevision, encryptedCheckpoint, signal }) {
    const bytes = blob(encryptedCheckpoint, "checkpoint"), pin = await digest(bytes);
    return this.change(expectedRevision, (next, blobs) => {
      if (next.pendingId !== null) fail("pending_exists", "Reconcile the original payment before replacing its checkpoint.");
      next.checkpointDigest = pin; blobs.put(bytes, "checkpoint");
    }, signal);
  }
  async reservePending({ expectedRevision, packetId, encryptedPacket, signal }) {
    if (!hex(packetId)) fail("invalid_input", "The original authorized packet digest is required.");
    const bytes = blob(encryptedPacket, "pending"), pin = await digest(bytes);
    return this.change(expectedRevision, (next, blobs) => {
      if (next.pendingId !== null) fail("pending_exists", "The original pending packet must be reconciled before any new send.");
      if (next.checkpointDigest === null) fail("checkpoint_required", "A durable verified checkpoint is required before reserving a payment.");
      if (next.lastPacketId === packetId) fail("already_settled", "This packet already has a final settlement; do not broadcast a replacement.");
      next.pendingId = packetId; next.pendingDigest = pin; blobs.put(bytes, "pending");
    }, signal);
  }
  async settlePending({ expectedRevision, reconciliation, encryptedCheckpoint, encryptedReceipt, signal }) {
    if (!keys(reconciliation, ["source", "networkId", "packetId", "decision"]) ||
        reconciliation.source !== "canonical-finalized-history" || reconciliation.networkId !== this.binding.networkId ||
        !hex(reconciliation.packetId) || !["accepted", "expired-absent"].includes(reconciliation.decision)) {
      fail("unreconciled", "Only an explicit worker-verified canonical final outcome may settle the original packet.");
    }
    const checkpoint = blob(encryptedCheckpoint, "checkpoint"), receipt = blob(encryptedReceipt, "receipt");
    const [checkpointPin, receiptPin] = await Promise.all([digest(checkpoint), digest(receipt)]);
    return this.change(expectedRevision, (next, blobs) => {
      if (next.pendingId === null || next.pendingId !== reconciliation.packetId) fail("pending_mismatch", "Final outcome does not identify the original pending packet.");
      next.checkpointDigest = checkpointPin; next.lastPacketId = next.pendingId;
      next.lastDecision = reconciliation.decision; next.receiptDigest = receiptPin;
      next.pendingId = null; next.pendingDigest = null;
      blobs.put(checkpoint, "checkpoint"); blobs.put(receipt, "receipt"); blobs.delete("pending");
    }, signal);
  }
}

export async function createWalletStore(configuration) {
  const value = { indexedDB: globalThis.indexedDB, ...configuration };
  options(value);
  const encryptedWallet = walletBlob(value.encryptedWallet), walletDigest = await digest(encryptedWallet);
  const instanceId = value.instanceId ?? crypto.randomUUID();
  if (!uuid(instanceId)) fail("invalid_input", "An explicit valid storage instance is required.");
  const db = await openDB(value, true);
  try {
    await transaction(db, "readwrite", (tx, current, blobs) => {
      if (current !== undefined || blobs.size) fail("already_exists", "Existing or partial wallet state cannot be overwritten; open or restore explicitly.");
      tx.objectStore("meta").put({ format: FORMAT, walletId: value.walletId, networkId: value.networkId,
        instanceId, revision: 0, walletDigest, checkpointDigest: null, pendingId: null, pendingDigest: null,
        lastPacketId: null, lastDecision: null, receiptDigest: null }, "state");
      tx.objectStore("blobs").put(encryptedWallet, "wallet");
    }, value.signal);
    return new WalletStore(db, { ...value, expectedInstanceId: instanceId });
  } catch (error) { db.close(); throw error; }
}

export async function openWalletStore(configuration) {
  const value = { indexedDB: globalThis.indexedDB, ...configuration };
  options(value);
  if (!uuid(value.expectedInstanceId)) fail("invalid_input", "Opening an existing wallet requires its expected storage instance.");
  const db = await openDB(value, false), store = new WalletStore(db, value);
  try { await store.read(value.signal); return store; }
  catch (error) { store.close(); throw error; }
}
