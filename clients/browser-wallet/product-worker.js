// Browser hot-wallet controller. Seed material stays inside BrowserVault.
// Only public identity/status and encrypted recovery bytes cross this boundary.
import { createWalletStore, openWalletStore, walletDatabaseName, WalletStorageError } from "./storage.js";

const CATALOG = "zolana-browser-product-v1", CATALOG_STORE = "wallets";
const FORMAT = "zolana-browser-product-record-v1";
let corePromise, configuration, networkJson, networkId, catalog, record, transport;
let engineMode = "scalar", engineThreads = 1, engineRuntime;
const automaticReadActions = new Set(["check_access", "payment_hint", "automatic_sync"]);
const allowed = new Set(["initialize", "create", "restore", "unlock", "lock", "backup", "status", "check_access", "join", "sync", "payment_hint", "automatic_sync", "cancel_review", "quote_payment", "send", "recover_pending"]);
const encoder = new TextEncoder();
const publicFailures = new WeakSet();
const interruptedReadFailures = new WeakSet();
function publicFailure(code, message) {
  const error = new Error(message); error.code = code; publicFailures.add(error); return error;
}
const fail = (code, message) => { throw publicFailure(code, message); };
// The Rust/Wasm boundary exports only versioned codes. Keep the UI copy here.
const coreErrorMessages = new Map([
  ["authentication", ["authentication", "Password could not open this wallet. Check it and try again."]],
  ["password", ["password", "Use a password between 12 and 1024 UTF-8 bytes."]],
  ["backup", ["backup", "This recovery file is invalid or unsupported. Choose your original encrypted Zolana recovery file."]],
  ["network", ["network", "This recovery file's format or network does not match this wallet. Use the original file for the selected Zolana network."]],
  ["configuration", ["configuration", "The wallet's network configuration is invalid. No saved wallet was changed."]],
  ["locked", ["locked", "Your wallet is locked. Unlock it to continue."]],
  ["recovery", ["recovery", "Saved wallet or payment recovery data could not be verified. Keep your recovery file; no state was reset or replacement payment sent."]],
  ["history", ["sync", "Network history could not be fully verified. Your last saved checkpoint and original payments were preserved. Try syncing again."]],
  ["sync_required", ["sync", "Sync and save verified wallet history before reviewing or recovering this payment."]],
  ["review", ["review", "The recipient, fee or expiry does not match the payment's bounds. Sync and review the payment again."]],
]);
const coreErrorPrefix = "zolana-wallet-error-v1:";
function publicError(error) {
  if (typeof error === "string" && error.startsWith(coreErrorPrefix)) {
    const response = coreErrorMessages.get(error.slice(coreErrorPrefix.length));
    if (response) return { code: response[0], error: response[1] };
  }
  if (error && typeof error === "object" && (publicFailures.has(error) || error instanceof WalletStorageError)) {
    return { code: typeof error.code === "string" && /^[a-z_]{1,32}$/.test(error.code) ? error.code : "wallet_error",
      error: error.message.slice(0, 220) };
  }
  return { code: "wallet_error", error: "Wallet operation failed; saved data was not reset." };
}
const hex = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const uuid = value => typeof value === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const equal = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((value, index) => value === b[index]);
// One owner controls every live vault, its store, and cancellation of work
// queued for that session. Durable wallet records remain owned by storage.js.
class WalletSession {
  constructor() {
    this.generation = 0;
    this.vault = undefined;
    this.store = undefined;
    this.admission = undefined;
    this.verifiedStatus = undefined;
    this.verifiedPoolHint = undefined;
    this.savedPending = false;
    this.reviewedQuote = undefined;
    this.lastOutcome = undefined;
    this.requests = new Set();
    this.operations = new Set();
    this.completion = Promise.resolve();
    this.activeRequestId = undefined;
  }

  requireVault() {
    if (!this.vault || !this.store) fail("locked", "Unlock your wallet before connecting to the test network.");
    return this.vault;
  }

  assertCurrent(generation, vault) {
    if (generation !== this.generation || vault !== this.vault || !this.vault) {
      fail("locked", "Wallet locked. Its encrypted data was preserved.");
    }
  }

  adopt(vault, store, generation, pending = false) {
    if (generation !== this.generation) fail("locked", "Wallet session was locked. Unlock again to continue.");
    this.vault = vault;
    this.store = store;
    this.savedPending = pending;
  }

  disposeHandles(vault, store, lockVault = false) {
    const failures = [];
    if (lockVault) {
      try { vault?.lock(); } catch (error) { failures.push(error); }
    }
    try { vault?.free(); } catch (error) { failures.push(error); }
    try { store?.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw failures[0];
  }

  release() {
    const vault = this.vault, store = this.store;
    this.vault = undefined;
    this.store = undefined;
    this.admission = undefined;
    this.verifiedStatus = undefined;
    this.verifiedPoolHint = undefined;
    this.savedPending = false;
    this.reviewedQuote = undefined;
    this.lastOutcome = undefined;
    this.disposeHandles(vault, store, true);
  }

  cancel() {
    this.generation++;
    for (const operation of this.operations) {
      if (!operation.started) this.clearPassword(operation.message);
    }
    const failures = [];
    for (const controller of this.requests) {
      try { controller.abort(); } catch (error) { failures.push(error); }
    }
    try { this.release(); } catch (error) { failures.push(error); }
    if (failures.length) throw failures[0];
  }

  clearPassword(message) {
    if (message?.password instanceof Uint8Array) message.password.fill(0);
  }

  enqueue(message) {
    // Explicit lock takes effect before queue admission, including a full queue.
    // A failed cleanup still locks the session and must receive a normal reply.
    let cancellationFailed = false, cancellationError;
    if (message?.action === "lock") {
      try { this.cancel(); } catch (error) { cancellationFailed = true; cancellationError = error; }
    }
    if (this.operations.size >= 4) {
      this.clearPassword(message);
      self.postMessage(cancellationFailed ? { id: message?.id, ok: false, ...publicError(cancellationError) } :
        { id: message?.id, ok: false, code: "busy", error: "A wallet operation is already running. Wait for it to finish." });
      return this.completion;
    }
    const operation = { message, generation: this.generation, started: false };
    this.operations.add(operation);
    this.completion = this.completion.then(async () => {
      operation.started = true;
      this.activeRequestId = message?.id;
      let response;
      try {
        if (cancellationFailed) throw cancellationError;
        const needsSession = allowed.has(message?.action) && !["initialize", "status", "lock"].includes(message.action);
        if (needsSession && operation.generation !== this.generation) {
          fail("locked", "Wallet locked. Its encrypted data was preserved.");
        }
        response = { id: message?.id, ok: true, result: await dispatch(message) };
      } catch (error) {
        if (["create", "restore", "unlock"].includes(message?.action)) {
          try { this.release(); } catch (cleanupError) { error = cleanupError; }
        }
        response = { id: message?.id, ok: false, ...publicError(error) };
        if (automaticReadActions.has(message?.action)) response.retryableRead = error?.code === "rate_limit" || interruptedReadFailures.has(error);
      } finally {
        this.activeRequestId = undefined;
        this.clearPassword(message);
        this.operations.delete(operation);
      }
      self.postMessage(response);
    });
    return this.completion;
  }
}
const session = new WalletSession();

async function sha(value) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", value))].map(byte => byte.toString(16).padStart(2, "0")).join("");
}
function validateConfiguration(value) {
  if (!value || value.format !== "zolana-browser-wallet-config-v1" || value.coin !== "ZOL" ||
      !["testnet", "mainnet"].includes(value.environment) || typeof value.label !== "string" || value.label.length < 1 || value.label.length > 64 ||
      !value.network || Object.keys(value.network).sort().join("|") !== "genesis_hash|network" ||
      !Array.isArray(value.network.network) || value.network.network.length !== 32 || !value.network.network.some(Boolean) ||
      !value.network.network.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255) ||
      typeof value.network.genesis_hash !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value.network.genesis_hash)) {
    fail("configuration", "This site has no valid Zolana network configuration. Wallet creation is unavailable.");
  }
  return { format: value.format, coin: "ZOL", environment: value.environment,
    label: value.label, network: { network: [...value.network.network], genesis_hash: value.network.genesis_hash } };
}
async function core() {
  if (!corePromise) corePromise = (async () => {
    const crossOriginIsolated = self.crossOriginIsolated === true;
    const parallel = crossOriginIsolated && typeof SharedArrayBuffer === "function";
    const reportedConcurrency = navigator.hardwareConcurrency;
    const hardwareConcurrency = Number.isSafeInteger(reportedConcurrency) && reportedConcurrency >= 1 && reportedConcurrency <= 65535 ? reportedConcurrency : null;
    const module = await import(parallel ? "/wasm-parallel/browser_core.js" : "/wasm/browser_core.js"); await module.default();
    if (parallel) {
      if (typeof module.initThreadPool !== "function") fail("unsupported", "The reviewed parallel wallet engine is missing its thread-pool interface.");
      engineThreads = Math.max(1, Math.min(8, Number.isInteger(reportedConcurrency) ? reportedConcurrency : 1));
      await module.initThreadPool(engineThreads); engineMode = "parallel";
    }
    engineRuntime = { crossOriginIsolated, hardwareConcurrency };
    if (typeof module.BrowserVault?.create !== "function" || typeof module.BrowserVault?.restore !== "function") {
      fail("unsupported", "The local wallet engine is unavailable. No wallet was replaced.");
    }
    return module;
  })();
  return corePromise;
}
function password(value) {
  if (!(value instanceof Uint8Array) || value.length < 12 || value.length > 1024) fail("password", "Use a password between 12 and 1024 UTF-8 bytes.");
  return value;
}
function encrypted(value) {
  if (!(value instanceof Uint8Array) || value.length < 48 || value.length > 4096) fail("backup", "Choose an encrypted Zolana recovery file smaller than 4 KB.");
  return value;
}
const natural = value => Number.isSafeInteger(value) && value >= 0;
function now() { return BigInt(Math.floor(Date.now() / 1000)); }
function audience(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try { const url = new URL(value); return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && ["", "/"].includes(url.pathname); }
  catch { return false; }
}
// Same-origin transport owns request framing and bounded responses. Session
// identity is checked by each authenticated caller around awaited work.
async function responseJSON(path, { raw, access, limit = 4096 } = {}) {
  if (!["/transport.json", "/rpc", "/admission/join", "/admission/status"].includes(path)) fail("transport", "Unknown same-origin wallet route.");
  if (raw !== undefined && (typeof raw !== "string" || encoder.encode(raw).length > (path === "/rpc" ? 32768 : 4096))) fail("request_size", "Wallet request exceeds its byte limit.");
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 25000); session.requests.add(controller);
  try {
    const headers = raw === undefined ? {} : { "Content-Type": "application/json" };
    if (access !== undefined) headers["X-Testnet-Access"] = access;
    const response = await fetch(path, { method: raw === undefined ? "GET" : "POST", headers, body: raw,
      credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal });
    if (!response.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) fail("transport", "The invited gateway returned an unexpected response. Saved wallet data is unchanged.");
    const reader = response.body?.getReader(); if (!reader) fail("transport", "The invited gateway returned no bounded response body.");
    const chunks = []; let size = 0;
    try {
      for (;;) { const next = await reader.read(); if (next.done) break; size += next.value.length;
        if (size > limit) { await reader.cancel(); fail("response_size", "The invited gateway response exceeds the wallet limit."); } chunks.push(next.value); }
    } finally { reader.releaseLock(); }
    const body = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
    let value; try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)); }
    catch { fail("transport", "The invited gateway returned unreadable JSON. No automatic retry was made."); }
    if (!response.ok) {
      const error = publicFailure(response.status === 403 ? "access" : response.status === 429 ? "rate_limit" : "transport", response.status === 403 ? "Invitation or access is invalid, expired, revoked or bound to another wallet." :
        response.status === 429 ? "The testnet request limit was reached. Wait before checking this same wallet again." :
        response.status === 409 ? "This devnet cohort is full. The first cohort is limited to 10 wallets while network capacity is being raised, and every place is taken. Your wallet is saved on this device, but it cannot join, receive or send on this network until the next cohort opens. Nothing is wrong with your wallet." :
        "The gateway response is unavailable. Its outcome may be unknown; check this same wallet before retrying.");
      if (response.status === 502 && value && Object.keys(value).sort().join("|") === "automatic_retry|error|outcome" &&
          value.error === "upstream_unavailable" && value.outcome === "unknown" && value.automatic_retry === false) interruptedReadFailures.add(error);
      throw error;
    }
    return value;
  } catch (error) {
    if (error.name === "AbortError" || error instanceof TypeError) {
      const interrupted = publicFailure("connection", "Connection interrupted. Your saved wallet and original payments were preserved. Check this same wallet again.");
      interruptedReadFailures.add(interrupted); throw interrupted;
    }
    throw error;
  } finally { clearTimeout(timer); session.requests.delete(controller); }
}
async function loadTransport() {
  const value = await responseJSON("/transport.json");
  if (!value || value.format !== "zolana-browser-transport-v1" || value.network?.genesis_hash !== configuration.network.genesis_hash ||
      !Array.isArray(value.network?.network) || value.network.network.length !== 32 || value.network.network.some((byte, index) => byte !== configuration.network.network[index]) ||
      value.rpc_path !== "/rpc" || value.join_path !== "/admission/join" || value.status_path !== "/admission/status" ||
      !audience(value.rpc_audience) || !audience(value.faucet_audience) || value.operator_metadata_visible !== true || value.automatic_retry !== false ||
      typeof value.pool !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value.pool) ||
      typeof value.program !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value.program)) {
    fail("transport", "The browser gateway configuration does not match this wallet network.");
  }
  transport = value; return value;
}
async function rpc(method, params, at, value, unsigned = false, limit = 16 * 1024 * 1024) {
  if (!transport) await loadTransport(); session.assertCurrent(at, value);
  const id = crypto.randomUUID();
  const access = unsigned ? undefined : value.rpc_header(transport.rpc_audience, now());
  const response = await responseJSON("/rpc", { raw: JSON.stringify({ jsonrpc: "2.0", id, method, params }), access, limit });
  session.assertCurrent(at, value);
  if (!response || response.jsonrpc !== "2.0" || response.id !== id ||
      (Object.hasOwn(response, "result") === Object.hasOwn(response, "error"))) fail("rpc", "The invited RPC response identity differs.");
  if (response.error) {
    if (["getShieldedFeeQuote", "submitShieldedPayment"].includes(method) && response.error.code === -32040 &&
        response.error.data && !Array.isArray(response.error.data) &&
        Object.keys(response.error.data).join("|") === "scope") {
      if (response.error.data.scope === "member") fail("member_payment_limit", "This test wallet has reached its payment limit. Contact the testnet operator to continue.");
      if (response.error.data.scope === "network") fail("network_payment_limit", "The devnet has reached its shared limit for private payments in this cohort, so no new payment can be sent right now. Sending reopens when network capacity is raised.");
    }
    if (method === "getWalletSyncSnapshot" && response.error.code === -32601) fail("rpc_method_missing", "This gateway does not support the bounded wallet snapshot method.");
    fail("rpc", "The invited RPC could not supply complete finalized data. Your saved checkpoint was preserved.");
  }
  return response.result;
}
async function retainedHistoryPage(params, at, value) {
  try { return await rpc("getWalletRetainedHistoryV3", params, at, value); }
  catch (error) {
    session.assertCurrent(at, value);
    if (!interruptedReadFailures.has(error) || !["transport", "connection"].includes(error.code)) throw error;
    // This is an immutable history read at the same target/token/cursor. No
    // replay mutation occurs until a complete response passes normal checks.
    // All other RPCs, including payment submission, remain single-attempt.
    return rpc("getWalletRetainedHistoryV3", params, at, value);
  }
}
async function checkAccess() {
  const value = session.requireVault(), at = session.generation;
  if (typeof value.admission_status !== "function") fail("unsupported", "This wallet engine does not yet support invited gateway access.");
  if (!transport) await loadTransport(); session.assertCurrent(at, value);
  const response = await responseJSON("/admission/status", { raw: value.admission_status(transport.faucet_audience, now()) });
  session.assertCurrent(at, value);
  const identity = JSON.parse(value.identity());
  if (!response || typeof response.admitted !== "boolean" || response.fee_address !== identity.fee_address ||
      !["active", "not_invited", "revoked", "expired"].includes(response.state) || response.admitted !== (response.state === "active") ||
      !(response.access_until === null || natural(response.access_until))) fail("admission", "The gateway membership response belongs to another wallet or is incomplete.");
  session.admission = { admitted: response.admitted, state: response.state, accessUntil: response.access_until };
  return currentStatus();
}
async function join(message) {
  const value = session.requireVault(), at = session.generation;
  if (typeof message.invitation !== "string" || !/^invite1_[A-Za-z0-9_-]{43}$/.test(message.invitation)) fail("invitation", "Enter the complete invitation code supplied for this testnet.");
  if (typeof value.admission_request !== "function" || typeof value.admission_claim_id !== "function") fail("unsupported", "This wallet engine does not yet support verified invitation receipts.");
  if (!transport) await loadTransport(); session.assertCurrent(at, value);
  const genesis = await rpc("getGenesisHash", [], at, value, true);
  if (genesis !== configuration.network.genesis_hash) fail("genesis", "The gateway serves a different network. No invitation was redeemed.");
  const response = await responseJSON("/admission/join", { raw: value.admission_request(transport.faucet_audience, message.invitation, now()) });
  session.assertCurrent(at, value);
  if (response?.claim_id !== value.admission_claim_id() || response.admitted !== true ||
      !["queued", "funding", "ready", "needs_attention"].includes(response.state)) fail("admission", "The invitation receipt differs from this wallet. Check access before retrying.");
  const result = await checkAccess();
  return { ...result, fundingState: response.state, fundingIsNotVerifiedBalance: true };
}
function progress(stage, cursor) {
  self.postMessage({ event: "progress", id: session.activeRequestId, stage, ...(cursor ? { slot: cursor.slot, target: cursor.target } : {}) });
}
const timingPhases = new Set(["quote_snapshot", "quote_sync", "quote_fresh_snapshot", "proof_key_prepare", "quote_fee", "quote_slot", "quote_checkpoint_digest",
  "send_snapshot", "send_checkpoint_digest", "send_slot", "send_build", "send_reserve", "send_packet", "send_submit", "send_recovery", "recovery_sync", "sync_open", "sync_snapshot_fetch", "sync_history_fetch", "sync_history_verify", "sync_finish", "sync_total", "send_total"]);
function timingClock() { try { return performance.now(); } catch { return NaN; } }
function timing(phase, began) {
  try {
    const elapsedMs = Math.round(timingClock() - began);
    if (timingPhases.has(phase) && Number.isFinite(elapsedMs) && elapsedMs >= 0 && elapsedMs <= 3600000) {
      self.postMessage({ event: "timing", phase, elapsedMs });
    }
  } catch { /* Diagnostics cannot change a wallet operation's outcome. */ }
}
const buildTimingPhases = ["checkpoint", "wallet_build", "validation", "anchor", "keys", "inputs", "bundle", "authorization", "proof", "signatures", "encoding", "seal"];
function engineDiagnostics(buildTimings) {
  // These are public execution observations only. Invalid/unsupported metrics
  // must never affect an original payment's reservation or outcome.
  const diagnostics = { format: "zolana-browser-engine-diagnostics-v1", engineMode, engineThreads,
    crossOriginIsolated: engineRuntime?.crossOriginIsolated ?? null,
    hardwareConcurrency: engineRuntime?.hardwareConcurrency ?? null };
  try {
    if (buildTimings && typeof buildTimings === "object" && !Array.isArray(buildTimings) &&
        Object.keys(buildTimings).sort().join("|") === [...buildTimingPhases].sort().join("|") &&
        buildTimingPhases.every(phase => Number.isSafeInteger(buildTimings[phase]) && buildTimings[phase] >= 0 && buildTimings[phase] <= 3600000)) {
      diagnostics.buildTimingsMs = Object.fromEntries(buildTimingPhases.map(phase => [phase, buildTimings[phase]]));
    }
  } catch { /* No arbitrary Rust result fields or errors cross this boundary. */ }
  return diagnostics;
}
function measureSync(phase, operation) {
  const began = timingClock();
  try { return operation(); } finally { timing(phase, began); }
}
async function measureAsync(phase, operation) {
  const began = timingClock();
  try { return await operation(); } finally { timing(phase, began); }
}
const headerConfig = { transactionDetails: "none", rewards: false, commitment: "finalized" };
function compactHistory(page) {
  const headers = page?.compact_headers;
  if (!page || !headers || headers.format !== "zolana-retained-headers-v1" ||
      !natural(headers.count) || headers.count > 32768 ||
      typeof headers.data_base64 !== "string" || headers.data_base64.length > 2271916 ||
      headers.data_base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(headers.data_base64)) {
    fail("history", "Compact history encoding is invalid. Your saved checkpoint was preserved.");
  }
  let binary;
  try { binary = atob(headers.data_base64); }
  catch { fail("history", "Compact history encoding is invalid. Your saved checkpoint was preserved."); }
  if (binary.length > headers.count * 52 || btoa(binary) !== headers.data_base64) {
    fail("history", "Compact history encoding exceeds its bounds. Your saved checkpoint was preserved.");
  }
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  const { data_base64: _encodedHeaders, ...metadata } = headers;
  return { metadata: JSON.stringify({ ...page, compact_headers: metadata }), bytes };
}

function normalizeBlocks(items, requested) {
  if (!Array.isArray(items) || items.length !== requested.length || items.length > 256) fail("history", "Finalized history omitted a requested block.");
  return items.map((entry, index) => {
    const block = entry?.block;
    if (entry?.slot !== requested[index] || !block || !natural(block.parentSlot) || !natural(block.blockHeight) ||
        typeof block.blockhash !== "string" || typeof block.previousBlockhash !== "string" || !Array.isArray(block.transactions)) fail("history", "Finalized history reordered or substituted a requested block.");
    return { slot: entry.slot, parent_slot: block.parentSlot, blockhash: block.blockhash,
      previous_blockhash: block.previousBlockhash, block_height: block.blockHeight, transactions: block.transactions };
  });
}
function poolPaymentHint(pool) {
  const account = pool?.value, data = account?.data;
  if (!natural(pool?.context?.slot) || !account || typeof transport?.program !== "string" || account.owner !== transport.program ||
      !Array.isArray(data) || data.length !== 2 || data[1] !== "base64" || typeof data[0] !== "string" ||
      data[0].length !== 34304 || !/^[A-Za-z0-9+/]*={0,2}$/.test(data[0])) {
    fail("hint", "The finalized payment update could not be checked. Your verified wallet state was preserved.");
  }
  let bytes;
  try { bytes = atob(data[0]); } catch { fail("hint", "The finalized payment update encoding is invalid."); }
  if (bytes.length !== 25728 || btoa(bytes) !== data[0] || bytes.slice(0, 8) !== "NPOOL004" ||
      configuration.network.network.some((byte, index) => bytes.charCodeAt(8 + index) !== byte)) {
    fail("hint", "The finalized payment update does not match this network.");
  }
  // Version/network/rent/backing/note count only. Completed slot anchors change
  // every block and are deliberately excluded. These bytes never supply balance.
  return btoa(bytes.slice(0, 64));
}
async function guardAutomatic(at, value) {
  session.assertCurrent(at, value);
  if (session.reviewedQuote) fail("review", "Finish or cancel your current payment review before checking incoming payments.");
  const saved = await session.store.snapshot(); session.assertCurrent(at, value);
  if (session.reviewedQuote) fail("review", "Finish or cancel your current payment review before checking incoming payments.");
  if (saved.pending !== null) session.savedPending = true;
  if (session.savedPending || saved.pending !== null) fail("pending", "Recover the original pending payment before checking incoming payments.");
}
async function paymentHint() {
  const value = session.requireVault(), at = session.generation;
  await guardAutomatic(at, value);
  if (!transport) { await loadTransport(); session.assertCurrent(at, value); }
  const pool = await rpc("getAccountInfo", [transport.pool, { commitment: "finalized", encoding: "base64" }], at, value, false, 64 * 1024);
  await guardAutomatic(at, value);
  if (session.verifiedStatus && pool?.context?.slot < session.verifiedStatus.slot) fail("hint", "The network update is behind your saved verified state.");
  const hint = poolPaymentHint(pool), baselineKnown = typeof session.verifiedPoolHint === "string";
  return { changed: !baselineKnown || hint !== session.verifiedPoolHint, baselineKnown };
}
async function scanCanonicalArchive(value, at, cursor, target, targetHeader) {
  if (typeof value.apply_archival_page !== "function") fail("unsupported", "This wallet engine cannot recover old canonical payment history yet.");
  // begin_sync already pinned this exact finalized header in the core session.
  // A nonzero fallback cursor requires that same anchor on its first RPC too.
  let anchor = { slot: target, blockhash: targetHeader.blockhash, block_height: targetHeader.blockHeight };
  for (let pages = 0; cursor.slot < target && pages < 65536; pages++) {
    const before = cursor.slot; progress("recovering-archival-payment", cursor);
    const page = await rpc("getWalletCanonicalHistory", [before, target, anchor], at, value);
    if (page === null) fail("history", "Complete canonical archive history is unavailable. The original payment and checkpoint remain saved.");
    cursor = JSON.parse(value.apply_archival_page(JSON.stringify(page)));
    if (!natural(cursor.slot) || cursor.slot <= before || cursor.target !== target) fail("history", "The canonical archive did not advance the exact finalized cursor.");
    anchor = page.anchor;
    if (pages === 65535 && cursor.slot < target) fail("history", "Canonical recovery exceeds this bounded run. The original payment remains reserved.");
  }
  return cursor;
}
function syncSnapshot(snapshot, savedSlot) {
  const object = value => value && typeof value === "object" && !Array.isArray(value);
  const invalid = () => fail("sync", "The gateway returned an invalid finalized wallet snapshot. Your original checkpoint was preserved.");
  if (!object(snapshot) || Object.keys(snapshot).sort().join("|") !== "canonical_tail|fallback|format|genesis|network|pool|saved_header|target_header" ||
      snapshot.format !== "zolana-wallet-sync-snapshot-v1" || snapshot.genesis !== configuration.network.genesis_hash ||
      !object(snapshot.network) || Object.keys(snapshot.network).sort().join("|") !== "genesis_hash|network" ||
      snapshot.network.genesis_hash !== configuration.network.genesis_hash || !Array.isArray(snapshot.network.network) || snapshot.network.network.length !== 32 ||
      snapshot.network.network.some((byte, index) => byte !== configuration.network.network[index]) ||
      !object(snapshot.target_header) || !(snapshot.saved_header === null || object(snapshot.saved_header)) ||
      ![null, "tail-too-large", "checkpoint-unavailable", "canonical-incomplete", "response-too-large"].includes(snapshot.fallback)) invalid();
  const target = snapshot.pool?.context?.slot;
  if (!natural(target) || !natural(snapshot.pool?.value?.lamports)) invalid();
  if (target < savedSlot) fail("rollback", "Finalized RPC state is behind your saved wallet. Recovery will not roll it back.");
  if ((savedSlot === 0 && snapshot.saved_header !== null) ||
      (savedSlot > 0 && snapshot.saved_header === null) !== (snapshot.fallback === "checkpoint-unavailable")) invalid();
  if (snapshot.fallback !== null) {
    if (snapshot.canonical_tail !== null) invalid();
    return null;
  }
  const tail = snapshot.canonical_tail;
  if (!object(tail) || Object.keys(tail).sort().join("|") !== "after_slot|blocks|complete|next_slot|target_slot" ||
      tail.after_slot !== savedSlot || tail.target_slot !== target || tail.next_slot !== target || tail.complete !== true ||
      !Array.isArray(tail.blocks) || tail.blocks.length > 256 || (tail.blocks.length === 0) !== (savedSlot === target)) invalid();
  const slots = tail.blocks.map(item => item?.slot);
  if (slots.some((slot, index) => !natural(slot) || slot <= savedSlot || slot > target || (index > 0 && slot <= slots[index - 1])) ||
      (slots.length > 0 && slots.at(-1) !== target)) invalid();
  return normalizeBlocks(tail.blocks, slots);
}
// Synchronization publishes a checkpoint only after canonical verification.
// Its session checks surround every asynchronous persistence boundary.
async function syncWallet({ rejectPending = false } = {}) {
  const value = session.requireVault(), at = session.generation;
  if (!["begin_sync", "checkpoint_info", "apply_compact_history_page", "apply_canonical_blocks", "finish_sync", "payment_status"].every(key => typeof value[key] === "function")) fail("unsupported", "Verified network sync is not available in this wallet engine yet.");
  const saved = await session.store.snapshot(); session.assertCurrent(at, value); session.savedPending = saved.pending !== null;
  if (rejectPending && saved.pending) fail("pending", "Recover the original pending payment before reviewing another send.");
  session.verifiedStatus = undefined; session.reviewedQuote = undefined;
  // Pending recovery preserves the exact original checkpoint. No retained page
  // may stand in for canonical payment inclusion or complete canonical absence.
  const checkpoint = saved.encryptedCheckpoint || new Uint8Array();
  const info = checkpoint.length ? JSON.parse(value.checkpoint_info(checkpoint)) : { slot: 0 };
  if (!natural(info.slot)) fail("checkpoint", "Saved checkpoint slot is invalid.");
  if (saved.pending) {
    if (!checkpoint.length || typeof value.validate_pending_checkpoint !== "function") fail("pending", "The original pending payment needs its exact saved checkpoint. No new send is allowed.");
    value.validate_pending_checkpoint(saved.pending.encryptedPacket, checkpoint);
  }
  progress("reading-finalized-state");
  let snapshot, canonicalTail = null;
  try { snapshot = await measureAsync("sync_snapshot_fetch", () => rpc("getWalletSyncSnapshot", [info.slot], at, value)); canonicalTail = syncSnapshot(snapshot, info.slot); }
  catch (error) { if (error.code !== "rpc_method_missing") throw error; }
  if (canonicalTail === null) {
    await checkAccess(); session.assertCurrent(at, value);
    if (!session.admission.admitted) fail("access", "This wallet has not joined the devnet yet, so it cannot sync. Use Join the test network first. If the cohort is full, joining reopens when the next cohort opens.");
  }
  if (snapshot === undefined) {
    const genesis = await rpc("getGenesisHash", [], at, value, true);
    if (genesis !== configuration.network.genesis_hash) fail("genesis", "The gateway serves a different network. Saved wallet data was preserved.");
  }
  const pool = snapshot === undefined ? await rpc("getAccountInfo", [transport.pool, { commitment: "finalized", encoding: "base64" }], at, value) : snapshot.pool;
  const target = pool?.context?.slot;
  if (!natural(target) || !natural(pool?.value?.lamports)) fail("pool", "The finalized pool response contains invalid integer bounds.");
  if (target < info.slot) fail("rollback", "Finalized RPC state is behind your saved wallet. Recovery will not roll it back.");
  const targetHeader = snapshot === undefined ? await rpc("getBlock", [target, headerConfig], at, value) : snapshot.target_header;
  let cachedHeader = null, replayCheckpoint = checkpoint, archiveRequired = false;
  if (info.slot !== 0) {
    try { cachedHeader = snapshot !== undefined ? snapshot.saved_header : info.slot === target ? targetHeader : await rpc("getBlock", [info.slot, headerConfig], at, value); }
    catch (error) {
      if (error.code !== "rpc") throw error;
      // A pruned cache header is not RPC truth. Rebuild an ephemeral history
      // from genesis; the old durable pending/checkpoint pair stays untouched.
      replayCheckpoint = new Uint8Array(); archiveRequired = !!saved.pending;
    }
    if (cachedHeader === null) { replayCheckpoint = new Uint8Array(); archiveRequired = !!saved.pending; }
  }
  session.assertCurrent(at, value);
  progress("loading-private-engine"); const module = await core(); session.assertCurrent(at, value);
  progress("opening-wallet-checkpoint");
  let cursor = measureSync("sync_open", () => JSON.parse(value.begin_sync(JSON.stringify(pool), JSON.stringify(targetHeader), replayCheckpoint, JSON.stringify(cachedHeader))));
  progress("private-wallet-ready", cursor);
  if (!natural(cursor.slot) || cursor.target !== target) fail("sync", "Wallet engine returned an invalid finalized cursor.");
  if (canonicalTail !== null) {
    if (canonicalTail.length > 0) cursor = JSON.parse(value.apply_canonical_blocks(JSON.stringify(canonicalTail)));
    if (!natural(cursor.slot) || cursor.slot !== target || cursor.target !== target) fail("history", "The snapshot tail did not reach its exact finalized target.");
  }
  if (!saved.pending && cursor.slot < target && (replayCheckpoint.length === 0 || target - cursor.slot >= 512)) {
    for (let pages = 0; cursor.slot < target && pages < 4096; pages++) {
      const before = cursor.slot;
      progress("checking-retained-history", cursor);
      const page = await measureAsync("sync_history_fetch", () => retainedHistoryPage([before, target, cursor.token || null, 32768], at, value));
      if (page === null) { if (cursor.token) fail("history", "Retained history disappeared during this sync."); break; }
      progress("verifying-downloaded-history", cursor);
      cursor = measureSync("sync_history_verify", () => {
        const compact = compactHistory(page);
        return JSON.parse(value.apply_compact_history_page(compact.metadata, compact.bytes));
      });
      // Rust has validated the entire page. A complete empty retained prefix
      // behind our authenticated checkpoint needs the canonical tail below.
      if (cursor.slot === before && cursor.target === target && page.complete === true &&
          natural(page.retained_tip) && page.retained_tip <= before) break;
      if (!natural(cursor.slot) || cursor.slot <= before || cursor.target !== target) fail("history", "Retained history did not advance the exact wallet cursor.");
      if (page.complete) break;
      if (pages === 4095) fail("history", "History exceeds this bounded sync run. Its last saved checkpoint was preserved.");
    }
  }
  // Fetch produced slots in finite windows. Rust checks every parent/hash,
  // authenticated transaction and replay effect against the finalized pool.
  let start = cursor.slot + 1;
  canonical: for (let windows = 0; !archiveRequired && start <= target && windows < 16384; windows++) {
    const end = Math.min(start + 9999, target);
    let slots;
    try { slots = await rpc("getBlocks", [start, end, { commitment: "finalized" }], at, value); }
    catch (error) { if (!saved.pending || error.code !== "rpc") throw error; archiveRequired = true; break; }
    if (!Array.isArray(slots) || slots.length > 10000 || slots.some((slot, index) => !natural(slot) || slot < start || slot > end || (index > 0 && slot <= slots[index - 1]))) fail("history", "The finalized block range is missing, reordered or out of bounds.");
    for (let offset = 0; offset < slots.length; offset += 256) {
      const requested = slots.slice(offset, offset + 256); progress(saved.pending ? "recovering-original-payment" : "verifying-history", cursor);
      let blocks;
      try { blocks = await rpc("getWalletHistoryBlocks", [requested], at, value); }
      catch (error) { if (!saved.pending || error.code !== "rpc") throw error; archiveRequired = true; break canonical; }
      const normalized = normalizeBlocks(blocks, requested);
      // A pruned range may omit old produced slots without an RPC error. Switch
      // to independently verified canonical archival pages before mutating the
      // core session; never substitute retained transaction metadata.
      if (saved.pending && normalized[0].parent_slot !== cursor.slot) { archiveRequired = true; break canonical; }
      cursor = JSON.parse(value.apply_canonical_blocks(JSON.stringify(normalized)));
    }
    start = end + 1;
    if (windows === 16383 && start <= target) fail("history", "History exceeds this bounded sync run. No partial checkpoint was published.");
  }
  if (saved.pending && cursor.slot < target) archiveRequired = true;
  if (archiveRequired) cursor = await scanCanonicalArchive(value, at, cursor, target, targetHeader);
  session.assertCurrent(at, value); progress("saving-verified-checkpoint", cursor);
  const nextCheckpoint = measureSync("sync_finish", () => value.finish_sync());
  if (saved.pending) {
    const outcome = JSON.parse(value.pending_outcome(saved.pending.encryptedPacket));
    if (outcome.packet_id !== saved.pending.packetId || !["accepted", "expired-absent", "unknown"].includes(outcome.decision)) fail("pending", "Recovery returned a different original payment identity.");
    if (outcome.decision === "unknown") {
      // Keep the original checkpoint and immutable pending packet together.
      session.verifiedStatus = undefined; fail("pending_unknown", "The original payment is still unresolved. Its exact packet remains saved; no replacement send is allowed.");
    }
    const receipt = new Uint8Array(outcome.encrypted_receipt);
    await session.store.settlePending({ expectedRevision: saved.revision,
      reconciliation: { source: "canonical-finalized-history", networkId, packetId: saved.pending.packetId, decision: outcome.decision },
      encryptedCheckpoint: nextCheckpoint, encryptedReceipt: receipt });
    session.assertCurrent(at, value); session.savedPending = false;
    session.lastOutcome = { packetId: outcome.packet_id, decision: outcome.decision,
      ...(typeof outcome.signature === "string" ? { signature: outcome.signature } : {}),
      ...(natural(outcome.slot) ? { slot: outcome.slot } : {}) };
  } else {
    await session.store.commitCheckpoint({ expectedRevision: saved.revision, encryptedCheckpoint: nextCheckpoint }); session.assertCurrent(at, value);
  }
  const verified = JSON.parse(value.payment_status());
  if (verified.verified !== true || !/^[0-9]{1,20}$/.test(verified.balance) || !/^[0-9]{1,20}$/.test(verified.max_payment) || !natural(verified.slot) || verified.slot !== target) fail("balance", "The wallet engine did not return a verified bounded balance.");
  const hint = poolPaymentHint(pool);
  session.verifiedStatus = verified;
  session.verifiedPoolHint = hint;
  if (canonicalTail !== null) session.admission = { admitted: true, state: "active", accessUntil: null };
  progress("synced", { slot: verified.slot, target: verified.slot }); return currentStatus();
}
function units(text) {
  if (typeof text !== "string" || !/^[1-9][0-9]{0,19}$/.test(text) || BigInt(text) > 18446744073709551615n) fail("amount", "Enter a positive ZOL amount within the native integer limit.");
  return BigInt(text);
}
// Payment coordination binds review, durable reservation, and recovery to
// one session and the original packet identity.
async function quotePayment(message) {
  const value = session.requireVault(), at = session.generation; session.reviewedQuote = undefined;
  if (typeof message.recipient !== "string" || !/^npriv1[1-9A-HJ-NP-Za-km-z]{58,294}$/.test(message.recipient)) fail("recipient", "Enter the recipient's complete Zolana private address.");
  const amount = units(message.amountUnits); let saved = await measureAsync("quote_snapshot", () => session.store.snapshot()); session.assertCurrent(at, value);
  if (saved.pending || !saved.encryptedCheckpoint) fail("pending", "Recover the original pending payment before reviewing another send.");
  // A review must use a newly verified checkpoint, rather than the last balance
  // displayed before the form sat idle. This path never reconciles a pending send.
  await measureAsync("quote_sync", () => syncWallet({ rejectPending: true })); session.assertCurrent(at, value);
  saved = await measureAsync("quote_fresh_snapshot", () => session.store.snapshot()); session.assertCurrent(at, value);
  if (saved.pending || !saved.encryptedCheckpoint) fail("pending", "Recover the original pending payment before reviewing another send.");
  if (!session.verifiedStatus) fail("sync", "Sync and save verified wallet history before reviewing a payment.");
  const module = await core(); session.assertCurrent(at, value);
  if (typeof module.prepare_wallet_prover !== "function") fail("unsupported", "The wallet engine lacks the reviewed local proving interface.");
  progress("preparing-private-wallet");
  measureSync("proof_key_prepare", () => module.prepare_wallet_prover());
  const quote = await measureAsync("quote_fee", () => rpc("getShieldedFeeQuote", [], at, value));
  if (!quote || quote.format !== "native-shielded-fee-quote-v1" || !natural(quote.fee) || quote.fee <= 0 || quote.fee > 100000000 ||
      quote.network?.genesis_hash !== configuration.network.genesis_hash || !Array.isArray(quote.network?.network) || quote.network.network.length !== 32 ||
      quote.network.network.some((byte, index) => byte !== configuration.network.network[index]) || quote.transport !== "native-inline-v1" || quote.pool_format !== "NPOOL004") fail("fee", "The gateway returned an invalid shielded fee quote.");
  const fee = BigInt(quote.fee);
  if (amount + fee > BigInt(session.verifiedStatus.balance) || amount + fee > BigInt(session.verifiedStatus.max_payment)) fail("balance", "This payment and its private fee exceed the currently spendable amount. Choose a smaller amount.");
  const slot = await measureAsync("quote_slot", () => rpc("getSlot", [{ commitment: "confirmed" }], at, value));
  if (!natural(slot) || slot < session.verifiedStatus.slot || !natural(slot + 512)) fail("expiry", "The current network slot is invalid or behind your saved wallet.");
  const reviewId = crypto.randomUUID();
  session.reviewedQuote = { reviewId, recipient: message.recipient, amountUnits: amount.toString(), maximumFeeUnits: fee.toString(),
    quote, expiry: slot + 512, revision: saved.revision, checkpointDigest: await measureAsync("quote_checkpoint_digest", () => sha(saved.encryptedCheckpoint)) };
  session.assertCurrent(at, value);
  return { reviewId, recipient: message.recipient, amountUnits: amount.toString(), feeUnits: fee.toString(),
    maximumFeeUnits: fee.toString(), totalUnits: (amount + fee).toString(), feeFromPrivateBalance: true, engineMode,
    diagnostics: engineDiagnostics() };
}
async function recoverPending({ attempts = 1, packetId } = {}) {
  const value = session.requireVault(), at = session.generation;
  for (let attempt = 0; attempt < attempts; attempt++) {
    // Only the automatic send path supplies this ID, after its exact packet is
    // durably reserved. Relay status is a readiness hint, never finality.
    if (attempts === 8 && hex(packetId)) {
      let pending = false;
      try {
        const hint = await rpc("getShieldedPaymentStatus", [packetId], at, value);
        pending = hint && typeof hint === "object" && !Array.isArray(hint) &&
          Object.keys(hint).sort().join("|") === "id|state" && hint.id === packetId && hint.state === "pending";
      } catch { session.assertCurrent(at, value); /* Canonical verification remains authoritative. */ }
      if (pending && attempt + 1 < attempts) {
        await new Promise(resolve => setTimeout(resolve, 500)); session.assertCurrent(at, value); continue;
      }
    }
    try { return await measureAsync("recovery_sync", () => syncWallet()); }
    catch (error) {
      if (error.code !== "pending_unknown") throw error;
      if (attempt + 1 === attempts) return { ...currentStatus(), pendingPayment: true, pendingOutcome: "unknown" };
      await new Promise(resolve => setTimeout(resolve, 500)); session.assertCurrent(at, value);
    }
  }
}
async function sendPayment(message) {
  const value = session.requireVault(), at = session.generation, began = performance.now();
  if (!session.verifiedStatus || !session.reviewedQuote || message.reviewId !== session.reviewedQuote.reviewId) fail("review", "Review this payment and its private fee again before sending.");
  const review = session.reviewedQuote; session.reviewedQuote = undefined;
  const saved = await measureAsync("send_snapshot", () => session.store.snapshot()); session.assertCurrent(at, value);
  if (saved.pending || saved.revision !== review.revision || !saved.encryptedCheckpoint || await measureAsync("send_checkpoint_digest", () => sha(saved.encryptedCheckpoint)) !== review.checkpointDigest) fail("conflict", "The wallet changed after this review. Sync and review again; no new payment was broadcast.");
  // Overlap only this read with local proof construction. Handle its rejection
  // immediately even if construction fails; no request is ever replayed.
  const slotRead = measureAsync("send_slot", () => rpc("getSlot", [{ commitment: "confirmed" }], at, value))
    .then(latest => ({ ok: true, latest }), error => ({ ok: false, error }));
  session.assertCurrent(at, value); progress("building-private-payment");
  const built = measureSync("send_build", () => JSON.parse(value.build_payment(review.recipient, BigInt(review.amountUnits), BigInt(review.maximumFeeUnits),
    JSON.stringify(review.quote), BigInt(review.expiry), saved.encryptedCheckpoint)));
  const freshness = await slotRead; session.assertCurrent(at, value);
  if (!freshness.ok) throw freshness.error;
  if (!natural(freshness.latest) || freshness.latest >= review.expiry) fail("review", "This payment review expired. Review a fresh fee quote before sending.");
  session.lastOutcome = undefined;
  if (!hex(built.packet_id) || built.amount !== review.amountUnits || built.fee !== review.maximumFeeUnits || built.expires_at !== review.expiry ||
      !Array.isArray(built.encrypted_pending) || built.encrypted_pending.length < 48 || built.encrypted_pending.length > 32768 ||
      built.encrypted_pending.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) fail("payment", "The wallet engine returned a payment different from your review. Nothing was broadcast.");
  const diagnostics = engineDiagnostics(built.build_timings_ms);
  const encryptedPending = new Uint8Array(built.encrypted_pending);
  progress("saving-original-payment");
  await measureAsync("send_reserve", () => session.store.reservePending({ expectedRevision: saved.revision, packetId: built.packet_id, encryptedPacket: encryptedPending }));
  session.assertCurrent(at, value); session.savedPending = true; session.verifiedStatus = undefined;
  // Only now obtain the original public packet. A crash before or after this
  // line leaves one durable immutable reservation, never a replacement send.
  const packet = measureSync("send_packet", () => JSON.parse(value.pending_packet(encryptedPending)));
  if (packet.id !== built.packet_id) fail("payment", "The saved original payment identity differs. Recovery is required before any further send.");
  progress("sending-original-payment");
  let responseLost = false, submissionLimit = null;
  try { await measureAsync("send_submit", () => rpc("submitShieldedPayment", [packet.packet], at, value)); }
  catch (error) {
    session.assertCurrent(at, value); responseLost = true;
    if (error.code === "member_payment_limit") submissionLimit = "member";
    if (error.code === "network_payment_limit") submissionLimit = "network";
    // A lost/denied reply is never permission to submit again. Canonical reads
    // below inspect this exact original reservation; they do not rebroadcast it.
  }
  progress("confirming-original-payment");
  try {
    const result = await measureAsync("send_recovery", () => recoverPending({ attempts: 8, packetId: packet.id }));
    return { ...result, diagnostics, responseLost, submissionLimit, sendElapsedMs: performance.now() - began,
      paymentOutcome: result.lastOutcome?.packetId === built.packet_id ? result.lastOutcome.decision : "unknown" };
  } catch (error) {
    session.assertCurrent(at, value);
    return { ...currentStatus(), diagnostics, pendingPayment: true, pendingOutcome: "unknown", responseLost, submissionLimit,
      sendElapsedMs: performance.now() - began, recoveryRequired: true };
  }
}
function validateRecord(value) {
  if (value === undefined) return null;
  if (!value || value.format !== FORMAT || value.networkId !== networkId || !hex(value.walletId) || !uuid(value.instanceId) ||
      value.dbName !== walletDatabaseName(value.walletId, networkId) || !["prepared", "ready"].includes(value.phase) ||
      !hex(value.backupDigest) || (value.phase === "prepared" ? !(value.encryptedWallet instanceof Uint8Array) || value.encryptedWallet.length > 4096 : value.encryptedWallet !== null)) {
    fail("catalog_corrupt", "Saved wallet information is incomplete. Keep your recovery file; no reset was performed.");
  }
  return value;
}
function openCatalog() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(CATALOG, 1); let blocked = false;
    request.onupgradeneeded = event => {
      if (event.oldVersion !== 0) { request.transaction.abort(); return; }
      request.result.createObjectStore(CATALOG_STORE);
    };
    request.onerror = () => reject(new Error("Browser storage is unavailable. No wallet was replaced."));
    request.onblocked = () => { blocked = true; reject(new Error("Close other Zolana tabs before opening wallet storage.")); };
    request.onsuccess = () => {
      const db = request.result;
      if (blocked) { db.close(); return; }
      if ([...db.objectStoreNames].join("|") !== CATALOG_STORE) { db.close(); reject(new Error("Wallet catalog schema differs; no reset was performed.")); return; }
      db.onversionchange = () => {
        // Invalidate both the catalog and session generation before cleanup:
        // pending work must never adopt a vault after a version change.
        catalog = undefined;
        const failures = [];
        try { session.cancel(); } catch (error) { failures.push(error); }
        try { db.close(); } catch (error) { failures.push(error); }
        if (failures.length) {
          const failure = publicError(failures[0]);
          throw publicFailure(failure.code, failure.error);
        }
      };
      resolve(db);
    };
  });
}
function catalogTransaction(write, action) {
  if (!catalog) fail("closed", "Wallet storage closed. Reload this page to inspect the saved wallet.");
  return new Promise((resolve, reject) => {
    let tx, result, failure;
    try {
      tx = write ? catalog.transaction(CATALOG_STORE, "readwrite", { durability: "strict" }) : catalog.transaction(CATALOG_STORE, "readonly");
      if (write && tx.durability !== "strict") { tx.abort(); fail("unsupported", "This browser cannot provide the required wallet storage durability."); }
    } catch (error) { reject(error); return; }
    tx.oncomplete = () => resolve(result);
    tx.onabort = () => reject(failure || new Error("Wallet storage did not commit. Reload to inspect the original state."));
    tx.onerror = () => { /* IndexedDB performs an atomic abort. */ };
    const store = tx.objectStore(CATALOG_STORE), request = store.get(networkId);
    request.onsuccess = () => {
      try { result = action(store, validateRecord(request.result)); }
      catch (error) { failure = error; try { tx.abort(); } catch { /* Already closed. */ } }
    };
  });
}
async function readRecord() { return catalogTransaction(false, (_store, current) => current); }
function sameRecord(a, b) {
  if (a === null || b === null) return a === b;
  return ["format", "networkId", "walletId", "instanceId", "dbName", "phase", "backupDigest"].every(key => a[key] === b[key]) &&
    (a.encryptedWallet === null ? b.encryptedWallet === null : equal(a.encryptedWallet, b.encryptedWallet));
}
async function changeRecord(expected, next) {
  validateRecord(next);
  await catalogTransaction(true, (store, current) => {
    if (!sameRecord(current, expected)) fail("conflict", "Another tab changed this wallet. Reload before continuing.");
    if (expected === null) store.add(next, networkId); else store.put(next, networkId);
  });
  record = next;
}
function currentStatus() {
  return { saved: !!record, phase: record?.phase || "new", locked: !session.vault,
    label: configuration.label, environment: configuration.environment, coin: "ZOL",
    authoritativeSync: !!session.verifiedStatus, paymentAvailable: !!session.verifiedStatus && !session.savedPending, browserHotWallet: true,
    transportAvailable: !!transport, admission: session.admission || null, verified: session.verifiedStatus || null,
    pendingPayment: session.savedPending, lastOutcome: session.lastOutcome || null, engineMode, engineThreads, diagnostics: engineDiagnostics(),
    ...(session.vault ? { identity: JSON.parse(session.vault.identity()) } : {}) };
}
async function status() {
  const current = await readRecord();
  if (!sameRecord(current, record ?? null)) { session.release(); record = current; }
  return currentStatus();
}
async function binding(identity, encryptedWallet) {
  const walletId = await sha(encoder.encode(JSON.stringify(["zolana-browser-product-wallet-v1", identity.network, identity.private_address])));
  return { format: FORMAT, networkId, walletId, dbName: walletDatabaseName(walletId, networkId),
    instanceId: crypto.randomUUID(), phase: "prepared", backupDigest: await sha(encryptedWallet), encryptedWallet: encryptedWallet.slice() };
}
async function finishPrepared(prepared, value, at) {
  let store;
  try {
    try { store = await openWalletStore({ ...prepared, expectedInstanceId: prepared.instanceId }); }
    catch (error) {
      if (error.code !== "missing") throw error;
      // Only a prepared, never-usable setup intent may create its exact initial
      // instance. A ready wallet with missing storage is never recreated here.
      store = await createWalletStore({ ...prepared, encryptedWallet: prepared.encryptedWallet });
    }
    const saved = await store.snapshot();
    if (saved.revision !== 0 || saved.encryptedCheckpoint !== null || saved.pending !== null ||
        !equal(saved.encryptedWallet, prepared.encryptedWallet) || await sha(saved.encryptedWallet) !== prepared.backupDigest) {
      fail("setup_changed", "Interrupted setup differs from its original encrypted record. No state was overwritten.");
    }
    const ready = { ...prepared, phase: "ready", encryptedWallet: null };
    await changeRecord(prepared, ready);
    if (at !== session.generation) fail("locked", "Wallet setup was saved, and its session was locked. Unlock to continue.");
    session.adopt(value, store, at); store = undefined;
    return currentStatus();
  } finally { store?.close(); }
}
async function createOrRestore(message, restoring) {
  session.release(); const at = session.generation;
  record = await readRecord();
  if (record) fail("exists", "A wallet is already saved for this network. Unlock it; this page will not overwrite it.");
  const module = await core(), pass = password(message.password);
  let value = restoring ? module.BrowserVault.restore(networkJson, encrypted(message.encrypted), pass) : module.BrowserVault.create(networkJson, pass);
  try {
    const identity = JSON.parse(value.identity()), backup = value.encrypted_backup();
    const prepared = await binding(identity, backup);
    // Persist the original authenticated encrypted setup before creating its
    // wallet database. A crash requires the same password to finish this intent.
    await changeRecord(null, prepared);
    const result = await finishPrepared(prepared, value, at); value = undefined;
    return result;
  } finally { value?.free(); }
}
async function unlock(message) {
  session.release(); const at = session.generation; record = await readRecord();
  if (!record) fail("missing", "No wallet is saved here. Restore your encrypted recovery file explicitly.");
  const module = await core(), pass = password(message.password);
  let value, store;
  try {
    if (record.phase === "prepared") {
      value = module.BrowserVault.restore(networkJson, encrypted(record.encryptedWallet), pass);
      const identity = JSON.parse(value.identity());
      const expected = await binding(identity, record.encryptedWallet);
      if (expected.walletId !== record.walletId) fail("binding", "Encrypted setup belongs to a different wallet.");
      const result = await finishPrepared(record, value, at); value = undefined; return result;
    }
    store = await openWalletStore({ ...record, expectedInstanceId: record.instanceId });
    const saved = await store.snapshot();
    if (await sha(saved.encryptedWallet) !== record.backupDigest) fail("binding", "Saved recovery bytes changed. No wallet was replaced.");
    value = module.BrowserVault.restore(networkJson, saved.encryptedWallet, pass);
    const identity = JSON.parse(value.identity()), expected = await binding(identity, saved.encryptedWallet);
    if (expected.walletId !== record.walletId) fail("binding", "Saved encrypted wallet identity differs.");
    if (at !== session.generation) fail("locked", "Wallet session was locked. Unlock again to continue.");
    session.adopt(value, store, at, saved.pending !== null); value = undefined; store = undefined;
    return currentStatus();
  } finally { session.disposeHandles(value, store); }
}
async function dispatch(message) {
  if (!message || typeof message.id !== "string" || message.id.length > 64 || !allowed.has(message.action)) fail("request", "Unknown wallet operation.");
  if (message.action === "initialize") {
    if (configuration) fail("initialized", "Wallet worker is already initialized.");
    if (!self.isSecureContext || !crypto?.subtle || !indexedDB) fail("unsupported", "Use a secure HTTPS or localhost origin with browser storage enabled.");
    configuration = validateConfiguration(message.configuration); networkJson = JSON.stringify(configuration.network);
    networkId = await sha(encoder.encode(JSON.stringify(["zolana-browser-product-network-v1", configuration.network])));
    catalog = await openCatalog(); record = await readRecord(); await core(); return status();
  }
  if (!configuration || !catalog) fail("uninitialized", "Reload the wallet to initialize its local engine.");
  if (message.action === "create") return createOrRestore(message, false);
  if (message.action === "restore") return createOrRestore(message, true);
  if (message.action === "unlock") return unlock(message);
  if (message.action === "lock") { session.release(); return status(); }
  if (message.action === "status") return status();
  if (message.action === "check_access") return checkAccess();
  if (message.action === "join") return join(message);
  if (message.action === "sync") return measureAsync("sync_total", () => syncWallet());
  if (message.action === "payment_hint") return paymentHint();
  if (message.action === "automatic_sync") {
    const value = session.requireVault(), at = session.generation;
    await guardAutomatic(at, value);
    return measureAsync("sync_total", () => syncWallet({ rejectPending: true }));
  }
  if (message.action === "cancel_review") { session.reviewedQuote = undefined; return currentStatus(); }
  if (message.action === "quote_payment") return quotePayment(message);
  if (message.action === "send") return measureAsync("send_total", () => sendPayment(message));
  if (message.action === "recover_pending") return recoverPending();
  if (message.action === "backup") {
    if (!session.vault) fail("locked", "Unlock your wallet before saving its encrypted recovery file.");
    return { encrypted: session.vault.encrypted_backup() };
  }
}
self.onmessage = event => session.enqueue(event.data);
