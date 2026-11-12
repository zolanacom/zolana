// Product shell: DOM inputs, public identity and encrypted recovery bytes only.
// No seed, viewing key, balance inference, RPC or payment authorization here.
import { timingLine } from "./timing.js";
const $ = id => document.getElementById(id);
const screens = ["loading", "failure", "welcome", "locked", "account", "activity", "recovery"];
const encoder = new TextEncoder();
let client, wallet, configuration, busy = false, epoch = 0, idleTimer;
let fatal = null, activeView = "wallet", downloaded = false;
let paymentReview;
let automaticReceive, preservingSendReview = false, reviewCancellation = null, automaticNotice = false;
const IDLE_MS = 5 * 60 * 1000;
const WORKER_IDLE_MS = 60 * 1000, WORKER_PROGRESS_LIMIT_MS = 15 * 60 * 1000;
const progressActions = new Set(["sync", "automatic_sync", "recover_pending", "quote_payment", "send"]);
const foregroundProgressActions = new Set(["sync", "recover_pending", "quote_payment", "send"]);
const workerProgressStages = new Set(["reading-finalized-state", "checking-retained-history", "verifying-downloaded-history",
  "loading-private-engine", "preparing-private-wallet", "opening-wallet-checkpoint", "private-wallet-ready",
  "building-private-payment", "saving-original-payment", "sending-original-payment", "confirming-original-payment",
  "recovering-archival-payment", "verifying-history", "recovering-original-payment", "saving-verified-checkpoint", "synced"]);

/* Automatic receive controller: read hints, then reuse verified durable sync.
   No signing, invitation redemption, payment retry or idle-clock reset here. */
function createAutomaticReceive({ state, readAccess, readHint, synchronize, onResult, onError,
  now = () => performance.now(), setTimer = (fn, delay) => setTimeout(fn, delay), clearTimer = id => clearTimeout(id) }) {
  let timer = null, running = false, paused = true, halted = false, generation = 0;
  let dirty = false, failures = 0, lastHint = -Infinity, lastSync = -Infinity;
  const hints = [], syncs = [];
  const eligible = value => value.enabled && !value.blocked && !value.pending;
  function budgetWait(times, maximum, gap, last) {
    const at = now();
    while (times.length && times[0] <= at - 60000) times.shift();
    return Math.max(0, last + gap - at, times.length >= maximum ? times[0] + 60000 - at : 0);
  }
  function schedule(delay = 1000) {
    if (timer !== null || running || paused || halted || !state().enabled) return;
    timer = setTimer(() => { timer = null; void tick(); }, Math.max(0, delay));
  }
  function current(at) { return at === generation && !paused && state().enabled; }
  async function tick() {
    if (running || paused || halted || !state().enabled) return;
    if (!eligible(state())) { schedule(); return; }
    const at = generation;
    let delay = 1000, again = true;
    running = true;
    try {
      if (state().admitted === null) {
        const value = await readAccess();
        if (!current(at) || !eligible(state())) return;
        onResult(value, "access");
      }
      if (state().admitted !== true) { again = false; return; }
      if (!state().verified) dirty = true;
      if (dirty) {
        delay = budgetWait(syncs, 12, 1000, lastSync);
        if (delay > 0) return;
        if (!eligible(state())) return;
        lastSync = now(); syncs.push(lastSync);
        const value = await synchronize();
        if (!current(at)) return;
        onResult(value, "sync"); dirty = false; failures = 0;
      } else {
        delay = budgetWait(hints, 60, 1000, lastHint);
        if (delay > 0) return;
        lastHint = now(); hints.push(lastHint);
        const hint = await readHint();
        if (!current(at) || !eligible(state())) return;
        if (!hint || typeof hint.changed !== "boolean" || typeof hint.baselineKnown !== "boolean") {
          const error = new Error("Automatic payment checks returned an invalid response. Use Sync to verify your wallet.");
          error.code = "hint"; throw error;
        }
        dirty = hint.changed || !hint.baselineKnown;
        onResult(hint, "hint");
        failures = 0; delay = dirty ? 0 : budgetWait(hints, 60, 1000, lastHint);
      }
    } catch (error) {
      if (!current(at)) return;
      if (error?.retryableRead === true) {
        failures++;
        delay = Math.min(30000, 2000 * 2 ** Math.min(failures - 1, 4));
      } else halted = true;
      await onError(error, { retrying: !halted });
    } finally {
      running = false;
      // A manual action can pause and resume while an earlier read is in flight.
      // Its stale result is ignored, but the new session must retain its wakeup.
      if (at !== generation) schedule();
      else if (again) schedule(delay);
    }
  }
  return {
    pause() { paused = true; generation++; if (timer !== null) clearTimer(timer); timer = null; },
    resume({ resetFailure = false, immediate = false } = {}) {
      paused = false;
      if (resetFailure) { halted = false; failures = 0; }
      schedule(immediate ? 0 : 1000);
    },
  };
}
/* End automatic receive controller. */
const diagnostics = new URLSearchParams(location.hash.split("?")[1] || "").get("diagnostics") === "1";
const timingLines = [];
function showTiming(value) {
  if (!diagnostics || document.hidden || wallet?.locked) return;
  const line = timingLine(value); if (line === null) return;
  timingLines.push(line); if (timingLines.length > 128) timingLines.shift();
  $("timing-output").textContent = timingLines.join("\n");
  $("timing-diagnostics").hidden = false;
}

class WalletWorker {
  constructor(onFailure) {
    this.worker = new Worker(new URL("./product-worker.js", import.meta.url), { type: "module" });
    this.jobs = new Map(); this.closed = false;
    this.worker.onmessage = event => {
      if (event.data?.event === "timing") { showTiming(event.data); return; }
      if (event.data?.event === "progress") { this.progress(event.data); showProgress(event.data); return; }
      const job = this.jobs.get(event.data?.id); if (!job) return;
      this.jobs.delete(event.data.id); clearTimeout(job.timer);
      this.startNext();
      if (event.data.ok) job.resolve(event.data.result);
      else { const error = new Error(event.data.error || "Wallet operation failed. Saved data was not reset."); error.code = event.data.code; error.retryableRead = event.data.retryableRead === true; job.reject(error); }
    };
    this.worker.onerror = () => { this.close(); onFailure("The wallet engine stopped. Reload this page to reopen the saved encrypted wallet."); };
    this.worker.onmessageerror = () => { this.close(); onFailure("The wallet engine response could not be read. Reload to inspect saved state."); };
  }
  call(action, parameters = {}) {
    if (this.closed) return Promise.reject(new Error("The wallet engine is closed. Reload this page."));
    if (this.jobs.size >= 4) return Promise.reject(new Error("A wallet operation is already running."));
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      this.jobs.set(id, { action, resolve, reject, timer: undefined, deadline: undefined, stages: new Set(), slot: -1, target: -1 });
      this.startNext();
      try { this.worker.postMessage({ id, action, ...parameters }); }
      catch (error) { const job = this.jobs.get(id); this.jobs.delete(id); clearTimeout(job?.timer); this.startNext(); reject(error); }
    });
  }
  startNext() {
    const job = this.jobs.values().next().value;
    if (!job || job.deadline !== undefined) return;
    job.deadline = performance.now() + (progressActions.has(job.action) ? WORKER_PROGRESS_LIMIT_MS : WORKER_IDLE_MS);
    this.arm(job);
  }
  arm(job) {
    clearTimeout(job.timer);
    job.timer = setTimeout(() => {
      // Timeout preserves IDB and the original pending packet for recovery.
      this.close(new Error("The wallet engine did not finish in time. Reload to inspect the original saved state."));
      fatal = "The wallet engine did not finish in time. Reload to inspect the original saved state."; lockView(); render();
    }, Math.max(0, Math.min(WORKER_IDLE_MS, job.deadline - performance.now())));
  }
  progress(value) {
    const [id, job] = this.jobs.entries().next().value || [];
    if (!job || value.id !== id || !progressActions.has(job.action) || !workerProgressStages.has(value.stage)) return;
    const hasCursor = value.slot !== undefined || value.target !== undefined;
    if (hasCursor && (!Number.isSafeInteger(value.slot) || !Number.isSafeInteger(value.target)
        || value.slot < 0 || value.target < value.slot || value.slot < job.slot || value.target < job.target)) return;
    const advanced = hasCursor ? value.slot > job.slot || value.target > job.target : !job.stages.has(value.stage);
    if (!advanced || performance.now() >= job.deadline) return;
    job.stages.add(value.stage);
    if (hasCursor) { job.slot = value.slot; job.target = value.target; }
    this.arm(job);
    const foregroundWaiting = job.action === "automatic_sync" &&
      [...this.jobs.values()].some(waiting => foregroundProgressActions.has(waiting.action));
    if ((foregroundProgressActions.has(job.action) || foregroundWaiting) && !document.hidden && wallet && !wallet.locked) resetIdle();
  }
  async password(action, parameters, value) {
    try { return await this.call(action, { ...parameters, password: value }); }
    finally { value.fill(0); }
  }
  close(error = new Error("The wallet session closed. Saved encrypted data was preserved.")) {
    if (this.closed) return; this.closed = true; this.worker.terminate();
    for (const job of this.jobs.values()) { clearTimeout(job.timer); job.reject(error); }
    this.jobs.clear();
  }
}

function message(text = "", kind = "info") {
  $("message").textContent = text; $("message").dataset.kind = kind; $("message").hidden = !text;
}
function currentView() {
  const view = location.hash.slice(1).split("?")[0]; return ["wallet", "activity", "recovery"].includes(view) ? view : "wallet";
}
function clearInputs() {
  document.querySelectorAll('input[type="password"]').forEach(input => { input.value = ""; });
}
function lockView() {
  automaticReceive?.pause();
  clearTimeout(idleTimer); clearInputs();
  if (wallet) wallet = { ...wallet, locked: true, identity: undefined };
  if ($("address-dialog").open) $("address-dialog").close();
  if ($("send-dialog").open) $("send-dialog").close(); paymentReview = undefined;
  $("private-address").textContent = "";
  $("invitation-code").value = ""; $("sync-progress").hidden = true;
  timingLines.length = 0; $("timing-output").textContent = ""; $("timing-diagnostics").hidden = true;
}
function formatZol(units) {
  if (typeof units !== "string" || !/^[0-9]{1,20}$/.test(units)) return null;
  const value = BigInt(units); if (value > 18446744073709551615n) return null;
  const whole = value / 1000000000n, fraction = (value % 1000000000n).toString().padStart(9, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}
function showProgress(value) {
  if (!wallet || wallet.locked || document.hidden) return;
  const stages = { "reading-finalized-state": "Checking finalized network state…", "checking-retained-history": "Downloading encrypted history…",
    "verifying-downloaded-history": "Verifying downloaded private history on this device…",
    "loading-private-engine": "Opening the private wallet engine…",
    "preparing-private-wallet": "Preparing private proofs on this device…",
    "opening-wallet-checkpoint": "Opening your saved private wallet state…",
    "private-wallet-ready": "Private wallet ready. Checking saved history…", "building-private-payment": "Creating the private payment proof on this device…",
    "saving-original-payment": "Saving the original payment before sending…", "sending-original-payment": "Submitting the saved original payment…",
    "confirming-original-payment": "Checking the payment in finalized history…",
    "recovering-archival-payment": "Recovering the original payment from canonical archive history…",
    "verifying-history": "Verifying payment history on this device…", "recovering-original-payment": "Checking the original payment before any new send…",
    "saving-verified-checkpoint": "Saving your verified wallet state…", synced: "History verified and saved." };
  if (!Object.hasOwn(stages, value.stage)) return;
  const output = $("send-dialog").open ? $("send-progress") : $("sync-progress");
  output.textContent = stages[value.stage] + (Number.isSafeInteger(value.slot) && Number.isSafeInteger(value.target) ? ` Block ${value.slot.toLocaleString()} of ${value.target.toLocaleString()}.` : "");
  output.hidden = false;
}
function render() {
  activeView = currentView();
  document.querySelectorAll("[data-view]").forEach(link => {
    if (link.dataset.view === activeView) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });
  let screen = !wallet ? "loading" : wallet.locked ? (wallet.saved ? "locked" : "welcome") : "account";
  if (wallet && activeView !== "wallet") screen = activeView;
  if (fatal) screen = "failure";
  screens.forEach(name => { $(`${name}-screen`).hidden = name !== screen; });
  $("lock-button").hidden = !wallet || wallet.locked || !!fatal;
  $("network-label").textContent = wallet ? wallet.label : "Opening local wallet";
  $("footer-network").textContent = wallet ? `${wallet.label} · ${wallet.environment === "testnet" ? "Test coins only" : "Payments unavailable"}` : "Local wallet engine";
  $("unlock-title").textContent = wallet?.phase === "prepared" ? "Finish your setup." : "Welcome back.";
  $("unlock-description").textContent = wallet?.phase === "prepared" ? "Setup was interrupted. Enter the same password to finish saving this exact wallet." : "Your encrypted wallet is saved in this browser.";
  $("unlock-form").querySelector('button[type="submit"]').textContent = busy ? "Opening locally…" : wallet?.phase === "prepared" ? "Finish wallet setup" : "Unlock wallet";
  $("failure-detail").textContent = fatal || "Saved data has not been reset.";
  document.querySelectorAll("form button, form input, .tab-switch button").forEach(control => { control.disabled = busy; });
  $("create-panel").querySelector('button[type="submit"]').textContent = busy ? "Saving encrypted wallet…" : "Create wallet";
  $("restore-panel").querySelector('button[type="submit"]').textContent = busy ? "Opening recovery file…" : "Restore wallet";
  document.querySelectorAll(".backup-button").forEach(button => { button.disabled = busy || !wallet || wallet.locked || !!fatal; });
  document.querySelectorAll(".download-note").forEach(note => { note.hidden = !downloaded; });
  $("address-button").disabled = busy || !wallet?.identity || wallet.locked;
  const balance = wallet?.authoritativeSync && !wallet.locked ? formatZol(wallet.verified?.balance) : null;
  const amount = document.createTextNode(`${balance === null ? "—" : balance} `), unit = document.createElement("span"); unit.textContent = "ZOL";
  $("balance-amount").replaceChildren(amount, unit); $("balance-amount").setAttribute("aria-label", balance === null ? "Balance unavailable" : `${balance} ZOL verified balance`);
  $("balance-caption").textContent = balance === null ? "Not synced. No balance has been verified." : `Test coins only. Verified through block ${wallet.verified.slot.toLocaleString()}.`;
  $("history-detail").textContent = balance === null ? "Not verified yet" : `Verified through block ${wallet.verified.slot.toLocaleString()}`;
  $("sync-title").textContent = balance === null ? "Connect and verify your wallet history." : "History checked and saved on this device.";
  $("sync-detail").textContent = balance === null ? "Sending stays off until history has been verified and saved." : "Finality relies on the invited RPC's consensus view. Private fees come from your shielded balance.";
  const admitted = wallet?.admission?.admitted === true;
  $("invitation-form").hidden = admitted;
  $("access-title").textContent = admitted ? "Connected to the invited testnet." : "Join the test network.";
  $("access-detail").textContent = admitted ? "This wallet has active testnet access. Incoming payments are checked while it stays open and unlocked; only verified history supplies the balance." :
    wallet?.admission?.state === "expired" || wallet?.admission?.state === "revoked" ? "This wallet's testnet access has expired or been revoked. Keep its recovery file and contact the testnet operator." :
    "An invitation connects this wallet to the invited testnet and requests its one-time test-coin grant.";
  $("check-access-button").disabled = busy || !wallet || wallet.locked || !!fatal;
  $("sync-button").disabled = busy || !wallet || wallet.locked || !!fatal;
  $("send-button").disabled = busy || !wallet?.paymentAvailable || wallet.locked || !!fatal;
  $("receive-button").disabled = busy || balance === null || wallet.locked || !!fatal;
  $("recover-pending-button").hidden = !wallet?.pendingPayment || wallet.locked;
  $("recover-pending-button").disabled = busy;
  $("sidebar-state").textContent = wallet?.pendingPayment ? "Original payment needs recovery" : balance === null ? "Verify history to send" : "Verified private balance";
  $("footer-state").textContent = !wallet ? "Loading local wallet engine" : wallet.engineMode === "scalar" ? "Scalar proof engine; sends may be slower" : "Local parallel proof engine";
  $("activity-title").textContent = wallet?.pendingPayment ? "The original payment is saved." : wallet?.lastOutcome?.decision === "accepted" ? "Payment finalized." : wallet?.lastOutcome?.decision === "expired-absent" ? "Payment expired without execution." : "No verified payment receipt in this session.";
  $("activity-detail").textContent = wallet?.pendingPayment ? "Its outcome is not confirmed yet. Check the original payment from your wallet; do not create a replacement send." : wallet?.lastOutcome?.decision === "accepted" ? "The exact original payment was found in finalized canonical history and its recovery journal was settled." : wallet?.lastOutcome?.decision === "expired-absent" ? "Complete canonical history confirmed this payment did not execute before its expiry." : "Sync checks your current balance. A complete transaction list is not available in this preview.";
  $("invitation-form").querySelector('button[type="submit"]').textContent = busy ? "Checking this wallet…" : "Join testnet";
  $("main").setAttribute("aria-busy", String(busy || (!wallet && !fatal)));
}
function resetIdle() {
  clearTimeout(idleTimer);
  if (wallet && !wallet.locked && !fatal) idleTimer = setTimeout(() => { void lockWallet("Wallet locked after five minutes without activity."); }, IDLE_MS);
}
async function lockWallet(note = "Wallet locked.") {
  const at = ++epoch, lockedClient = client; lockView(); render();
  try {
    const result = await lockedClient?.call("lock");
    if (at === epoch && result) { wallet = result; render(); message(note); }
  } catch (error) {
    lockedClient?.close(error);
    if (at === epoch) { fatal = String(error.message || error); render(); }
  }
}
function readPassword(id) {
  const input = $(id), value = encoder.encode(input.value); input.value = "";
  if (value.length < 12 || value.length > 1024) { value.fill(0); throw new Error("Use a password between 12 and 1024 UTF-8 bytes."); }
  return value;
}
async function perform(action, successMessage) {
  if (busy) return;
  automaticReceive?.pause();
  busy = true; const at = epoch; message(); render();
  let successful = false;
  try {
    const result = await action();
    if (at !== epoch || document.hidden) return;
    wallet = result; fatal = null; location.hash = diagnostics ? "wallet?diagnostics=1" : "wallet"; message(typeof successMessage === "function" ? successMessage(result) : successMessage); resetIdle(); successful = true;
  } catch (error) {
    if (at !== epoch) return;
    lockView();
    try { if (!client.closed) wallet = await client.call("status"); } catch { /* Preserve the reported failure and local state. */ }
    if (at !== epoch) return;
    message(String(error.message || "Wallet operation failed. Saved data was not reset."), "error");
  } finally { busy = false; clearInputs(); render(); automaticReceive?.resume({ resetFailure: successful, immediate: successful }); }
}
function showTab(name) {
  for (const tab of ["create", "restore"]) {
    const selected = name === tab; $(`${tab}-tab`).setAttribute("aria-selected", String(selected));
    $(`${tab}-tab`).tabIndex = selected ? 0 : -1; $(`${tab}-panel`).hidden = !selected;
  }
  clearInputs(); message();
}

$("create-panel").addEventListener("submit", event => {
  event.preventDefault(); let value, confirmation;
  if (busy || !client || !wallet || fatal) return;
  try {
    value = readPassword("create-password"); confirmation = readPassword("confirm-password");
    if (value.length !== confirmation.length || !value.every((byte, index) => byte === confirmation[index])) throw new Error("The two passwords do not match. Enter them again.");
    confirmation.fill(0); confirmation = undefined;
    const owned = value; value = undefined;
    void perform(() => client.password("create", {}, owned), "Wallet created locally. Save your encrypted recovery file next.");
  } catch (error) { message(error.message, "error"); }
  finally { value?.fill(0); confirmation?.fill(0); clearInputs(); }
});
$("restore-panel").addEventListener("submit", event => {
  event.preventDefault(); let value;
  if (busy || !client || !wallet || fatal) return;
  try {
    const file = $("recovery-file").files?.[0];
    if (!file || file.size > 4096 || file.size < 48) throw new Error("Choose an encrypted Zolana recovery file smaller than 4 KB.");
    value = readPassword("restore-password"); const owned = value; value = undefined; $("recovery-file").value = "";
    void perform(async () => {
      let encrypted;
      try { encrypted = new Uint8Array(await file.arrayBuffer()); return await client.password("restore", { encrypted }, owned); }
      finally { owned.fill(0); encrypted?.fill(0); }
    }, "Wallet restored locally.");
  } catch (error) { value?.fill(0); message(error.message, "error"); clearInputs(); }
});
$("unlock-form").addEventListener("submit", event => {
  event.preventDefault();
  if (busy || !client || !wallet || fatal) return;
  try { const value = readPassword("unlock-password"); void perform(() => client.password("unlock", {}, value), "Wallet unlocked locally."); }
  catch (error) { message(error.message, "error"); }
});
$("create-tab").addEventListener("click", () => showTab("create"));
$("restore-tab").addEventListener("click", () => showTab("restore"));
document.querySelector(".tab-switch").addEventListener("keydown", event => {
  if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
  event.preventDefault(); const next = $("create-tab").getAttribute("aria-selected") === "true" ? "restore" : "create"; showTab(next); $(`${next}-tab`).focus();
});
$("lock-button").addEventListener("click", () => { void lockWallet(); });
$("reload-button").addEventListener("click", () => location.reload());
window.addEventListener("hashchange", () => { clearInputs(); $("invitation-code").value = ""; message(); render(); });
$("check-access-button").addEventListener("click", () => { void perform(() => client.call("check_access"), "Network access checked for this wallet."); });
$("sync-button").addEventListener("click", () => { void perform(() => client.call("sync"), "Wallet history verified and saved. The displayed balance comes from that checked history."); });
$("recover-pending-button").addEventListener("click", () => { void perform(() => client.call("recover_pending"), result => result.pendingPayment ?
  "The original payment remains unresolved and saved. No replacement was sent." : result.lastOutcome?.decision === "accepted" ?
  "The original payment finalized. Its saved recovery journal is now settled." : result.lastOutcome?.decision === "expired-absent" ?
  "The original payment expired without execution. Its saved recovery journal is settled." :
  "No unresolved payment is saved here. Its earlier outcome is unavailable in this session; this does not confirm expiry."); });
$("invitation-form").addEventListener("submit", event => {
  event.preventDefault(); if (busy || !client || !wallet || wallet.locked || fatal) return;
  const invitation = $("invitation-code").value.trim(); $("invitation-code").value = "";
  if (!/^invite1_[A-Za-z0-9_-]{43}$/.test(invitation)) { message("Enter the complete invitation code supplied for this testnet.", "error"); return; }
  void perform(() => client.call("join", { invitation }), "Invitation accepted. This wallet will check for finalized test funding while it stays open and unlocked.");
});

async function saveRecoveryFile() {
  if (busy || !wallet || wallet.locked) return;
  automaticReceive?.pause();
  const at = epoch; busy = true; message(); render();
  let encrypted, url;
  try {
    encrypted = (await client.call("backup")).encrypted;
    if (at !== epoch || document.hidden) return;
    if (!(encrypted instanceof Uint8Array) || encrypted.length < 48 || encrypted.length > 4096) throw new Error("The wallet engine returned an invalid recovery file.");
    url = URL.createObjectURL(new Blob([encrypted], { type: "application/json" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `Zolana-encrypted-recovery-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(anchor); anchor.click(); anchor.remove();
    downloaded = true; message("Recovery download requested. Confirm the file is saved outside this browser.");
  } catch (error) { if (at === epoch) message(error.message, "error"); }
  finally {
    encrypted?.fill(0); if (url) setTimeout(() => URL.revokeObjectURL(url), 30000);
    busy = false; render(); resetIdle(); automaticReceive?.resume();
  }
}
document.querySelectorAll(".backup-button").forEach(button => button.addEventListener("click", () => { void saveRecoveryFile(); }));
$("address-button").addEventListener("click", () => {
  if (wallet?.locked || typeof wallet?.identity?.private_address !== "string") return;
  const address = wallet.identity.private_address;
  if (!address.startsWith("npriv1") || address.length > 200) { message("The local engine returned an invalid public address.", "error"); return; }
  $("private-address").textContent = address; $("copy-address").textContent = "Copy address"; $("address-dialog").showModal();
});
$("receive-button").addEventListener("click", () => $("address-button").click());
$("close-address").addEventListener("click", () => $("address-dialog").close());
$("address-dialog").addEventListener("close", () => { $("private-address").textContent = ""; });
$("copy-address").addEventListener("click", async () => {
  if (wallet?.locked || !$("address-dialog").open) return;
  try { await navigator.clipboard.writeText($("private-address").textContent); $("copy-address").textContent = "Address copied"; }
  catch { $("copy-address").textContent = "Select the address to copy it"; }
});
function amountUnits(text) {
  if (!/^(?:0|[1-9][0-9]{0,10})(?:\.[0-9]{1,9})?$/.test(text)) throw new Error("Enter a ZOL amount with up to nine decimal places.");
  const [whole, fraction = ""] = text.split("."), value = BigInt(whole) * 1000000000n + BigInt(fraction.padEnd(9, "0"));
  if (value <= 0n || value > 18446744073709551615n) throw new Error("Enter a positive ZOL amount within the native limit.");
  return value.toString();
}
function sendError(text = "") { $("send-error").textContent = text; $("send-error").hidden = !text; }
function cancelEphemeralReview() {
  if (reviewCancellation || !client || client.closed || !wallet || wallet.locked) return;
  automaticReceive?.pause(); const at = epoch;
  reviewCancellation = client.call("cancel_review").catch(error => {
    if (at === epoch && !wallet?.locked && !document.hidden) message("The payment review could not be cleared. Use Sync before reviewing another send.", "error");
  }).finally(() => { reviewCancellation = null; automaticReceive?.resume(); });
}
function editPayment() { cancelEphemeralReview(); $("send-progress").hidden = true; paymentReview = undefined; $("send-form").hidden = false; $("send-review").hidden = true; sendError(); }
$("send-button").addEventListener("click", () => {
  if (!wallet?.paymentAvailable || wallet.locked || busy) return;
  automaticReceive?.pause(); preservingSendReview = false;
  editPayment(); $("send-dialog").showModal();
});
$("close-send").addEventListener("click", () => $("send-dialog").close());
$("send-dialog").addEventListener("close", () => {
  // Closing a submitted review must retain its authorization for the queued
  // explicit send. Ordinary Cancel also clears a quote still being prepared.
  if (!preservingSendReview) cancelEphemeralReview();
  preservingSendReview = false;
  $("send-progress").hidden = true; paymentReview = undefined; $("send-recipient").value = ""; $("send-amount").value = ""; sendError();
  automaticReceive?.resume();
});
$("edit-send").addEventListener("click", editPayment);
$("send-form").addEventListener("submit", async event => {
  event.preventDefault(); if (busy || !wallet?.paymentAvailable || wallet.locked) return;
  const at = epoch; let amount;
  try { amount = amountUnits($("send-amount").value.trim()); } catch (error) { sendError(error.message); return; }
  const recipient = $("send-recipient").value.trim(); busy = true; sendError(); render();
  automaticReceive?.pause();
  try {
    // An earlier dialog's cancellation must complete before creating a new
    // worker review. Otherwise a second Cancel could be coalesced before it.
    if (reviewCancellation) await reviewCancellation;
    if (at !== epoch || document.hidden || !$("send-dialog").open) return;
    const review = await client.call("quote_payment", { recipient, amountUnits: amount });
    if (at !== epoch || document.hidden) return;
    if (!$("send-dialog").open) { cancelEphemeralReview(); return; }
    if (review.amountUnits !== amount || review.recipient !== recipient || !formatZol(review.feeUnits) || typeof review.reviewId !== "string") throw new Error("The reviewed payment differs from your request.");
    $("send-progress").hidden = true; paymentReview = review; $("review-recipient").textContent = review.recipient;
    $("review-amount").textContent = `${formatZol(review.amountUnits)} ZOL`;
    $("review-fee").textContent = `${formatZol(review.maximumFeeUnits)} ZOL`;
    $("review-total").textContent = `${formatZol(review.totalUnits)} ZOL`;
    $("send-form").hidden = true; $("send-review").hidden = false;
  } catch (error) {
    if (at === epoch) {
      $("send-progress").hidden = true;
      sendError(`${error.message} This review did not send a payment or charge a fee.`);
    }
  }
  finally { busy = false; render(); automaticReceive?.resume(); }
});
$("confirm-send").addEventListener("click", () => {
  if (busy || !paymentReview || wallet?.locked) return;
  const reviewId = paymentReview.reviewId; preservingSendReview = true; $("send-dialog").close();
  void perform(() => client.call("send", { reviewId }), result => {
    if (result.paymentOutcome === "accepted") return "Payment finalized on Zolana. The recipient's unlocked wallet can now verify the incoming payment.";
    if (result.paymentOutcome === "expired-absent") return "This payment expired without execution. Your balance was rechecked; review again if you still want to send.";
    if (result.submissionLimit === "member") return "This test wallet has reached its payment limit. Check the saved original payment to finish recovery, then contact the testnet operator.";
    if (result.submissionLimit === "network") return "Testnet payment capacity is full. Check the saved original payment to finish recovery, then contact the testnet operator.";
    return "The original payment is saved, but its outcome is not confirmed. Check the original payment before any new send.";
  });
});
document.addEventListener("visibilitychange", () => {
  // Lock even while setup/unlock is in flight: its late response must never
  // reopen a background page, and the queued lock frees that worker-owned key.
  if (document.hidden) { clearInputs(); if (client && wallet) void lockWallet("Wallet locked while the page was away."); }
});
window.addEventListener("pagehide", () => { epoch++; lockView(); client?.close(); });
window.addEventListener("pageshow", event => { if (event.persisted) location.reload(); });
for (const event of ["pointerdown", "keydown"]) document.addEventListener(event, resetIdle, { passive: true });

automaticReceive = createAutomaticReceive({
  state: () => ({
    enabled: !!client && !client.closed && !!wallet && !wallet.locked && !fatal && !document.hidden,
    blocked: busy || !!reviewCancellation || $("send-dialog").open || !!paymentReview,
    pending: !!wallet?.pendingPayment,
    admitted: wallet?.admission?.admitted ?? null,
    verified: wallet?.authoritativeSync === true,
  }),
  readAccess: () => client.call("check_access"),
  readHint: () => client.call("payment_hint"),
  synchronize: async () => {
    busy = true; render();
    try { return await client.call("automatic_sync"); }
    finally { busy = false; render(); }
  },
  onResult: (result, kind) => {
    if (kind !== "hint") { wallet = result; render(); }
    if (kind === "sync") $("sync-progress").hidden = true;
    if (automaticNotice) { automaticNotice = false; message(); }
  },
  onError: async (error, { retrying }) => {
    const at = epoch;
    // A failed verifier must not leave a stale ready-to-send state in the UI.
    // This is local worker status, never another RPC or automatic payment retry.
    try {
      const result = await client.call("status");
      if (at !== epoch || document.hidden || wallet?.locked || busy || $("send-dialog").open) return;
      wallet = result; render();
    } catch { if (at !== epoch || document.hidden || wallet?.locked) return; }
    if (at !== epoch || document.hidden || wallet?.locked || busy || $("send-dialog").open) return;
    $("sync-progress").hidden = true; automaticNotice = true;
    message(retrying ? "The network connection is interrupted. Automatic payment checks will retry; your saved state is preserved." :
      "Automatic payment checks paused. Use Sync to verify history or check the original pending payment. Your saved state was preserved.", retrying ? "info" : "error");
  },
});

async function start() {
  try {
    if (!isSecureContext || !crypto?.subtle || !window.Worker || !window.indexedDB) throw new Error("Open this wallet over trusted HTTPS or localhost in a browser with storage enabled.");
    const response = await fetch("/wallet-config.json", { cache: "no-store", credentials: "omit", redirect: "error" });
    if (!response.ok) throw new Error("This site has not supplied a Zolana network configuration. No wallet was opened or created.");
    const text = await response.text(); if (text.length > 8192) throw new Error("The wallet network configuration is too large.");
    configuration = JSON.parse(text);
    client = new WalletWorker(detail => { epoch++; lockView(); fatal = detail; render(); });
    wallet = await client.call("initialize", { configuration });
    if (document.hidden) { lockView(); wallet = await client.call("lock"); }
    showTab("create"); render();
  } catch (error) { client?.close(); fatal = String(error.message || "The local wallet engine could not start."); lockView(); render(); }
}
render(); void start();
