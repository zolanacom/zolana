// Opt-in, device-local diagnostics. Only fixed phase names and bounded numeric
// durations are accepted; wallet inputs, packet identities and errors are not.
export const TIMING_PHASES = Object.freeze([
  "quote_snapshot", "quote_sync", "quote_fresh_snapshot", "proof_key_prepare",
  "quote_fee", "quote_slot", "quote_checkpoint_digest", "send_snapshot",
  "send_checkpoint_digest", "send_slot", "send_build", "send_reserve",
  "send_packet", "send_submit", "send_recovery", "recovery_sync", "sync_snapshot_fetch", "sync_open", "sync_history_fetch", "sync_history_verify", "sync_finish", "sync_total", "send_total",
]);
const phases = new Set(TIMING_PHASES);
export function timingLine(value) {
  if (!value || Object.keys(value).sort().join("|") !== "elapsedMs|event|phase" ||
      value.event !== "timing" || !phases.has(value.phase) ||
      !Number.isInteger(value.elapsedMs) || value.elapsedMs < 0 || value.elapsedMs > 3600000) return null;
  return `${value.phase}: ${value.elapsedMs} ms`;
}
