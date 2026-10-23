import assert from "node:assert/strict";
import { TIMING_PHASES, timingLine } from "./timing.js";
for (const phase of TIMING_PHASES) assert.equal(timingLine({ event: "timing", phase, elapsedMs: 0 }), `${phase}: 0 ms`);
for (const value of [null, {}, { event: "timing", phase: "recipient", elapsedMs: 1 },
  { event: "timing", phase: "send_build", elapsedMs: -1 },
  { event: "timing", phase: "send_build", elapsedMs: Infinity },
  { event: "timing", phase: "send_build", elapsedMs: 0.5 },
  { event: "timing", phase: "send_build", elapsedMs: 3600001 },
  { event: "timing", phase: "send_build", elapsedMs: 5, packet: "not allowed" }]) assert.equal(timingLine(value), null);
console.log("PASS: diagnostics accepts only fixed public phase names and bounded integer durations.");
