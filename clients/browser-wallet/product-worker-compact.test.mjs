// Actual byte-bridge checks using the same Python/Rust public golden fixture.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";
const source = await loadWorkerSource();
const golden=JSON.parse(await readFile(new URL("../../tools/fixtures/gateway_history_compact_v1.json",import.meta.url),"utf8"));
const context=createWorkerContext({TextEncoder,Uint8Array,BigInt,atob,btoa,WalletStorageError:class extends Error{},self:{postMessage(){}}});
vm.runInContext(source+"\nglobalThis.compact=compactHistory;",context);
const result=context.compact(golden.v3_result);
assert.deepEqual([...result.bytes],[...Buffer.from(golden.v3_result.compact_headers.data_base64,"base64")]);
const metadata=JSON.parse(result.metadata), expected=structuredClone(golden.v3_result);
delete expected.compact_headers.data_base64;
assert.deepEqual(metadata,expected);
for (const change of [p=>p.compact_headers.count=32769,p=>p.compact_headers.count=0,
  p=>p.compact_headers.format="unknown",p=>p.compact_headers.data_base64="AQ",p=>p.compact_headers.data_base64="AB==",
  p=>p.compact_headers.data_base64="!!!!",p=>p.compact_headers.data_base64="A".repeat(2271920)]) {
 const page=structuredClone(golden.v3_result);change(page);assert.throws(()=>context.compact(page),e=>e.code==="history");
}
console.log("PASS: actual compact bridge preserves exact metadata/bytes and rejects unsupported, oversized and noncanonical inputs.");
