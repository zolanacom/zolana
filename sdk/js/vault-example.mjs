// Load the built browser core and create a disposable wallet.
//
//     sh sdk/build-browser-core.sh
//     node sdk/js/vault-example.mjs
//
// Offline: no request is made. The wallet runs this module in a browser worker;
// Node is used here only because it can load the same file without a page.
// @ts-check
import { existsSync, readFileSync } from "node:fs";

const pkg = new URL("../../clients/browser-core/pkg/", import.meta.url);
if (!existsSync(new URL("browser_core_bg.wasm", pkg))) {
  console.error("Build the core first: sh sdk/build-browser-core.sh");
  process.exit(1);
}
/** @type {typeof import("./zolana-browser-core.d.ts")} */
const core = await import(new URL("browser_core.js", pkg).href);
// In a browser: `await core.default()` fetches browser_core_bg.wasm next to the script.
core.initSync({ module: readFileSync(new URL("browser_core_bg.wasm", pkg)) });
console.log("core:", core.version());

// A network is a 32-byte domain and a base58 genesis hash. These are fixture values.
const network = JSON.stringify({ network: Array(32).fill(7), genesis_hash: "1".repeat(32) });
const password = new TextEncoder().encode("disposable example password");

// The seed is created and kept inside Wasm memory. No method returns it.
const vault = core.BrowserVault.create(network, password);
const identity = JSON.parse(vault.identity());
console.log("private address:", identity.private_address);
console.log("fee address:    ", identity.fee_address);

// The recovery file is what the user saves. Restoring it gives the same wallet.
const backup = vault.encrypted_backup();
console.log("recovery file:  ", backup.length, "bytes,", JSON.parse(new TextDecoder().decode(backup)).format);
const restored = core.BrowserVault.restore(network, backup, password);
console.log("restored the same wallet:", restored.identity() === vault.identity());
restored.free();

// A cohort member signs each gateway request with its fee key. This is the
// value of the X-Testnet-Access header (rpc.mjs: the `accessHeader` option).
const now = BigInt(Math.floor(Date.now() / 1000));
const header = vault.rpc_header("https://gateway.example", now);
const proof = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
console.log("access proof:   ", proof.purpose, "for", proof.audience, "valid", proof.expires_at - proof.issued_at, "seconds");

// Failures are strings with a stable code, not Error objects.
vault.lock();
try { vault.identity(); } catch (error) { console.log("after lock():   ", error); }
try { vault.unlock(new TextEncoder().encode("a wrong password")); } catch (error) { console.log("wrong password: ", error); }
vault.free();
