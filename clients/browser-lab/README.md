# Synthetic browser feasibility lab

This isolated loopback page exercises the current Orchard 0.16 / Orchard v2 WASM build in a dedicated worker. It does not open the existing wallet, contact a gateway, grant coins, broadcast a transaction or run validators. It accepts no wallet seed, password or viewing key. Disposable fixture keys remain inside WASM worker memory. Only the exact public synthetic packet contract is passed to the configured native reference checker; an explicitly selected checker wrapper may perform that verification on a separate Linux host.

Serve the generated `clients/browser-core/pkg/browser_core.js` and `browser_core_bg.wasm` with:

```sh
python3 -B tools/browser_feasibility.py --port 18994 --native-checker /absolute/path/to/public-fixture-checker
```

Omit `--native-checker` to inspect browser behavior alone. The UI then says native compatibility is unavailable and never reports a full pass. `--wasm-dir` may point at a different explicit generated package directory. There is no fallback to remote proving or to any existing wallet. The server binds only `127.0.0.1`, serves a fixed asset allowlist with no-store/strict CSP, and refuses cross-origin/host requests. No permissive CORS is enabled.

The checker is one explicit executable, invoked without a shell or command arguments. It receives public fixture JSON on stdin and returns `zolana-browser-native-parity-v1` JSON. Its response must confirm the synthetic expected backing/commitment count and checks; generic `ok: true` cannot masquerade as compatibility. Request bodies are bounded to 128 KiB and not logged. Do not configure a wallet or a production RPC client as the checker.

“First” means the first proof attempt in a fresh worker; local browser compilation/download caches may already be warm. “Warm” retains the same worker and prepared prover. The construction measurement includes **two** synthetic proofs (funding and payment) plus local verification; the check list reports each proof separately. This does not measure sending a payment, network finality or recipient onward spending. WASM linear-memory size is not whole-browser resident memory. A 50 ms main-thread heartbeat reports the worst observed scheduling gap, which can also increase when the tab is backgrounded.

Abort/restart terminates the worker and ignores stale replies; a new worker must prepare its prover again. This is a feasibility cancellation test, not durable-wallet recovery. An already started native verification may finish independently after the browser cancels its HTTP request; the server bounds its subprocess time and allows one native check at a time.

## Optional parallel artifact

Keep the scalar package unchanged. Enable a separately built `browser-multicore` package with `--parallel-wasm-dir /absolute/path/to/parallel-pkg --parallel-snippet snippets/wasm-bindgen-rayon-HASH/src/workerHelpers.no-bundler.js`, replacing HASH with the exact generated helper path. Only explicitly supplied helper paths are served; there is no snippets-directory wildcard. The selector offers 4/8 threads only when the package is available and the browser exposes cross-origin isolation, SharedArrayBuffer and enough logical processors. Each count starts a fresh dedicated worker and initializes its Rayon pool before prover preparation; warm attempts reuse that worker/pool.

The pinned wasm-bindgen-rayon1.3 no-bundler helper creates Blob module workers. Configuring the parallel artifact therefore explicitly adds `blob:` to **worker-src only in this synthetic loopback lab**. This is not a selected production wallet content policy. A reviewed same-origin helper could remove that exception later. Parallel abort must be checked in a real browser to establish that nested Rayon workers stop consuming CPU; the scalar cancellation test alone does not establish that. Do not report a thread count as a payment-speed or target guarantee.

Boundary fixtures run with `python3 -B -m unittest browser_feasibility_test` from `tools/`. Real WASM execution, cancellation, first/warm timing and actual native compatibility still require an actual browser with the generated build.
