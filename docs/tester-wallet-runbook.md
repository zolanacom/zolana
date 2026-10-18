# Standalone tester wallet rehearsal

Everything in this runbook remains local. It neither starts a public network nor publishes a package. Preserve existing fixture ledgers, towers, operator vaults and wallet journals.

Build an archive against an existing network's public identity:

```sh
CARGO_BUILD_JOBS=2 python3 -B tools/package_wallet.py \
  --network .data/u1/network.json --label 'Invited tester rehearsal' \
  --rpc http://127.0.0.1:18899 --transport loopback-http \
  --output .local/tester-package/rehearsal-new.tar.gz
```

The builder runs the locked offline wallet build and gathers third-party notices from installed dependency metadata. Its allowlist exports no fixture roles, validator keys, sponsor configuration, wallet state or passwords. Output files must be new. Identical input bytes/source metadata produce identical archives regardless of filesystem timestamps or input order. This is archive reproducibility, not a cross-host reproducible Rust build. The accompanying SHA-256 and manifest are integrity records, not publisher signatures.

The alternate `--transport https --rpc https://rpc.example.invalid/native` builds a profile with an explicit certificate-validated remote endpoint. It does not contact or deploy that endpoint. Only a real selected testnet RPC with the correct genesis can pass `--check`. Do not use a Solana mainnet/devnet endpoint or publish this preserved development fixture. HTTPS paths are supported; embedded credentials/query tokens and redirects are forbidden. A release must select hosting, access control and identity separately.

Extract the archive into a new directory outside the checkout, then run:

```sh
sh native-wallet/start-wallet.command --verify
sh native-wallet/start-wallet.command --check
sh native-wallet/start-wallet.command --no-browser --data-dir /private/tmp/test-wallet-state --port 8771 --duration 600
```

`--verify` is offline. `--check` needs the configured RPC and no wallet/password. The wallet server binds only `127.0.0.1`; omit `--no-browser` to open the local URL automatically. Python 3.10+ and a browser are required; no Rust/compiler, validator or checkout is needed on the client. The archive is host-specific: the current `darwin-arm64` development build has only system dynamic-library dependencies. It is unsigned/unnotarized and may contain local compiler paths. It is not an externally distributable release.

The default state directory is the current user's application-data directory under `Zolana Test Wallet/<genesis>`. An explicit `--data-dir` must be outside the package and owner-only. Reuse it for updates. The launcher rejects profile changes in that directory and preserves all wallet/recovery/pending/staging files. To use another chain, choose a new directory or explicitly restore a compatible encrypted recovery file. No update resets keys, caps or unknown payments.

Create/save/restore and receiving-address access work with the network offline. A balance failure leaves an unlocked wallet with Receive/Recovery available. Payments need the pinned RPC and continuous history. Standalone mode has no sponsor: private sends and withdrawals use the user's separately funded fee account, with explicit quotes/caps. A profile with an explicitly configured faucet offers Get test coins + gas after recovery-file confirmation; it requests both together and checks the same claim automatically. Profiles without a faucet still require separately provisioned private test notes and public gas. See [private sending](private-send-runbook.md) for the send flow and original-cap crash recovery. See the [test distribution runbook](test-faucet-runbook.md) for finite one-time grants, address binding, restart recovery and invitation admission. Invited profiles point at the separate gateway and set `invite_required: true`; create/back up the wallet, then enter the operator code once. Restore reuses admission. See the [invited access runbook](invited-testnet-runbook.md).

Repeat extracted-package acceptance with a provided isolated browser script and an already installed Playwright runtime:

```sh
python3 -B tools/tester_package_localnet.py \
  --root .data/u1 --archive .local/tester-package/rehearsal-new.tar.gz \
  --browser-script /private/tmp/tester-package-browser.cjs \
  --playwright-module /path/to/installed/playwright
```

The backend runner requires the preserved LOCAL-013 rehearsal, pins that network, restores its encrypted funded user wallet into separate client state and only reads chain state. Its browser script receives passwords/recovery through stdin JSON and must test `offline`, `offline-restore` and `online` phases at `http://127.0.0.1:8771/`. It writes screenshots/results under the runner's new temporary evidence directory. The test never prints passwords or copies operator files into the package. It owns and stops its browser/wallet/probe/validator processes and leaves encrypted client state/evidence in place. Initial acceptance of the runner exposed and fixed an upstream unfollowed-redirect panic before any validator started; the original failure evidence is retained.

Before external invited testing: deploy the invited gateway and bounded faucet with validated TLS and raw-RPC isolation, provide independently hosted validators/RPC, history retention/replication and a release build/distribution review. External network reachability and valid publicly trusted TLS hosting are not established by local rejection probes. No mainnet use or privacy/security audit claim is made.
