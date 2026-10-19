# Standalone tester wallet rehearsal

Everything in this runbook remains local. It neither starts a public network nor publishes a package. Preserve existing fixture ledgers, towers, operator vaults and wallet journals.

Build an archive against an existing network's public identity:

```sh
CARGO_BUILD_JOBS=2 python3 -B tools/package_wallet.py \
  --network .data/u1/network.json --label 'Invited tester rehearsal' \
  --rpc http://127.0.0.1:18899 --transport loopback-http \
  --output .local/tester-package/rehearsal-new.tar.gz
```

The default builder runs the locked offline debug wallet build and gathers third-party notices from installed dependency metadata. Its allowlist exports no fixture roles, validator keys, sponsor configuration, wallet state or passwords. Output files must be new. Identical input bytes/source metadata produce identical archives regardless of filesystem timestamps or input order. This is archive reproducibility, not a cross-host reproducible Rust build. The accompanying SHA-256 and manifest are integrity records, not publisher signatures. For inspected optimized candidates, use the [path-remapped build workflow](path-remapped-wallet-runbook.md) and pass its `--binary` plus `--build-receipt`; this bypasses debug recompilation and preserves the receipt in the signed inventory.

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

The [authenticated release workflow](wallet-release-runbook.md) now prepares a separately trusted offline verifier, independently pinned publisher/profile and signed archive descriptors, with rollback checks and interrupted-update recovery outside wallet state. Its local SIGKILL acceptance passed. This adds publisher authentication when the verifier/pins are obtained independently; the archive's original internal checksum check alone still does not. The path-remapped workflow additionally prepares inspected optimized development builds. Apple signing/notarization, real production key custody and distribution remain unconfigured.

## Gateway recovery update

Build the tester archive from the wallet containing LOCAL-022's authenticated pending-resolution fix. Preserve the exact existing public profile, including the invitation flag, faucet endpoint and public local CA when rehearsing locally. Do not change the profile label/endpoints during an update: the stored canonical profile intentionally pins them along with genesis. For the existing isolated rehearsal, use its desktop-owned public `profile.json` as `--network`, its unchanged label, `--rpc https://127.0.0.1:23898 --transport https --faucet https://127.0.0.1:13780 --invite-only`, and a file containing only its public `local_tls_ca_pem` with `--local-tls-ca`. No private service directory or key belongs in the builder's inputs. Packaging builds only the native-wallet binary offline; set `CARGO_BUILD_JOBS=2` and reduced priority.

Stop the wallet before replacing its extracted package directory. Reuse its existing owner-only data directory outside the package. Keep wallet/recovery files and pending/staging journals intact; replacing an archive never authorizes another send. Check previous payment uses the original signed identity, a canonically pinned authenticated checkpoint and continuous recent RPC history where supported. An offline/lagging RPC leaves the original pending record intact. Recipient-bound withdrawals retain full receipt replay.

`tools/tester_gateway_recovery.py` is the LOCAL-023 two-UID package acceptance. Its desktop role accepts `--ipc`, a new `--evidence` directory outside the checkout, `--archive`, an older local `--baseline` archive and the original LOCAL-021 desktop `--source` evidence. It makes private copies of the already encrypted client state; original funded wallets are never edited. The prior archive's public profile is explicitly rebound as a local update fixture while its old binary/runtime/assets stay unchanged. The test checks modified-content rejection, forbidden operator/RPC options, offline pending preservation, package replacement at the same path and actual launcher restart. Packaged actions run in isolated Python processes importing only the extracted runtime, with passwords on stdin and no checkout fallback.

The test reinstates the exact saved LOCAL-022 pending/staging JSON into the isolated client copy, not a new payment. It then resolves that already-finalized identity after a real supervisor/validator-group SIGKILL and automatic restart. The dedicated `run-package-test` service mode has reduced priority and a ten-minute session deadline retained across restart. Its ordinary authenticated gateway reads remain enabled; a service-private guard records and rejects every attempted transaction broadcast. Passing requires zero attempts, unchanged native effects/keys/claims/budgets and existing admission/grants, matching client wallet/backup bytes and cleared original journals. The old staging account is already closed, so reclamation must not broadcast another close.

The administrator runs only digest-pinned reviewed controller, coordination-helper and installer bytes under isolated system Python. The controller imports only the sealed service runtime plus that explicitly pinned helper, restores the exact normal launchd plist and unloads the test service in cleanup. Preserve started/result records on failure. Do not rerun by clearing markers. This is packaged journal-replay acceptance against an actual validator crash, not a fresh lost-acknowledgement send or a browser-rendering test. LOCAL-022 contains the separate real withheld-acknowledgement evidence. Nothing is hosted or published by this procedure.
