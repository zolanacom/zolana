# Local wallet preview

This is a wallet for the independent privacy L1, backed by its real local validators. It is not a Solana-mainnet application or a DEX. The UI uses disposable native test units, with fees paid by the fixture sponsor. Private Solana tokens, bridging, mainnet settlement and trading are unavailable.

Build and start against a stopped, initialized NPOOL003 fixture:

```sh
sh tools/build_localnet.sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-wallet
python3 -B tools/wallet_ui.py --root .data/l3 --start-network --duration 1800
```

Open `http://127.0.0.1:8765/`. The server binds only loopback. Startup uses the guarded coordinated restart, never deletes towers or ledgers, and rejects incompatible fixtures. Stop any existing owned session before starting another. A 30-minute timer bounds disk growth; when it ends, the server stops its own validators. Wallets, encrypted recovery files and journals persist. Restart the same command to resume, then reload the page and unlock the existing wallet.

Phone-sized layouts put the wallet controls first, keep touch targets at least 44 pixels, preserve a draft when editing a reviewed payment and return new views to their heading. Address inputs disable autocorrection/capitalization and amounts request a numeric keyboard. Desktop layout is preserved.

For a new wallet, choose a password of at least 12 characters, save the encrypted recovery file separately from the password and confirm. **Save encrypted text instead** provides a copyable recovery envelope when downloads or file pickers are unavailable: save the complete text as a `.json` file. **Restore a wallet** accepts either that file or **Paste recovery text instead**, with the same password and network checks. Neither recovery option displays a plaintext spending seed. Download initiation alone does not prove the file was saved; confirm only after saving your own copy.

Add 100 test units, share a receiving address, or review and send to another private address on this network. Recovery requires both the encrypted file/text and its password; no reset authority exists. A restored seed is retained if later balance verification is unavailable, and the dashboard offers refresh rather than asking for another restore. The receive screen explicitly distinguishes these addresses from Solana addresses. Do not send Solana funds to this preview.

`--profile <lowercase-name>` selects a separate encrypted local wallet without overwriting another profile. The default directory is `.data/l3/wallet-ui`; a named profile uses `.data/l3/wallet-ui-<name>`. Existing wallets are unlocked rather than replaced. To inspect a second profile while validators are running, omit `--start-network` and choose another port:

```sh
python3 -B tools/wallet_ui.py --root .data/l3 --profile second --port 8766 --duration 600
```

An unknown finalization blocks new payments. Use **Check previous payment** before **Recover upload rent**. An accepted payment remains a success if rent cleanup or balance refresh fails. Do not make a fresh payment to resolve an unknown result. The existing CLI `resolve` and `reclaim` commands remain available.

Passwords stay in browser/process memory and the CLI's bounded stdin pipe; there is no password storage in browser localStorage, URLs, arguments or named temporary files. Encrypted wallet files are owner-only. The device-local backend decrypts with the password; it is not suitable for deployment as a hosted multi-user service. Requests require the exact host, same origin and a random session header; no CORS or analytics integration is provided. RPC consensus remains trusted. First sync and seed-only recovery need complete RPC history or separately retained history plus a recent continuous RPC suffix; repeat scans can use an encrypted verified checkpoint. See the [wallet runbook](local-wallet-runbook.md) for cache trust checks and the [recovery-history runbook](recovery-history-runbook.md) for retention.

The backend automatically uses `<root>/recovery-history` when present. `--rpc-index 1` selects the fixture's snapshot-restored peer; API requests cannot redirect the RPC. Unknown-payment resolution still requires canonical full-history RPC/status checks and does not use retained transaction identities.

Repeat real phone-sized download, file restore, review/edit, payment and nullifier acceptance with an already installed Playwright runtime:

```sh
PLAYWRIGHT_MODULE=/path/to/installed/playwright python3 -B tools/mobile_localnet.py --root .data/mobile-new --evidence /private/tmp/mobile-wallet-evidence
```

The runner starts/stops its own loopback validators and isolated HTTP servers/browser. It uses a new ignored fixture and leaves existing wallets unchanged. Chromium touch/viewport and reduced-height keyboard emulation do not constitute physical phone/Safari testing.

Repeat concurrent acceptance on a fresh fixture:

```sh
python3 -B tools/load_localnet.py --root .data/load-new --clients 24
```

The runner owns/stops both validators, performs deposit and nonuniform private-send bursts, checks both validators' balances/nullifiers, rejects live duplicates, restarts and audits. `--baseline` is only for the historical 16-root NPOOL002 build; it is expected to reject eight of 24 payments. Never point a new-format binary at an old ledger.

Invited admission/status transport errors now receive at most four retries with bounded backoff/jitter and the same original wallet/invitation inputs. Payments, authorization failures and quota rejections are not automatically retried. The [ten-wallet rehearsal](ten-wallet-rehearsal.md) covers the four-slot listener burst, completed-claim retry and source-lock recovery. Restart existing local UI servers on their original storage/profile to load a source update; signed standalone releases still require their normal reviewed packaging process.

## Remote native profile

For a remote (Linux-hosted) native NPOOL004 profile, use an explicit reviewed binary and separate disposable test storage, without `--start-network`:

```sh
python3 -B tools/wallet_ui.py \
  --network-profile /absolute/path/reviewed-native-profile.json \
  --data-dir /absolute/path/new-owner-only-test-storage \
  --binary /absolute/path/pinned/native-wallet --duration 600
```

The profile must preserve `private_send_transport: native-inline-v1` and `retained_history_format: compact-v2`, invited HTTPS and its exact pinned identity/trust. Existing storage is bound to its original profile; do not edit that profile or overwrite a wallet to make a new launch work. A configured admission endpoint does not establish live funding. See the [privacy and delivery review](privacy-boundary.md) for limits. The NPOOL003 fixture commands above intentionally start local validators; this remote-profile path does not.
