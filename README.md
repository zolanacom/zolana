# Zolana (ZOL)

Zolana is an independent Layer 1 blockchain derived from the
[Agave](https://github.com/anza-xyz/agave) validator, with shielded payments
implemented natively in the protocol. ZOL is the name of its native coin.

Zolana's blockchain is currently in devnet. **Devnet test coins are valueless
and distinct from the ZOL token issued on Solana.** The planned bridge will
lock ZOL on Solana and mint an equal amount of native ZOL on Zolana, **1:1**.
The blockchain code has not yet been independently audited. Zolana mainnet and
the bridge are not yet live. Read
[Status and limitations](#status-and-limitations) before relying on anything
here.

## What it is

- **An independent chain.** Zolana has its own genesis, validators and native
  coin; the coin pays fees and is the stake asset. It is not a Solana program,
  token or rollup and does not settle on Solana. No bridge is implemented. See
  [decision 0005](docs/decisions/0005-independent-privacy-l1.md).
- **Shielded payments verified by the validator.** A built-in native program,
  enabled by a feature gate, verifies shielded-payment proofs during transaction
  execution and applies the result atomically: pool backing, note commitments
  and permanent nullifier accounts. Unmodified upstream validators cannot
  validate this network's payments. See decisions
  [0003](docs/decisions/0003-native-validator-integration.md) and
  [0004](docs/decisions/0004-durable-nullifiers.md).
- **Existing shielded cryptography.** Payments use the `orchard` crate
  (version 0.16.0, Orchard v2 bundles with Halo 2 proofs) unchanged. The project
  does not define its own circuit. See
  [decision 0002](docs/decisions/0002-payment-validation-boundary.md).
- **Public and shielded value side by side.** Public accounts and transfers
  still work. A user deposits native coins into the shielded pool, sends
  privately, and can withdraw to a public account
  ([decision 0008](docs/decisions/0008-recipient-bound-withdrawals.md)).
  Privacy is an added native capability, not a property of every transaction.
- **Three ways to pay fees.** A development sponsor, the user's own public fee
  account ([0009](docs/decisions/0009-user-paid-fees.md),
  [0011](docs/decisions/0011-user-paid-private-sends.md)), or a fee taken from
  the shielded notes being spent and reimbursed to a relay
  ([0032](docs/decisions/0032-shielded-fees.md)).
- **Wallets and tools.** A native command-line wallet, a device-local wallet
  UI, a browser wallet that builds proofs and decrypts notes on the device, a
  read-only network portal and explorer, and Python tooling for local test
  networks, gateways, faucets, history retention, monitoring and wallet
  packaging.

## Repository layout

| Path | Contents |
| --- | --- |
| `protocol/payments/` | `native-payments`: payment validation, wire formats, pool state, anchors and envelopes |
| `node/adapter/` | `native-payment-program`: the native program (metered execution, staging, nullifier accounts, coin accounting) |
| `node/agave/` | Upstream Agave v3.0.14 source snapshot with local modifications; Apache-2.0, see [THIRD_PARTY.md](THIRD_PARTY.md) |
| `node/validator-check/` | Integration tests that run signed transactions through the Agave Bank |
| `node/localnet/` | `native-localnet` and `native-validator` binaries for local test networks |
| `node/rpc-access/` | Authenticated private RPC transport used by the validator and operator tools |
| `node/candidate/` | Patch series and reconstruction plan that port the payment code to Agave 4.3.2; not built by the workspace, see [its README](node/candidate/README.md) |
| `clients/cli/` | `payment-lab`: proof fixture and development commands |
| `clients/wallet/` | `native-wallet`, `native-faucet` and `native-shielded` binaries, plus the synthetic `native-fast-cash` fixture |
| `clients/wallet-core/`, `clients/wallet-seed/` | Shared proof construction and history replay; the encrypted seed format |
| `clients/browser-core/` | Rust/Wasm core of the browser wallet |
| `clients/browser-wallet/` | Browser wallet page, workers, storage adapter and Node test suites |
| `clients/browser-lab/` | Loopback page that measures synthetic proofs in a browser ([README](clients/browser-lab/README.md)) |
| `clients/wallet-ui/` | Device-local wallet UI, served by `tools/wallet_ui.py` |
| `clients/network-portal/` | Network portal and read-only explorer, served by `tools/network_portal.py` |
| `sdk/` | Developer SDK 0.1: runnable Rust examples, the browser-core Wasm build script, TypeScript types and a JSON-RPC client ([README](sdk/README.md)) |
| `tools/` | Build wrappers, local-network runners, operator services and their tests |
| `docs/decisions/` | Architecture decisions |
| `docs/` | Runbooks, design notes and the tester quick-start |

## Build and run

Prerequisites:

- Rust 1.92 (pinned in `rust-toolchain.toml`) and a C/C++ toolchain. On macOS
  that is the Xcode command-line tools; for Ubuntu the packages are listed in
  the [Linux pilot runbook](docs/linux-pilot-runbook.md).
- Python 3. The tools use the standard library; a few tests and acceptance
  runners use optional extras (the `cryptography` package, an installed
  Playwright runtime). Individual runbooks say where a newer Python is needed.
- Node.js for the JavaScript test suites, and Git.

Development has been on Apple Silicon macOS, with Linux x86-64 builds described
in the Linux pilot runbook. Other platforms are untested.

`tools/dev.sh` wraps Cargo with a project-local dependency cache (`.tools/cargo`)
and target directory. Fetch dependencies once; everything after that builds
offline against the lockfile.

```sh
sh tools/dev.sh fetch --locked

# Build and verify a real shielded-payment proof fixture. No chain, no funds.
sh tools/dev.sh run --offline --locked -p payment-lab -- proof-smoke

# Execute synthetic native payments in the runtime and through the Agave Bank.
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked -p native-payment-program --test runtime
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked -p native-validator-check --test bank
```

Start a disposable two-validator network on loopback. This builds the validator
from `node/agave`, which takes time and disk space. See the
[local validator runbook](docs/local-validator-runbook.md).

```sh
sh tools/build_localnet.sh
python3 -B tools/localnet.py init --root .data/v2
python3 -B tools/localnet.py start --root .data/v2
python3 -B tools/localnet.py verify --root .data/v2
python3 -B tools/localnet.py stop --root .data/v2
```

Exercise the command-line wallet end to end on a fresh local network (stop any
other local network first; see the [wallet runbook](docs/local-wallet-runbook.md)):

```sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-wallet
python3 -B tools/wallet_localnet.py --root .data/wallet-example
```

Run the portal without a network; it shows a disconnected-history state
([portal runbook](docs/network-portal-runbook.md)):

```sh
python3 -B tools/network_portal.py --port 8780
```

Run the development checks (formatting, Clippy, Rust, Python and Node tests):

```sh
sh tools/check.sh --development-only
```

The local tools bind to loopback and use disposable test keys and test units.
They keep their state in git-ignored directories: `.data/` for networks and
wallets, `.local/` for operator scratch files, `.tools/` and `target/` for
build caches.

## Documentation

The documentation site is at <https://zolana.com/docs>.

Runbooks describe how to run one tool or procedure. Most were written for local
rehearsals on one development machine, so amounts, limits and paths in them are
development values.

- **Local network and wallets:** [validators](docs/local-validator-runbook.md),
  [command-line wallet](docs/local-wallet-runbook.md),
  [wallet UI](docs/local-wallet-ui-runbook.md),
  [network portal](docs/network-portal-runbook.md).
- **Payment paths:** [withdrawals](docs/withdrawal-runbook.md),
  [user-paid fees](docs/user-paid-fees-runbook.md),
  [sponsor-free private sends](docs/private-send-runbook.md),
  [shielded fees](docs/shielded-fees-runbook.md),
  [interrupted uploads](docs/staging-recovery-runbook.md).
- **Restart and recovery:** [coordinated restart](docs/coordinated-restart-runbook.md),
  [crash and fork faults](docs/fault-recovery-runbook.md),
  [offline and damaged snapshots](docs/offline-recovery-runbook.md),
  [retained history](docs/recovery-history-runbook.md),
  [history replica](docs/history-replica-runbook.md),
  [canonical archive](docs/canonical-archive-runbook.md),
  [gateway acknowledgement loss](docs/gateway-pending-recovery-runbook.md).
- **Test network access:** [keys and sponsor](docs/testnet-key-sponsor-runbook.md),
  [test faucet](docs/test-faucet-runbook.md),
  [invitations](docs/invited-testnet-runbook.md),
  [TLS and raw RPC isolation](docs/tls-rpc-isolation-runbook.md),
  [private host RPC transport](docs/host-isolation-runbook.md),
  [direct HTTPS ingress](docs/direct-tls-runbook.md),
  [public TLS certificate](docs/public-tls-certificate-074.md).
- **Operator services:** [service account](docs/service-account-runbook.md),
  [isolated wallet ingress](docs/isolated-wallet-runbook.md),
  [operator health](docs/operator-health-runbook.md),
  [off-host monitor](docs/offhost-monitor-runbook.md),
  [paging](docs/human-paging-runbook.md),
  [watchdog](docs/watchdog-runbook.md),
  [vote-admission budget](docs/vat-budget-runbook.md).
- **Pilot preparation:** [cohort](docs/pilot-cohort-runbook.md),
  [host and funding](docs/pilot-host-funding-runbook.md),
  [installation](docs/pilot-installation-runbook.md),
  [runtime](docs/pilot-runtime-runbook.md),
  [ten-wallet rehearsal](docs/ten-wallet-rehearsal.md),
  [Linux candidate](docs/linux-pilot-runbook.md).
- **Wallet delivery:** [tester wallet](docs/tester-wallet-runbook.md) and its
  [quick-start](docs/tester-wallet-quickstart.txt),
  [authenticated releases](docs/wallet-release-runbook.md),
  [path-remapped builds](docs/path-remapped-wallet-runbook.md),
  [Apple signing preparation](docs/apple-signing-runbook.md).
- **Design notes:** [privacy and delivery review](docs/privacy-boundary-LOCAL-070.md),
  [post-quantum migration plan](docs/post-quantum-roadmap.md),
  [module boundaries](docs/refactoring-plan.md),
  [browser storage adapter](clients/browser-wallet/storage.js),
  [Agave 4.3.2 candidate](node/candidate/README.md).
- **Decisions:** numbered records under [docs/decisions/](docs/decisions/).

Where a document says a test passed, it refers to the project's own runs. The
underlying logs are not part of this repository.

## Status and limitations

**Stage: public devnet.** The project runs one devnet with valueless test
coins for trying the browser wallet. Access is capped by a small, finite
number of test-coin grants and relay jobs. The network has so far run in
bounded windows and shuts itself down when its operational safety checks fail.
Expect it to be offline, reset or withdrawn without notice. No availability is
promised.

**Test coins only.** Devnet test coins have no monetary value and nothing
redeems them. They are distinct from the ZOL token issued on Solana (see
[Token](#token)). Earlier test networks have been replaced by fresh ones, and
balances can be lost when that happens. No production supply, issuance, fee or
rent schedule has been chosen; every amount in this repository is a development
parameter.

**No mainnet yet.** Zolana mainnet and the planned bridge are not yet live, and
there is no production deployment. No bridge to Solana or to any other chain is
implemented, and there is no exchange, swap or trading function.

**Not audited.** No independent security audit or cryptographic review has
been completed for the protocol, the validator modifications, the wallets or
the operator tooling. Using an existing proof system does not make this
integration secure.

**Operated by the project.** Every validator of the devnet is run by
the project, and they are co-located on one host. Independent validators are
not supported yet: there is no procedure for an outside operator to join.
Liveness, and the correctness of what a wallet is shown, depend on the
project's infrastructure.

Known limits:

- **Wallets trust their RPC endpoint.** The wallets verify proofs, signatures
  and history continuity against the validator they are configured with. They
  are not light clients and do not verify consensus independently.
- **The gateway operator can link activity.** Admission ties a wallet's
  membership identity to its receiving address. The gateway sees IP addresses
  and request timing and can link submitted payments to a member. Shielding
  hides amounts and counterparties from the public ledger, not activity from
  the operator. See the
  [privacy and delivery review](docs/privacy-boundary-LOCAL-070.md).
- **Public metadata remains.** Fee payer or relay payee, the exact fee, timing
  and nullifiers are public. Deposits and withdrawals reveal their amounts and
  public accounts. There is no network-layer anonymity.
- **One asset, bounded design.** The shielded pool holds only the native coin.
  Payments have exactly two actions, the anchor history is bounded, and the
  shared pool account serialises payments. No throughput figure is claimed.
- **Not post-quantum secure.** The chain uses Ed25519 and Orchard/Halo 2. The
  [post-quantum migration plan](docs/post-quantum-roadmap.md) is unimplemented
  planning.
- **Two validator code lines.** The workspace builds against the Agave 3.0.14
  snapshot in `node/agave`. Single-transaction ("inline") shielded payments
  need the Agave 4.3.2 candidate in `node/candidate`, which is a patch series
  reconstructed and built separately.
- **Wallet delivery is unfinished.** Standalone wallet packages are development
  builds without Apple Developer ID signing or notarization. The browser wallet
  is a hosted hot wallet: a compromised site could replace wallet code.
  Physical phone and Safari testing has not been done.
- **Recovery is tested for process crashes only.** Restart and recovery
  procedures have been exercised against process kills on test fixtures. Power
  loss, disk loss and host loss are not covered, and history retention has
  finite bounds.
- **The hosted devnet is not reproducible from this repository alone.** The
  deployment, enrollment and backup automation used to host the devnet is not
  included here.
- **Numbers are the project's own.** Timings and test counts quoted in the
  documents were measured by the project on its development machines. They are
  not independent benchmarks.

## Token

ZOL launches first as a token on Solana, to reach users and wallets where they
already are while the Zolana network is in development.

Token address on Solana:

```
UQLWvkwiSsnViuVBy7oArMtzb5RAZyrdJ79amQFrzoL
```

A bridge is planned: holders will lock ZOL on Solana and mint the same amount
on the Zolana network. The bridge is not built yet and has no release date.
Until it exists, the Solana token and the devnet are separate, and devnet coins
remain valueless test coins. Nothing in this repository implements the bridge.

## Licence and third-party code

First-party code is under the MIT licence; see [LICENSE](LICENSE).

`node/agave/` is a source snapshot of upstream
[Agave](https://github.com/anza-xyz/agave) v3.0.14 under the Apache License 2.0
([node/agave/LICENSE](node/agave/LICENSE)), with local modifications. Upstream
licences, copyright notices and attributions inside that tree are retained.
[THIRD_PARTY.md](THIRD_PARTY.md) records the upstream commit, the pristine
tree, the local modifications and the list of changed files.

The patches in `node/candidate/` apply to upstream Agave v4.3.2. They contain
upstream Apache-2.0 code as patch context and a modified vendored copy of the
`agave-transaction-view` crate; see [THIRD_PARTY.md](THIRD_PARTY.md).

Rust dependencies are fetched by Cargo and keep their own licences. Wallet
packages built by `tools/package_wallet.py` bundle the dependency notices.

This project is not affiliated with or endorsed by the maintainers of Agave or
Solana. Their names are used only to describe the origin of the code.
