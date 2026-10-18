# Local testnet key and sponsor rehearsal

This setup is a separate, loopback-only rehearsal for an independent privacy L1. It does not publish a testnet, select production economics, create a bridge or reuse existing disposable keys. `init` still creates an explicitly public fixture. `init-private` creates fresh operator material and marks the network `local-testnet-rehearsal-v1`; that label is not a security audit or deployment approval.

## Roles and files

Fourteen independently random Ed25519 keys are bound to the new genesis. Each of two validators has an identity, authorized voter, vote account address, vote withdrawal authority, stake account address and stake control authority. Stake control currently uses one offline key for both stake authorization roles. Treasury and payment sponsor are separate keys. The vote account key is not the runtime voter or withdrawal authority.

Only `identity-{0,1}.keypair.json` and `voter-{0,1}.keypair.json` are written as plaintext hot files, with mode 0600 inside a 0700 root. `operator-recovery.enc.json` backs up all fourteen roles. `sponsor.enc.json` contains only the sponsor and requires a different password. Both envelopes use XChaCha20-Poly1305, fresh 16-byte salt/24-byte nonce and PBKDF2-HMAC-SHA256 at 600,000 iterations. Genesis, network, public roles, format and KDF parameters are authenticated. Passwords are bounded private file inputs; one ceremony password may instead use stdin. No secret is printed or passed as a command argument/environment value. Read-back authentication precedes usable network configuration publication.

`network.json` publishes public roles, identities and vote addresses. The validator runner pins genesis and loopback endpoints, selects the distinct voter file, checks hot file permissions and retains the existing signed-tower restart rules. Rehearsal roots must be owner-only directories under `.data`. Disposable fault-injection helpers remain disabled for private rehearsal roots.

## Initialize and recover

Build with `sh tools/dev.sh build --offline --locked -p native-wallet -p native-localnet`. Prepare separate owner-only password files outside the rehearsal root using operator-controlled secret storage. Do not put a real cold password on a validator host. The automated acceptance uses random, ignored test passwords on the same development machine; that is a custody rehearsal, not actual offline custody.

```sh
target/debug/native-localnet init-private .data/rehearsal \
  --cold-password-file <private-cold-password-file> \
  --sponsor-password-file <different-private-sponsor-password-file>
```

The root must be new. Partial initialization is unusable and cannot be silently replaced. Preserve it and investigate an error. Back up the encrypted recovery bundle separately and record the public genesis/role fingerprints. Launch only through the existing loopback runner, using the same root and its retained towers. Do not run a recovered identity alongside another instance of that identity.

```sh
target/debug/native-localnet restore-hot .data/rehearsal \
  --cold-password-file <private-cold-password-file>
```

Recovery verifies the authenticated public role map and genesis, reconstructs the genesis vote/stake authorities and validates all existing targets before restoring missing identity/voter files. Existing files must match and are never overwritten. No treasury, stake-control or vote-withdrawal key is exported. This restores keys, not a missing tower or lost ledger. Keep the signed tower and ledger/snapshot recovery procedures.

If the encrypted sponsor file is lost, restore to a missing sponsor path:

```sh
target/debug/native-localnet restore-sponsor .data/rehearsal \
  --cold-password-file <private-cold-password-file> \
  --sponsor-password-file <new-private-sponsor-password-file>
```

This re-encrypts the same signing key under a new password; it is not signing-key rotation. The original sponsor policy and reservation journal must remain present and are never reset. Preserve an existing encrypted file instead of overwriting it. Actual compromised-key rotation, authority changes and hardware-backed custody remain separate work.

## Complete but unfrozen shutdown tail

The coordinated restart helper refuses to select an older checkpoint when a fully received child has not been executed. That refusal protects Agave's bank-hash/stake gate: initial replay must not silently advance past the selected wait slot. With both validators stopped, `python3 -B tools/replay_localnet.py --root .data/rehearsal` can handle exactly one adjacent complete child whose bank hash is already frozen on the stopped peer.

It runs a no-voting validator to an upstream development inspection halt, executes/validates retained blocks, compares the newly frozen child with the peer and checks that every original shred, frozen hash and signed tower survives unchanged. Its temporary inspection RPC ports are separate; never use them for wallet state, inclusion checks or payments. The helper then stops only its owned parked child. Normal restart still requires the original signed tower, snapshot/root safety, exact checkpoint hash and stake gate. Multiple/complex/uncorroborated/dead/duplicate tails fail closed and require explicit repair. Nothing is deleted or rewound. Retained before/after/log evidence lives under a new `tail-replay-*` directory. The wallet UI performs this preflight before starting an existing two-tower network; a genuinely new genesis bootstraps normally.

## Sponsor controls

The managed sponsor funds development deposits and native private-send/withdrawal fees/rent. It has no treasury authority, accepts no arbitrary transaction-signing request, and uses the wallet's fixed instruction construction and native authorization. Recipient-bound withdrawals pay the user's chosen public account, independently of the sponsor. The local UI selects the operator password file at startup; browser requests cannot replace it, the RPC, signer or policy.

The rehearsal defaults are deliberately finite development amounts:

| Setting | Default |
| --- | --- |
| Sponsor genesis balance | 1,000,000,000 smallest native units |
| Treasury genesis balance | 10,000,000,000 units, separate offline authority |
| Gross allowance per payment attempt | 150,000,000 units |
| Lifetime reserved allowance | 900,000,000 units, six attempts total |
| Maximum sponsored deposit / local faucet amount | 5,000,000 units in new private rehearsals |
| Maximum private send value | 1,000,000,000 units of the user's shielded balance |
| Maximum recipient-bound withdrawal | 10,000,000 units of the user's shielded balance |
| Attempts per receiving identity | Three, including failed/interrupted reservations |

These are valueless rehearsal units, not selected issuance, denomination, market value or launch parameters. The 80/20 stake arrangement, overfunded development vote accounts, short epochs and validator balances are development settings, not an external validator distribution plan.

The fixed `sponsor-policy.json` and its 0600 `.reservations.json` journal are network/signer bound. A separate OS lock spans reservation, proof preparation, uploads, finalization and cleanup across every wallet sharing this sponsor. The CLI reserves a full attempt allowance with fsync and atomic replacement before preparing the payment. Every broadcast first persists its potential gross debit: actual RPC fee for that message/blockhash, staging account rent, both permanent nullifier rents and any public deposit value. Failed broadcasts and uncertain execution do not refund charges. Staging rent refunds do not replenish a reservation. Full attempt reservations never automatically return to the lifetime budget.

A request ID is mandatory for a new payment. Reusing one is rejected even from another wallet file or after a crash/restart. Per-wallet limits use the seed-derived receiving identity, not a file path. IDs/identities are hashed in the local journal; this is accounting metadata, not network anonymity or protection against address guessing. New receiving identities can bypass the per-wallet count; the global finite budget remains the abuse ceiling. This is not a Sybil-resistant public faucet.

```sh
target/debug/native-wallet deposit --network .data/rehearsal/network.json \
  --wallet <encrypted-wallet-file> --password-file <private-wallet-password-file> \
  --rpc http://127.0.0.1:18899 --amount 100 \
  --sponsor-password-file <private-sponsor-password-file> \
  --sponsor-request-id <unique-16-to-128-character-request-id>
```

`send` also requires `--to` and uses the same sponsor arguments. Plaintext sponsor overrides are rejected for this mode. New private genesis and policies enable recipient-bound `withdraw`, defaulting to a public authority recoverable from the user's encrypted seed. See the [withdrawal runbook](withdrawal-runbook.md). Preserved old policies without `max_withdraw` continue to deny it; old genesis does not activate the new feature. Explicit `withdraw-legacy` remains restricted to disposable fixtures and is always denied by managed sponsorship. The earlier LOCAL-011 acceptance deliberately retains its original 100-unit test amounts.

An interrupted upload records its original request ID in the existing staging journal. `resolve` still requires canonical history and never uses retained-history inclusion claims. Once any pending payment is resolved, `reclaim` uses only the original wallet reservation's durably remaining allowance; it cannot authorize a new payment or increase lifetime reservations. Cleanup therefore remains available after the per-wallet/global new-payment cap is reached, provided that original allowance can cover the close fee. The UI selects this association automatically. Preserve pending/staging journals.

The local UI can use guarded sponsorship with its existing mobile flow:

```sh
python3 -B tools/wallet_ui.py --root .data/rehearsal --profile preview \
  --sponsor-password-file <private-sponsor-password-file> --start-network
```

This remains a device-local process that sees wallet unlock passwords and seeds. Do not host it as a multiuser wallet or sponsor service. Operator password files need separate secret provisioning; storing one beside its ciphertext defeats at-rest protection for that machine. Runtime hot files are not protected from a compromised local operator. Journal integrity/anti-rollback assumes a trusted owner-only local filesystem; do not restore an older journal to refill allowances. Missing/malformed/changed ledgers fail closed, and changing an existing policy does not silently create a new budget. Independent durable accounting/replication and replenishment authorization are required before a public sponsor service.

## Acceptance

`python3 -B tools/sponsor_localnet.py --root .data/<new-short-name>` creates a fresh local rehearsal and private ignored test inputs. It owns/stops both validator children and wallet subprocesses. It tests encrypted recovery and authority separation, UI-backed real deposits/sends, sponsor overrides/limits, cross-wallet exclusion, SIGKILL during upload and immediately after reservation, coordinated validator restart, sponsor re-encryption, original-budget cleanup, seed-copy duplicates and exhausted allowances. Final assertions reconcile the sponsor's on-chain balance with all transaction fees, permanent nullifier rents and deposit value, require an untouched treasury and compare exact native state on both validators. Evidence is in `sponsor-result.json`; key/password files are never included in source control.
