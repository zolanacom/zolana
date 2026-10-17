# Local private-payment wallet

`native-wallet` creates its own random Orchard spending keys. It does not use the public Alice/Bob fixture keys in `payment-lab`. Keys, note decryption, coin selection, witnesses, proving and authorization all stay in the local process. This is an experimental CLI for the disposable local chain; RPC endpoints are restricted to literal loopback HTTP, with proxies and redirects disabled.

## Build and exercise

From the repository root:

```
sh tools/build_localnet.sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-wallet
python3 -B tools/wallet_localnet.py --root .data/wallet-example
```

The harness requires unused local validator ports 18899 and 19899 and a new ignored data directory. Stop the previously managed network through its own `tools/localnet.py stop --root <old-network>` before starting another one. It preserves previous networks. The harness initializes the native pool using the existing `native-localnet` binary and starts the fork's actual validators with transaction history enabled.

It generates two independent random-key wallets, executes deposit/send/change/withdrawal and a two-note spend, reconstructs balances on both peers, exercises the pending-payment guard, restores from seed-only backups and restarts the 20% minority validator while majority stake stays online. Restart acceptance requires fresh finalized blocks and peer catch-up, not only recovered balances. It also restores the follower from a full snapshot and checks that a wallet refuses incomplete history there while recovery still succeeds through the original archive node. Receipts stay in `.data/<network>/wallet-result.json`; secret material remains in private files under its `wallets/` directory. Test completion leaves both validators running.

## Create and back up

Wallet and backup files contain an encrypted 32-byte Orchard spending seed plus network metadata. They contain no note database or balance cache. The encryption is XChaCha20-Poly1305 with random 16-byte KDF salt and 24-byte nonce; PBKDF2-HMAC-SHA256 uses 600,000 rounds. The complete format/network/KDF/nonce header is authenticated. Every save uses a new salt and nonce, mode 0600, exclusive creation and a file sync. Existing files are never overwritten. Password and seed buffers use zeroizing storage.

The password is read from a private regular file, never a command-line value or environment variable. It must contain 12–1,024 bytes; bytes are used exactly, including any newline. Reads reject group/world-readable files and symlinks. A password file, encrypted seed file and public fee-payer key are different things. Store the encrypted backup and its password separately. Restoring the private seed does not restore a separate public sponsor key.

For local testing, create a private directory and a random password file without printing it:

```
mkdir -m 700 .data/my-wallet
python3 -c 'import os,secrets; f=os.open(".data/my-wallet/unlock.password",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.write(f,secrets.token_bytes(48)); os.close(f)'
target/debug/native-wallet init --network .data/wn2/network.json --wallet .data/my-wallet/main.wallet.json --backup .data/my-wallet/main.seed-backup.json --password-file .data/my-wallet/unlock.password
```

The receiving address is public and may be copied. Its `npriv1` format contains the raw Orchard address, a domain derived from both the native network ID and expected genesis fingerprint, and a checksum. It is an experimental native address format, not a Zcash unified address. Deposits default to the wallet's own receiving address; sending requires an explicit destination.

## Discover, send and withdraw

Use the same `--network`, `--wallet` and `--password-file` options on every command. Add `--rpc http://127.0.0.1:18899` for chain operations. `address` needs no RPC. `balance` returns the verified finalized balance, unspent-note count and the largest amount payable from two notes.

```
target/debug/native-wallet balance --network .data/wn2/network.json --wallet .data/my-wallet/main.wallet.json --password-file .data/my-wallet/unlock.password --rpc http://127.0.0.1:18899
```

`deposit`, `send` and `withdraw` also require `--sponsor <private-keypair.json>` and `--amount <positive-native-units>`. The sponsor file must be private. `send` requires `--to <npriv1-address>`; `deposit` optionally accepts it. Withdrawal pays the signed public sponsor, as required by the minimal protocol. The sponsor pays public transaction fees, temporary staging rent and two permanent marker rents. The wallet normally closes consumed staging accounts after finalization to reclaim temporary rent; permanent marker rent remains locked and is separate from shielded backing.

Coin selection uses up to two largest unspent notes because the protocol has exactly two actions. Positive change goes to an internal Orchard address, which the scanner also discovers. If the amount exceeds the value in two notes, the CLI rejects it even when the total balance is higher. Consolidate smaller notes by sending a supported amount back to your own address. All amounts are integer native units, not decimal coin strings.

## Restore and interrupted submissions

```
target/debug/native-wallet restore --network .data/wn2/network.json --wallet .data/my-wallet/recovered.wallet.json --backup .data/my-wallet/main.seed-backup.json --password-file .data/my-wallet/unlock.password
```

Then run `balance` against the archive RPC with the recovered wallet path. The address and notes are reconstructed from the seed and verified chain history, with no original wallet cache required.

Before broadcasting finalization, the wallet exclusively creates a durable private `<wallet-path>.pending.json` containing its signed transaction identity, staging address, network and blockhash validity height. An unresolved record blocks another value-changing command for that wallet path. Balance scanning remains available. If finalization is uncertain, do not delete that record or retry a fresh deposit. Run `resolve` with the same wallet/network/password/RPC arguments. It scans complete finalized history and checks execution status; it clears the record only after observing the accepted finalization, a finalized failure, or a complete checkpoint beyond blockhash expiry that excludes the transaction. A still-live unknown transaction remains blocked. This protects retries in one wallet path; it is not a distributed lock across separate seed copies.

After a successful finalized payment, failure to close staging is reported separately in `staging_rent_reclaimed`; it does not turn an accepted payment into a failed one. A failed or interrupted staging upload can leave a refundable staging account; automated cleanup of every partial upload is future work.

## Verification and limits

The scanner starts at genesis and reads successful top-level native instructions from complete finalized blocks. It resolves versioned account keys, verifies transaction signatures, reconstructs sequential uploads/seals, verifies Orchard proofs and authorizations, rebuilds the spent set/frontier/backing and compares the entire result with one finalized pool checkpoint. Failed transactions contribute no native effects. It checks parent-slot/hash continuity and refuses missing staging data, unsupported/missing metadata or a state mismatch. It derives notes from both external and internal incoming viewing keys and derives current Merkle witnesses locally.

RPC consensus and the supplied genesis configuration remain trusted. These checks authenticate discovered notes relative to that node's canonical pool state; this is not a light client or independent consensus proof. A hostile node controlling both history and pool responses is outside this trust model.

Complete archive history is required. A compact validator snapshot preserves the pool and permanent replay markers but does not contain old ciphertexts from closed staging buffers. Snapshot-only or pruned RPCs must fail rather than display a partial zero balance. An archive node or future encrypted-output retention/indexing design is needed for new-wallet recovery. The local harness retains the complete experiment but still has a ledger-size bound; it is not an unlimited archival service. This CLI deliberately has no persisted note cache; full rescanning uses memory and time proportional to history and is not a production scaling solution.

Sponsors, fees, nullifiers, timing and public deposits/withdrawals remain visible. The pool is still a shared write lock, anchor history is only 16 roots and proving/submission can race a busy chain. No independent security audit, network anonymity or public deployment is claimed. See LOCAL-003 validation for completed evidence.
