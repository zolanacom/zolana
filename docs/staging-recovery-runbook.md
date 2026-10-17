# Wallet upload interruption and rent recovery

Build the native wallet and localnet helper, then select a new short path under ignored `.data/`. Stop other fixtures using ports 18899/19899 first.

```sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-wallet -p native-localnet
python3 -B tools/staging_localnet.py --root .data/s1
```

The runner uses the already built fork validator, two owned loopback processes and random encrypted Alice/Bob/Carol wallets. It writes `<root>/staging-result.json` and retains ledgers, journals, receipts and logs. Cleanup stops owned wallets and validators on success or failure. Keep at least 2 GiB free.

It first deposits 20 native units, starts another deposit and observes the native buffer while only part of the payload has been uploaded. A concurrent reclaim must fail the wallet operation lock. The runner SIGKILLs only its own authenticated, live wallet child. The retained journal must block a fresh payment, reject the wrong sponsor, and enable staging closure. The sponsor's finalized balance increase must equal the staging rent minus the close transaction's actual fee. Pool and permanent nullifier accounts must stay unchanged.

After a new private send succeeds, the runner submits an initialization with an unfunded fixture signer. Preflight failure must leave its original signed identity and lifetime recorded. A reclaim before that lifetime has ended must remain blocked. The experiment never changes that real record's expiry; it waits for finalized block height to pass and then clears it without rent movement.

The second owned wallet SIGKILL occurs after a real deposit executes and before finalization/cleanup. Reclamation must refuse its unresolved payment. The original signature must finalize, `resolve` must recover acceptance once and preserve the staging recovery record, and `reclaim` must close the consumed buffer with the exact rent-minus-fee refund. Finally, seed-only restored wallets must recover balances 18/5 with backing 23, six commitments and six permanent markers. No pending/staging records may remain.

This tests process interruption on a retained local archive. It does not establish power-loss filesystem durability, recovery of deleted/corrupt journals or coordination across separate seed copies. RPC consensus remains trusted. It does not deploy a bridge, Solana settlement or any public network.
