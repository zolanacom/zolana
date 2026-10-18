# Local user-controlled withdrawals

Work only in an existing owner-only local rehearsal or a new short `.data` directory. Do not replace old genesis, keys, wallets, reservations, towers or ledgers to enable this feature. Fresh `init-private` activates recipient-bound withdrawals; old genesis needs a future coordinated activation procedure.

Build offline with the cached toolchain, then run the acceptance suite on a **new** root:

```sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p agave-validator -p native-localnet -p native-wallet
python3 -B tools/withdraw_localnet.py --root .data/w1 \
  --playwright-module /absolute/path/to/cached/playwright \
  --evidence /private/tmp/withdraw-evidence
```

The runner creates separate random private operator passwords under ignored `.local`, encrypts the sponsor, and launches only two local validators plus loopback wallet/proxy services. It never exports signing keys or publishes anything. It preserves every run and stops its own children even on failure. Ordinary invocation rejects an existing run directory. The narrowly checked `--resume-before-upload-crash` and `--resume-after-lost-ack` options resume only their preserved two- and five-reservation cases. `--resume-after-payments` requires the six completed reservations, the recorded non-broadcast blockhash preflight error and exact pre-transfer public balances. It refuses unknown spending outcomes. These options never reset policy, keys or journals. Replace the example root with a new short name when reproducing acceptance; `.data/w1` is preserved evidence.

The wallet's `balance` response includes `public_address`, `public_balance` and `minimum_public_withdrawal`. In the UI, select **Withdraw publicly**, check the public destination and amount, review the public disclosure, then confirm. The default destination is controlled by the same encrypted recovery seed. The first withdrawal must cover that account's minimum balance; an already funded account can receive smaller amounts. These are this chain's test units, not SOL.

Withdrawals can also use [user-paid fees](user-paid-fees-runbook.md) without operator credentials. The following older example selects the guarded development sponsor and its durable allowance:

```sh
target/debug/native-wallet withdraw \
  --network .data/w1/network.json --wallet /absolute/path/to/encrypted-wallet.json \
  --password-file - --rpc http://127.0.0.1:18899 \
  --sponsor-password-file /absolute/path/to/private-operator-password \
  --sponsor-request-id unique-attempt-identifier --amount 1000000
```

An optional `--to <public-address>` selects a different ordinary public account. Verify its owner and network yourself. The operator sponsor cannot change that address without invalidating the proof. Keep the encrypted recovery file and password separately.

After an interrupted withdrawal, do not retry it as a new payment. If `.pending.json` exists, run `resolve` against this network's full-history RPC. It either returns the canonical recipient/amount and clears a known result, or retains the journal while the result is unresolved or saved intent differs. A snapshot-only peer or retained archive cannot resolve an unknown withdrawal. Keep a full-history peer available.

Then run `reclaim` with the original encrypted sponsor to close the staging account. Do not supply a new request ID for cleanup; the saved original reservation applies even when new-payment allowances are exhausted. A crashed upload without a pending finalization can go directly to `reclaim`. Never delete journals, reset sponsor reservations or reinitialize the network as a recovery shortcut.

Encrypted seed restoration plus verified retained history restores shielded notes and the public signing authority after a snapshot-only peer rejoins. The one-shot local `owner-transfer-check` utility verifies actual public signing control with a recovered seed; general public-account send and private key export are deliberately outside this wallet flow. Physical mobile/Safari behavior, independent security review and production sponsor/onboarding operation remain separate gates.
