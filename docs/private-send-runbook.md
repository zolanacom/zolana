# Local sponsor-free private sends

Private sends use the native coin of this independent chain. They do not send SOL or Solana tokens. The recipient needs a private `npriv1` address on the same network. The sender needs spendable private notes and public test coins at the separate seed-derived fee address. No operator sponsor is required once those balances exist.

Request a private-send quote without sending a proof or revealing the private recipient:

```sh
target/debug/native-wallet fees --network <wallet-profile.json> \
  --wallet <encrypted-wallet.json> --password-file - --payment send
```

With a standalone tester profile, omit `--rpc`; the profile pins it. An existing local fixture instead uses `--network .data/p1/network.json --rpc http://127.0.0.1:18899`. The quote reports `payment: send`, fee address/balance, refundable staging rent, permanent nullifier rent, transaction fees, protected cleanup room and a gross cap. A different chosen cap requires sufficient public balance for that entire cap plus the account minimum. A withdrawal quote remains the default; use `--payment withdraw` explicitly when desired.

Submit after reviewing the fee bound:

```sh
target/debug/native-wallet send --network <wallet-profile.json> \
  --wallet <encrypted-wallet.json> --password-file - \
  --to <same-network-private-address> --amount <private-native-units> \
  --fee-payer user --max-fee-debit <reviewed-gross-debit-bound>
```

Do not combine user-paid fees with sponsor key/password/request options. Deposits and legacy sponsor-crediting withdrawals are not enabled by user fee mode. The recipient receives the full private amount; gas/rent comes from the sender's public fee account. Upload rent is refunded only after successful cleanup. Permanent nullifier rent and transaction fees remain spent. The currently large temporary rent and raw test-unit display are development economics.

In the device-local wallet, unlock → **Send** → enter recipient/amount → review fee account and funding → **Review payment** → **Send payment**. An unfunded fee account blocks submission. **Refresh fee balance** and **Edit payment** preserve the draft. The review states the gross fee cap separately from private value and explains public fee-account/timing visibility. A development sponsor can be selected explicitly only when operator credentials were configured locally. Standalone users have no sponsor option or automatic test-coin faucet.

After a crash, keep all encrypted files and `.pending.json`/`.staging.json`. An unknown payment must be resolved before new payments or upload-rent cleanup. The UI offers **Check previous payment**, then **Recover upload rent**. CLI recovery remains:

```sh
target/debug/native-wallet resolve --network <wallet-profile.json> \
  --wallet <encrypted-wallet.json> --password-file -
target/debug/native-wallet reclaim --network <wallet-profile.json> \
  --wallet <encrypted-wallet.json> --password-file -
```

No sponsor arguments or new cap are accepted for original user-paid cleanup. Resolve uses canonical full RPC history/status; cache/retained inclusion metadata cannot authorize an unknown result. A missing unexpired signature stays pending. A seed-only restore recovers both private and fee authorities and reconstructs notes from retained history, but it does not copy another device's unfinished journals. Keep one active operation per seed; do not create replacement payments to resolve unknown execution.

Repeat acceptance on a new short ignored fixture, using an already installed browser runtime:

```sh
python3 -B tools/private_send_localnet.py --root .data/private-send-new \
  --playwright-module /path/to/installed/playwright \
  --browser-script /private/tmp/private-send-browser.cjs \
  --evidence /private/tmp/private-send-evidence-new
```

The runner creates independent encrypted client state outside the repository, an initial bounded development deposit and one valueless public-gas allocation per user. It then makes sponsor files unavailable and checks actual browser/CLI sends, upload and finalized-reply SIGKILL, validator SIGKILL/rejoin, coordinated restart, unchanged pending/cap journals, canonical UI recovery, new-buffer spent-proof rejection, restored recipient/sender spending, withdrawal compatibility and exact fee/rent/backing/nullifier accounting. Its browser phases are `unfunded`, `funded` and `recovery` at `http://127.0.0.1:8772/`; passwords and private receiving addresses enter that isolated script through stdin JSON, never process arguments or logs. Screenshot/browser scripts live outside committed source.

The runner refuses existing roots. `--resume-setup` is narrowly limited to preserved pre-deposit setup failures: it retains all keys/wallets/ledgers, requires no payments, pending uploads or used sponsor reservations, and does not initialize/reset anything. It does not resume an ambiguous or accepted deposit. `--resume-upload` handles the exact preserved negative-assertion mismatch after the first accepted browser send and Bob's upload SIGKILL; it requires the same wallet state, original cap/journal and exact native balances/count, reconstructs operator baselines from canonical setup history, and continues without another deposit, gas allocation or browser payment. Finalized-history readiness is checked before scanning after startup; missing history still fails closed in the wallet. All fixtures/evidence remain preserved and owned processes stop on failure or completion. External hosting, test-gas distribution, packaging/signing, physical-device/Safari validation and independent review remain separate work. No deployment.
