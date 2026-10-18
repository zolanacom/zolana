# Local user-paid withdrawal fees

This path uses this chain's native coin. It requires an existing recipient-withdrawal activation, the encrypted wallet seed/password and public coins at the seed-derived fee address. Operator sponsor credentials are unnecessary.

The same bounded authority now supports [private sends](private-send-runbook.md). Use `fees --payment send` and `send --fee-payer user --max-fee-debit <bound>`. The default `fees` command below retains the withdrawal quote for compatibility.

```sh
target/debug/native-wallet fees --network .data/u1/network.json \
  --wallet <encrypted-wallet-file> --password-file - \
  --rpc http://127.0.0.1:18899
```

The quote's `fee_address` differs from the public withdrawal address. Fund that fee address on this L1 before withdrawal. `refundable_staging_rent` is temporary collateral; `permanent_nullifier_rent` and transaction fees are spent. `funding_required` includes the gross-debit quote plus the account minimum. The `maximum_gross_debit` includes reserved cleanup room. A larger chosen cap requires enough balance to cover that full cap and the minimum.

```sh
target/debug/native-wallet withdraw --network .data/u1/network.json \
  --wallet <encrypted-wallet-file> --password-file - \
  --rpc http://127.0.0.1:18899 --amount 1000000 \
  --fee-payer user --max-fee-debit <reviewed-gross-debit-bound>
```

An optional `--to` selects an ordinary public recipient. Do not supply `--sponsor`, `--sponsor-password-file` or `--sponsor-request-id` in user-paid mode. The proof binds the user fee authority and withdrawal destination independently. Withdrawals remain public on this L1.

The device-local UI can start without `--sponsor-password-file`. Open **Withdraw publicly**, review the fee quote, fund the displayed address if needed, refresh, choose the amount and review the cap before confirming. **Send** uses the same fee authority with its own private-payment quote. An explicitly configured test sponsor remains a selectable development option; it is never an automatic fallback from a failed user-paid operation. Automatic faucet funding remains disabled when no sponsor is configured.

After an interruption, preserve `.pending.json` and `.staging.json`. Run `resolve` first when a pending finalization exists, using full canonical history. Then run `reclaim` with the same wallet and password and no sponsor arguments. The CLI detects user-paid recovery, derives the original signer and reuses its saved cap and cleanup allowance. It never refunds/reset charges or increases the cap automatically. A pending/unfinished upload blocks another withdrawal at that wallet path. Keep one active operation per seed and retain its journals when copying/restoring a wallet.

Repeatable acceptance uses a new short `.data` root, the cached Playwright runtime and a browser script saved outside the repository. `tools/userfees_localnet.py --help` lists the inputs. The runner funds one private note using the development sponsor, makes the sponsor vault/policy/journal unavailable, tests an unfunded fee account, gives it one valueless gas allocation from the cold test treasury and then performs only user-paid withdrawals. It tests actual browser review/payment, upload and finalized-acknowledgement SIGKILL, abrupt validator rejoin, coordinated restart, original-cap recovery, seed restoration and exact public/private/fee accounting. Existing run directories are refused and all test children are stopped even on failure. Initial gas allocation is setup, not a production public faucet.

All existing fixtures, operator files and genesis remain preserved. No remote or public deployment is involved. Physical mobile/Safari behavior, independent review, fee-account funding UX outside the local rehearsal and production economics remain open.
