# Local test distribution

Build with `CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-wallet -p native-localnet`. Keep all ceremonies, validators, keys and testing local; this runbook does not publish anything.

1. Export a public wallet profile with the existing package tool. Explicitly add `--faucet http://127.0.0.1:8780` alongside `--transport loopback-http` and the intended loopback RPC. No faucet URL is automatically discovered or copied from an operator config. The bundle contains the client only, never the faucet executable, wallet or credentials.
2. Prepare a separate owner-only password file (12–1024 bytes), outside the tester package. Run `target/debug/native-faucet init --root .data/new-faucet --profile wallet-profile.json --password-file <private-file> --max-claims 3`. The directory must be new. Save the encrypted recovery file and password separately. Keep the entire data directory backed up; the seed alone does not contain the claim ledger.
3. Fund the displayed private reservoir address and public fee address through an explicit local operator ceremony. Three grants need 3,000,000 private units, 450,000,000 public gas units, and extra working rent/fees for the faucet's own sends. The acceptance rehearsal provisions 5,000,000 private units and 1,000,000,000 public units. The service never opens a cold vault or automatically replenishes its balance. Do not use the faucet seed in another spending process.
4. Run `python3 -B tools/test_faucet.py --root .data/new-faucet --password-file <private-file> --port 8780`. It binds only 127.0.0.1. Run the standalone wallet package locally. Create a wallet, save and confirm the encrypted recovery, then select **Get test coins + gas**. The wallet checks the same claim automatically for three minutes; **Check coins + gas** also resumes checking. Closing/restarting the wallet is safe; unlocking/restoring and selecting the button reuses the claim.
5. Once finalized, normal private sends use the tester's own gas account and require no operator sponsor. The fee review still checks the actual on-chain balance and authorization cap. Receiving addresses and gas addresses are visible together to the faucet; shielded sends retain the existing protocol's privacy limits.

For interruption, preserve all files and restart the same service/root. The worker resolves gas signatures and private pending records canonically, recovers interrupted upload rent, and retains accepted outcomes. Do not delete progress, outcomes, pending/staging journals, claim reservations or source wallet data to force a retry. Missing state, exhausted attempts/capacity, insufficient reservoir funds, unavailable canonical history or a different source seed require operator recovery. Never initialize over an existing faucet or substitute a new ledger with the same funded key.

Reproduce the real acceptance using a fresh short `.data` root:

```
python3 -B tools/faucet_localnet.py --root .data/new-faucet-check \
  --evidence <new-temporary-evidence-directory> \
  --browser-script <temporary-playwright-check-script> \
  --playwright-module <cached-playwright-module>
```

The harness owns its validators and loopback servers, simulates acknowledgement loss by forwarding and withholding real RPC replies, crashes only its own worker children, restarts both validators with existing towers/ledgers, and checks canonical balances/nullifiers and public gas accounting. Existing fixtures or evidence directories are refused before mutation. Browser scripts/screenshots remain outside committed source.
