# Local gateway acknowledgement-loss acceptance

Start with the original stopped isolated service and the original funded desktop client evidence from LOCAL-021. The expected pre-test private balances are 950,000/1,050,000, with twelve permanent nullifiers. The test sends exactly 10,000 private units using the sender's quoted user-paid fee cap. It creates no wallet, grant, reservoir, validator identity or genesis.

Build and check the changed wallet/faucet clients offline with limited jobs while validators are paused. Prepare a new sealed service bundle, review and pin its installer/manifest digests, and apply it using the existing administrator update procedure. Updating a paused service keeps it paused. The changed normal runtime and binaries must pass installed-seal verification before running the test.

`tools/gateway_ack_loss.py` contains the desktop participant and administrator-reviewed controller. Create a new mode-0700 desktop-owned directory under `/private/tmp`, named `native-ack-loss-022-` followed by 32 random lowercase hexadecimal characters. Start the desktop participant with the existing evidence:

```sh
python3 -B tools/gateway_ack_loss.py desktop \
  --ipc <new-private-coordination-directory> \
  --evidence <original-funded-desktop-evidence>
```

The administrator runs the exact digest-reviewed controller bytes with isolated system Python and role `administrator --ipc <same-directory>`. Do not execute mutable desktop code as root without the digest bootstrap, and never pass administrator passwords through chat or command arguments. The controller uses only the sealed installed service tools and fixed service paths. It verifies the original normal launchd configuration and paused state before opening the temporary test job.

The protocol is ready → durable pending/client stop → exact gate arm/client resume → authentic finalized reply held → signing-client SIGKILL → supervisor SIGKILL and automatic validator replacement → exact original journal recovery → original signature resolution/staging cleanup → replay original resolution journal → verified balances and unchanged native effects. Ordinary invited authorization and durable usage limits apply throughout. The controller compares admission/claim and key/budget hashes across the crash before subsequent client requests legitimately charge usage again; member identities, policy and claims remain pinned after those requests.

The desktop participant refuses an existing `ack-loss-022.json`. The controller refuses an existing `ACK-LOSS-022.started.json`, result or gate. On a failure retain those records, the original pending/staging files and saved copies. Recover the original transaction explicitly; never clear markers, recreate wallets, refill allowances or re-run the send as a retry. A complete pending file is required before stopping the client, so the test does not freeze an incomplete initial file write.

There are two narrow continuation modes. `--resume-waiting` only resumes an unchanged authentication wait before any signer, pending/staging file or administrator reply exists. It never retries a started send. `--recover-held` handles the original LOCAL-022 checkpoint-command failure: the desktop must still have the exact saved pending/staging bytes, original wallet fingerprints and `client_stopped` record; the administrator requires the original `starting` checkpoint, identical keys/budgets/plist, an already-held authentic acknowledgement and no desktop native-wallet process. Both participants use a new private coordination directory. This mode preserves the original failure record, never rearms the gate or launches a send, and refuses a second recovery attempt. Its report explicitly records the orderly failure cleanup before the subsequent abrupt service crash test; it must not be described as an uninterrupted fresh run.

The temporary gateway records every transaction broadcast attempt before forwarding, including attempts whose upstream call fails. After the crash, resolution and journal replay must add no broadcasts, apart from at most one explicitly identified original staging-close transaction. A fresh checkpoint command must load the service's private RPC routes before querying status; it cannot fall back to raw TCP.

The test job has reduced scheduling priority, the existing low-disk guards and a ten-minute deadline shared across restarts. The controller pauses validators and restores the exact original normal plist in cleanup. Confirm that no service-account process remains before reporting completion. The signing client also runs at reduced priority. No legacy wallet validator or public deployment is started.

Success requires accepted resolution of the original signature, exact 940,000/1,060,000 private balances, fourteen permanent nullifiers, unchanged wallet/backups/profile identities, original gas/staging authority and fee cap, no extra grant or sponsor usage, and repeated desktop denial of keys/raw RPC. Actual recovery scan statistics must show authenticated cache use. The replayed pending-journal step must not change the canonical native state or resubmit a payment.
