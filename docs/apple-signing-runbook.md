# Local Apple signing preparation

Use a previously authenticated path-remapped archive, its signed descriptor and independently initialized verifier state. Work on copies. Keep validators paused; this performs no RPC requests, payment broadcasts, service installation or administrator actions.

```sh
python3 -B tools/wallet_apple.py prepare \
  --archive /private/tmp/reviewed-input/wallet.tar.gz \
  --release /private/tmp/reviewed-input/release.json \
  --trust-root /private/tmp/reviewed-trust \
  --root /private/tmp/new-apple-preparation
python3 -B tools/wallet_apple.py verify --root /private/tmp/new-apple-preparation
```

Trust must already carry the externally established publisher/profile/channel/minimum-sequence pins. Never initialize trust from a download. Input verification enforces its existing rollback cursor. A new preparation root must not exist. Use `--resume` only for that original input/trust binding. Corrupt or partial initialization fails closed; retain it rather than resetting state.

`state.json` points to a completed private attempt. Attempts retain original native bytes, empty entitlements, transformed payload, signed `wallet-rehearsal.dmg`, `REHEARSAL.json` and `NOTARIZATION-PLAN.json`. Interrupted attempts are retained. `BUILD.json` describes pre-sign bytes; `APPLE.json` binds them to the transformed signature/executable. Normalized code/data identity is checked independently of whole-file hashes.

`wallet_apple.mounted_payload(root)` provides locked read-only inspection and normal cleanup. `wallet_apple.recover_mount(root)` reconciles a crashed inspector's exact owned attachment. Unexpected image/mountpoint/device state stops cleanup rather than detaching another disk. The copied launcher uses isolated Python; Python 3.10+ remains external. Nothing is copied into Applications or existing tester wallet state.

Run finite real-artifact acceptance against the retained LOCAL-036 sequence-5 fixture:

```sh
python3 -B tools/wallet_apple_rehearsal.py --source /private/tmp/native-remapped-wallet-036-9v420550
python3 -B -m unittest discover -s tools -p '*_test.py'
```

This kills real preparation processes after payload/image signing and an actual mounted inspector, resumes original inputs, tests the hardened native wallet offline with a fresh encrypted seed/restore, and kills the fixture handoff before hypothetical acknowledgement. It never contacts Apple. Ignored `.local/apple-037-stage.json` and `.local/apple-037-result.json` link retained evidence.

The disabled plan is data, not a live release executor. A future implementation must create a **new Developer ID artifact**, use hardened runtime, an explicit reviewed identity and secure timestamps, regenerate provenance/inventories, then create/sign the image. [Apple's requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) apply to real distribution. Never treat the ad-hoc image as a release.

Submit without waiting, persist the UUID before polling and bind results to the exact submitted digest. An uncertain response requires explicit reconciliation; do not blindly upload again. Persist rejection and diagnostic logs privately. Accepted status alone does not prove ticket installation or end-user Gatekeeper acceptance. Staple, validate and assess in a clean environment, then hash/sign the final distributable with independently distributed publisher pins because stapling changes bytes. Credential values never belong in commands, receipts, logs or source. Live operations remain unimplemented and untested.

The transformed `apple-signing-rehearsal` inventory is intentionally unsupported by the current update installer. Do not relabel it or reuse the original descriptor: its bytes changed. Production update integration requires separate review/acceptance.
