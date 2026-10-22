# Apple release preparation

This preparation is tested locally with injected fixtures only; real Developer ID signing and notarization have not been performed, and no real Apple Developer identity has been used with this path. Further Apple delivery work is deferred under the [browser-first delivery decision](decisions/0035-browser-first-wallet-delivery.md). This runbook is an optional future distribution path, not mandatory public onboarding.

## Separate real and rehearsal paths

`tools/wallet_apple.py` remains the frozen ad-hoc signing rehearsal library. It never produces an Apple-approved release.

`tools/wallet_apple_release.py` is the new explicit Developer ID preparation CLI. It requires independently initialized publisher/profile/channel/minimum-sequence trust, an original authenticated path-remapped archive/descriptor, explicit usable Developer ID Application certificate SHA1, Team ID and bundle identifier. Never derive trust from a download or invent an identity. Missing identity refuses before workspace creation. Work only in a genuinely new private root; resume only the original immutable input binding. Interrupted attempts stay retained.

Preparation signs copies with hardened runtime, empty entitlements and secure timestamps. Verification requires an Apple-anchored Developer ID chain, exact public leaf fingerprint, Team/identifier and unchanged executable code/data. BUILD retains pre-sign provenance, APPLE binds the transformation, exact inventories bind resources and a separately signed DMG/receipt binds resulting bytes. `verify --root ... --receipt-sha256 ...` verifies completed preparation. `prepare --help` lists its required arguments. Actual preparation may contact Apple's timestamp service; no real invocation has occurred.

## Notarization and interruption recovery

`tools/apple_notary_release.py init --root ... --prepared-root ... --preparation-sha256 ... --keychain-profile ...` requires the completed, independently pinned Developer ID receipt. It freezes a submission copy and binds an explicitly reviewed credential profile NAME, never its secret. No credential setup is performed by this tool. An account holder must establish real membership/certificate and appropriate notary authentication separately; do not enter passwords/API secrets in command arguments or receipts.

Use `status --root ...` to inspect bound state. Each live `submit`, `check`, `reconcile`, `staple` or `assess` operation requires `--execute` for that specific action. CLI fixture mode does not exist. Submit does not wait; it durably records intent BEFORE the external operation and UUID BEFORE polling. A timeout or lost response leaves submission_unknown. Do not resubmit: reconcile the exact original job with `reconcile --submission-id ... --execute`, requiring the completed job log to match the exact submitted SHA256. Preserve unknown/rejected state and diagnostics.

Accepted info is followed by the bound raw log. Stapling works on a separate attempt copy, validates the ticket and exact signature, then records the changed digest. Local Gatekeeper assessment remains distinct; neither accepted status nor successful local assessment proves external-device behavior. Final `release_ready` stays false: post-stapling publisher signing/update integration and real external-device acceptance remain required.

The new apple-developer-id inventory is intentionally refused by the old installer. Do not relabel it or reuse the original signed descriptor. A self-contained .app/runtime and normal quarantine installation also remain unimplemented. Signing the current CLI/folder would not remove its external Python3.10/Terminal dependency.

Focused local tests are `wallet_apple_release_test.py` and `apple_notary_release_test.py`. They inject Apple responses and permanently label fixtures; passing them does not notarize software. Actual power-loss durability, real certificate/authentication, Apple service results and clean external-device acceptance are untested.
