# Explicit Developer ID preparation and recoverable notarization

This adds a separate real Developer ID preparation/notarization implementation beside the frozen ad-hoc signing rehearsal. It authenticates the original publisher release first, copies it, verifies an explicit Apple signing identity/chain/fingerprint and records pre-sign build provenance. A new artifact type prevents the existing installer from silently accepting transformed bytes.

Submission intent precedes the external operation; the resulting UUID precedes polling. An uncertain outcome requires exact artifact/job reconciliation, never automatic resubmission. Ticket installation and local Gatekeeper assessment are distinct from Apple's accepted result, and fixture evidence can never claim any of those live outcomes. A final publisher envelope must cover final post-stapling bytes.

No Apple Developer ID certificate has been used with this implementation. No enrollment, identity provisioning, credential setup or live Apple operation was performed; only local component tests and an ad-hoc recovery rehearsal were run.

Because asking newcomers to install software raises onboarding and trust concerns, further Apple delivery work is deferred in favor of the [browser-first delivery decision](0035-browser-first-wallet-delivery.md). This code remains a reviewed optional distribution path, not a requirement for chain users. Python/Terminal removal, updater integration, real signing/notarization and external quarantine installation were not completed.
