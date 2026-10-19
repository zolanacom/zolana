# Finalized explorer projection and separate current-network wallet

Status: accepted for local development. No hosted deployment or protocol change.

The portal needs current public chain activity without acquiring private RPC credentials. The sealed service publishes a fixed finalized metadata projection in its existing service-owned public health directory. The desktop portal reads this projection and an independently selected retained-history archive; it cannot request arbitrary methods from the service.

The projection permits only finalized block ancestry/hash/height, first transaction signatures, public execution/fees and public voting identities. It contains no serialized transactions, instruction payloads, logs, wallet secrets, access proofs or RPC credentials. It is bounded to 2 MiB and 2,048 blocks. Strict ownership, no-follow reads, exact schemas and a single publisher lock guard local publication. Atomic durable replacement is also the publisher's restart checkpoint. An uncertain storage result requires reopening the original file. Restart rechecks the last original checkpoint against finalized RPC before extending it.

A finalized observation from the selected local service is not an independent consensus proof. The portal reports live activity only while both the managed health observation and feed sample are fresh. Saved finalized metadata remains searchable during outages and intentional pauses. Five-second visible-page refresh does not replace an open detail, dialog or expanded pagination.

Retained wallet history is a native-payment subset of each block. Full-block feeds also include votes and other public transactions. On overlap, block ancestry/hash/height must match, every original payment signature must be included, and slot, fee and execution must remain identical. A subset position may differ from a full-block position. Full-block records use their canonical position. Conflicts preserve the last good index rather than partially replacing it. Coverage and saved-subset counts are disclosed.

An older user wallet is bound to another genesis. It must never be repinned or relabeled as current chain funds. Keep it at a separate local endpoint with original storage and password. A separate empty client directory uses the current public gateway profile and matches the explorer genesis. The wallet provides an explicit link to the previous wallet. This separation does not migrate funds or consume an invitation.

Installed-service acceptance is finite and read-only. It verifies original private-file hashes and exact canonical pool/nullifier accounts before and after supervisor SIGKILL, checks that the public feed revalidates and advances, and unloads the service after testing. Original failed evidence is retained. No new payment, faucet grant or admission policy is created by this integration.
