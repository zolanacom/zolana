# Native payment privacy and tester delivery review

Engineering review, 2026-10-22. This is an internal code/trust-boundary review, not an independent cryptographic audit. Native payments are experimental test coins on a three-validator, single-host/operator rehearsal. No speed advantage over other systems has been demonstrated.

## Claims supported by the inspected implementation

The explicit `native-inline-v1` path creates its Orchard proof and decrypts private outputs on the wallet device. A shielded send deducts the reviewed fee from its private inputs, with a shared relay handling public execution costs: no user public gas balance is required for that send. Public withdrawals retain their separate funded public fee-account requirement.

The native shielded-send payload does not contain a plaintext application sender, recipient or payment amount. Its public fields still include the exact fee/payee, network/expiry, nullifiers, commitments, randomized authorization keys, encrypted outputs and proof/signatures. Timing and the two-action shape remain observable. The pool is one native asset; this does not demonstrate arbitrary private SOL/USDC or token-identity hiding. Deposits and withdrawals expose public account/amount information. Finality comes from trusted canonical-finalized operator RPC, not a client verification of independent consensus certificates.

Read `protocol/payments/`, `clients/wallet/src/payments/`, `clients/wallet/src/shielded/native.rs` and `node/adapter/` for the corresponding construction, verification and accounting. Orchard/Halo2 and Ed25519 are not claimed post-quantum safe; the [migration roadmap](post-quantum-roadmap.md) is planned work.

## The gateway can link member activity

`clients/wallet/src/access.rs` signs access with a stable seed-derived fee/public identity. Admission combines that identity with a private receiving address. `clients/wallet/src/rpc.rs` attaches authenticated access to gateway requests. `tools/testnet_gateway.py` passes the member identity into the relay, and `tools/shielded_relay.py` durably records hashed-member ownership of submitted jobs. Hashing an identity known to the operator is not anonymous membership.

The operator can observe membership, receiving address, its own faucet grants, socket IP and request timing/methods, and link submitted packets to membership. The relay payer is shared fixed operator configuration. Inspected client flows do not export viewing/spending keys to it, but that does not imply anonymity from the operator. A gateway can also deny service. Local/SSH-loopback routing may change the peer IP visible at an individual boundary; it is not evidence of network anonymity.

There is also a potential active metadata watermark: the wallet accepts a valid quoted payee/fee under the authorized cap; the proof binds those public effects. A malicious operator could individualize them. Honest current configuration uses shared fixed settings. Stronger operator-unlinkability would require a reviewed policy, credential and submission design; it has not been implemented here.

## Delivery fixes implemented in this phase

`tools/package_wallet.py` previously omitted `private_send_transport` and `retained_history_format` from its public allowlist. Packaging now preserves these two explicit optional modes. Deployment endpoints, admission selection and public local CA remain explicit package arguments; operator credentials and arbitrary extra fields remain excluded. The real wallet `TesterProfile` parser still validates the final assembled profile before any archive is written. Invalid modes are retained for rejection rather than silently downgraded.

The device-local UI launcher accepts `--binary` only in standalone `--network-profile` mode. This allows a reviewed native executable to be selected without accidentally using a stale `target/debug` binary or starting local validators. Fixture mode rejects this override.

UI status now reports `test_faucet_configured` instead of asserting `test_faucet_available`. It means a pinned endpoint exists; it does not claim live/funded grants. The matching UI says “Join testnet,” makes funding checks explicit, and distinguishes queued, funding, ready and operator-recovery states. Checking existing invitation access no longer implicitly requests coins. Missing endpoint/sponsor gives a disabled “Test funding unavailable” control.

The privacy dialog, invitation screen and payment review distinguish public-ledger payment secrecy from member/IP/timing/submission linkage. They explain local proof/decryption, private-send fees and public withdrawal boundaries, and do not promise a bridge or PQ protection. These are targeted copy/capability changes, not a redesign.

## Remaining gates

External trusted HTTPS/client-profile delivery, supported external devices, finite real pilot admission, concurrent use, independent backups/history, off-host human paging and wider security review remain gates. Live send/receive/respend acceptance on a hosted network and real mobile-device testing were not part of this review.
