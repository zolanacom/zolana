# Zolana (ZOL) network identity and portal

The selected product name is **Zolana**, with native coin ticker **ZOL**. This names the independent privacy L1 and its wallet; it does not create a Solana token, mainnet, bridge, production coin supply or public listing. Existing network domains, program identifiers, genesis, historical signatures and encrypted wallets are unchanged. Retain upstream attribution and the established wallet data directory, including its legacy name, so rebranding cannot silently produce an empty wallet.

Make the chain visible through a network portal: overview, public block/transaction explorer, honest validator-service status, builder information and a separate wallet handoff. The wallet is one client of the chain. A branding page alone would not demonstrate the network, so the explorer must read actual recorded public blocks and support block/hash/signature lookup, details, pagination and reloadable links.

The portal does not start validators. Use a pinned retained-history snapshot from the prior local chain tests rather than exposing raw RPC or inventing live activity. Validate the selected network, each referenced segment checksum, boundaries, block ancestry, heights and bounded transaction/signature metadata before building a read-only in-memory index. Missing records mean absence from this snapshot, not absence from the chain. Checksums/continuity are not consensus proofs or payment-recovery authority.

Read only the sanitized service heartbeat for last observations, with an explicit matching genesis binding, and reconcile local launchd status before claiming the managed service is running. Do not expose process IDs, filesystem paths, credentials, raw transactions, wallet contents or operator routes. The portal has no RPC forwarder or mutations. Bind HTTP to loopback and its exact host; reject cross-site requests and serve only a fixed asset/API inventory.

The existing saved wallet and the retained archive are different development-genesis fixtures. Preserve the existing wallet and identify that mismatch at handoff. Never migrate funds, substitute a profile or imply a bridge between them. The portal can show recorded chain evidence while the old wallet remains accessible offline.

The first visual direction used large typography, quiet navigation and a table-driven explorer; the portal's styling has since been revised. Reuse the repository's dependency-free HTML/CSS/JavaScript conventions. No hosted frontend, remote font, analytics, dependency download or service privilege change is needed.

## Status update (2026-11-20)

This record is kept as written. When it was written the name created no Solana token. ZOL has since been issued as a token on Solana, and the project runs a public devnet; see [Token](../../README.md#token) in the README. Devnet test coins are valueless and distinct from that token. The bridge is planned and not built, and there is still no mainnet.
