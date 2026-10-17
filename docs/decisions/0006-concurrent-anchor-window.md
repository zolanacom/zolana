# Bounded concurrent anchor history

The 24-client RPC baseline finalized exactly 16 independent deposits and rejected eight with invalid instruction data after their shared anchor was evicted. Distinct sponsors, random shielded keys and nullifiers remove shared-wallet locking and intentional double spending from that workload.

Development format NPOOL003 retains 64 recent roots instead of 16. The pool is 3,137 bytes. Roots remain bounded, validated and authenticated in Bank state; nullifier checks, proof verification, compute charging and consensus thresholds are unchanged. This accommodates the tested burst, not arbitrary throughput or every proof's complete authorization lifetime. The shared writable pool and finite history remain limits. Wallets must synchronize before proving and cannot indefinitely queue proofs.

This is a fresh-genesis development change. NPOOL002 accounts and configuration are rejected, never silently reinterpreted or migrated. Historical fixtures and validation evidence remain intact; use the corresponding historical build to operate them. New recovery tests use NPOOL003.

Wallet uploads combine initialization and the first bounded write, then pack ordered writes into signed packets of at most 1,232 bytes. A 9,222-byte proof uses ten upload transactions including sealing, rather than fifteen. Instruction order is preserved inside each transaction and dependent transactions still wait for confirmation. Staging initialization remains journaled before broadcast; value-changing finalization retains its separate pending journal and finality checks.
