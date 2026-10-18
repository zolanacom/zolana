# Coordinated restart of the disposable local cluster

An ordinary restart retains Agave's vote-before-leader guard. If the 80% identity restarts, waiting for a new rooted vote can deadlock this two-node fixture. Use the explicit coordinated path when majority stake must restart. It uses the upstream `--wait-for-supermajority`, `--expected-bank-hash`, `--expected-shred-version` and `--require-tower` arguments; consensus code and protocol storage are unchanged.

For the whole cluster, stop its managed processes, then restart from their existing ledgers:

```
python3 -B tools/localnet.py stop --root .data/<network>
python3 -B tools/localnet.py coordinated-start --root .data/<network>
```

For just the majority identity, leave the minority running:

```
python3 -B tools/localnet.py stop --root .data/<network> --validator 0
python3 -B tools/localnet.py coordinated-start --root .data/<network> --validator 0
```

The command requires new finalized slots beyond the stored tip before reporting success. An available RPC socket or a readable old balance is insufficient. The full-cluster command applies the coordinated gate to node 0 and ordinary catch-up to node 1. An explicitly selected node 1 also supports the gate, but its approximately 20% stake alone cannot pass the upstream 80% threshold.

Preflight opens the stopped ledger exclusively, verifies the identity's signed tower, and checks its last vote hash and ancestry against the retained frozen bank. It binds the checkpoint to the saved genesis and identity. The checkpoint must be above the saved tower root, blockstore root and available snapshot roots: upstream interprets a wait slot equal to the restored root as a hard fork and discards tower restoration, which this helper refuses. It also rejects dead/duplicate checkpoints and unsupported ledger tails.

A normal shutdown can leave one partial child after the last frozen bank, including absent skipped slot numbers. The helper retains that slot's original data and coding shreds. Agave's existing `next_leader_slot` skips slots with existing shreds; no ledger truncation, hard fork, tower reset or unconditional leader override is performed. Intermediate slot metadata, dead/duplicate tails or missing history require separate investigation and are refused. A missing tower after a managed launch fails before process creation. A new bootstrap also checks for existing ledger history and snapshots, so losing a PID file cannot silently turn an old ledger into a fresh bootstrap.

Ignored `restart-checkpoint-<index>.json` records the bank hash, shred version, roots, signed tower file digests, frozen bank hashes and individual shred digests. These are public consensus artifacts, kept locally with the rest of the private experiment directory. Keep the original ledgers, towers and logs when investigating a refusal.

The upstream stake gate counts recently observed gossip contacts with matching shred versions, including the local identity. It is an operator-controlled restart mechanism, not an additional cryptographic agreement on a checkpoint. This local 80%/20% fixture assumes preserved identity storage, honest local operators and no simultaneous duplicate identity process. This validation covers orderly restarts, a partial shutdown slot and absent quorum. Arbitrary disk loss, Byzantine forks, partition rollback and abrupt crash durability remain in LOCAL-005.

To repeat the complete wallet and restart acceptance on a new disposable network:

```
python3 -B tools/wallet_localnet.py --root .data/<new-wallet-network>
python3 -B tools/restart_localnet.py --root .data/<new-wallet-network>
sh tools/check.sh
```

The adverse runner reads the seed-restored wallet balances and requires their sum to equal native backing, with no open staging accounts. It preserves logs and signed tower copies, tests wrong hashes/shred versions, missing/corrupt towers and an isolated minority, then performs majority and whole-cluster restarts. It requires fresh finalization across an epoch, sends one unit privately, reconstructs its already-public proof from archive staging transactions and rejects that proof after another restart while its authorization remains live. A three-unit deposit and two-unit withdrawal then increase backing by one and add six commitments/nullifier accounts in total. For a fresh wallet fixture starting at 5/15 with ten commitments, the final balances are 7/14, backing 21 and 16 commitments/markers. The receipt records the actual starting and final values.

Payment finalization and staging-rent reclamation have separate commitment barriers. The runner waits for the successful close transaction to finalize on both peers before saving account snapshots; otherwise a consumed staging account can disappear between snapshots and cause a false recovery failure. Retained bank hashes and individual shred bytes must survive every audit. The runner refuses an existing success receipt rather than applying payments again.

If the harness is interrupted immediately after its private send, it saves the accepted receipt and pre-send journal. `--resume-evidence <restart-evidence-directory-name>` resumes that one submitted send, validates restored balances and reconstructs the accepted public proof instead of sending twice. It requires exactly one journaled payment and a still-live authorization for the subsequent replay test; it does not bypass expiry or resolve ambiguous wallet submissions.

Everything binds to loopback and stays under ignored `.data`.

A single unfrozen child may follow skipped slot numbers. The local inspector accepts the actual parent only when no intermediate slot metadata exists, the checkpoint is frozen/live, and signed-tower ancestry matches. Dead/duplicate/multiple tails still fail closed; a complete child still requires peer-corroborated offline replay. No shreds or towers are discarded.
