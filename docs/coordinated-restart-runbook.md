# Coordinated restart of a preserved local cluster

An ordinary restart retains Agave's vote-before-leader guard. If the 80% identity restarts, waiting for a new rooted vote can deadlock this two-node fixture. Use the explicit coordinated path when majority stake must restart. It uses the upstream `--wait-for-supermajority`, `--expected-bank-hash`, `--expected-shred-version` and `--require-tower` arguments, plus the opt-in native startup replay bound `--native-restart-checkpoint`. The bound preserves later ledger records for normal verified replay after the stake barrier; it changes startup control, not payment rules or protocol storage.

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

A shutdown can leave partial children, compatible complete descendants, rejected forks and competing complete blocks. The inspector classifies these by ancestry while retaining every record and existing rejection flag. The native startup bound prevents a higher competing block from bypassing the pinned bank/stake barrier. A crash can also persist a signed vote before the last shred batch: only a complete frozen ancestor on that same branch can then serve as checkpoint, with the original future tower vote and lockouts retained. Missing selected ancestry, duplicate/frozen-dead contradictions and root-reaching checkpoints still fail closed. A missing tower after a managed launch fails before process creation. A new bootstrap also checks for existing ledger history and snapshots, so losing a PID file cannot silently turn an old ledger into a fresh bootstrap. See [the preserved-checkpoint design](decisions/0021-preserved-restart-checkpoint.md).

Ignored `restart-checkpoint-<index>.json` records the bank hash, shred version, roots, signed tower file digests, frozen bank hashes and individual shred digests. These are public consensus artifacts, kept locally with the rest of the private experiment directory. Keep the original ledgers, towers and logs when investigating a refusal.

The upstream stake gate counts recently observed gossip contacts with matching shred versions, including the local identity. It is an operator-controlled restart mechanism, not an additional cryptographic agreement on a checkpoint. This local 80%/20% fixture assumes preserved identity storage, honest local operators and no simultaneous duplicate identity process. This validation covers orderly restarts, a partial shutdown slot and absent quorum. Arbitrary disk loss, Byzantine forks, partition rollback and abrupt crash durability are not covered by this validation; see the [fault recovery runbook](fault-recovery-runbook.md) for process-crash and partition cases.

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

A single direct unfrozen complete child can use peer-corroborated, no-voting offline replay. Multiple or uncorroborated complete children stay stored for native checkpoint startup and ordinary post-barrier verification; the helper never guesses their bank hashes. No shreds or towers are discarded. The sealed service always gates both validators and wraps rehearsals in one shared finite deadline; validators remain paused outside explicitly requested tests.

Managed launches use `--native-durable-votes` so new signed votes require complete local data for the candidate and its unrooted ancestry. Native coordinated replay verifies historical local-leader blocks from the captured pre-start slot inventory instead of treating them as live TPU output. An optional `--native-restart-epoch-horizon`, with required ancestor slot/hash pins, opens at most one extra leader-schedule epoch from a shared frozen ancestor. It does not advance roots or replace towers; normal rooted schedules must agree when finality catches up. These custom runtime paths need independent review before external deployment. Process SIGKILL and repeated restarts of preserved installed ledgers have been exercised; power-loss durability is not established.

The installed-service acceptance performs existing invited-wallet reads in the original desktop session. A root child that merely changes UID does not inherit the desktop session's macOS folder-access authorization. The finite controller publishes readiness, then validates a bounded, non-executable result receipt from that desktop check while separately checking invitation membership and faucet state. No persistent privileged command queue or authentication bypass is installed.
