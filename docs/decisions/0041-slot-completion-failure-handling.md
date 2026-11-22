# What a validator does when a slot cannot be completed

Status: draft for review. Nothing described here is implemented.

## The situation

The Agave 4.3.2 candidate completes a payment slot inside `Bank::freeze`. `seal_native_payment_slot` in `runtime/src/bank.rs` reads the pool account, decodes it, calls `PoolState::with_completed_slot` with the slot of the bank, and stores the result. Leaders and replaying validators both go through it before the bank hash is computed, so the checkpoint is part of the state every validator has to agree on.

Both steps that can fail end in `expect`: decoding the pool account, and recording the checkpoint. A failure is therefore a panic of the validator process while it freezes a block.

Such a failure is a function of the block and of the state before it. Every validator that replays the block reaches it. The leader reaches it when it freezes its own block, by which time the block has been broadcast. A validator that is restarted replays the same block from its ledger and stops again. The network cannot root anything after the parent of that block until the operators agree, outside the protocol, on a different binary or on a ledger without the block.

The protocol fuzz targets found pool states on which the checkpoint is refused ([protocol fuzz targets](../protocol-fuzzing.md)). The two rules added after that close the ways of reaching one that were found. They do not make the failure impossible: a state with a checkpoint that claims a root it never had still decodes, and for the states the program writes the argument rests on the tree hash having no collisions. This record is about what the validator does if a refusal happens anyway.

## What any answer has to satisfy

- **Same result everywhere.** The outcome depends only on the block and the state before it, never on timing, local configuration or what a node has seen.
- **Same result on a leader and on replay.** A leader must not produce a block that it, or any replaying validator, then treats differently.
- **Payments fail closed.** No root becomes an eligible anchor unless a completed slot recorded it under the existing rules.
- **Wallets follow the same rule.** `WalletState` in `wallet-core` completes every replayed block with `complete_slot` and treats a refusal as an error. Whatever a validator does to the pool on a refusal, a wallet replaying the chain has to do too, or it stops at that block.

## Options

### A. Keep the panic

| | |
| --- | --- |
| Leader | Stops while freezing its own block. The block has already been broadcast. |
| Replay | Every validator stops at the same block, and again after each restart. |
| Network | Halts at the parent of the block until a coordinated restart with another binary or a truncated ledger. |
| Payments | Nothing wrong is ever committed. |

Fail-stop is the right answer to a fault on one machine, such as a damaged account: that validator stops instead of voting on a state the others do not have. It is the wrong answer to a failure every validator shares, because one block then stops all of them and restarting does not help.

### B. Leave the pool unchanged and freeze

On a refusal the pool account is not written. The validator logs an error, reports a metric, and freezes the bank as it would without the payment program.

| | |
| --- | --- |
| Leader | Freezes its block. The bank hash covers the pool as the last transaction left it. |
| Replay | Computes the same state and the same hash, and votes. |
| Network | Keeps producing and rooting blocks. Votes and public transfers are unaffected. |
| Payments | The slot records no checkpoint. Every following slot tries again. Roots recorded earlier stay eligible until they leave the window of 512 slots; a payment that changes the tree in that time makes it recordable again. If none does, no root is eligible once the window has passed and every payment is refused until the pool is repaired by a release. |

The rule is deterministic and adds no state. It turns a halt of the network into a stall of private payments that an operator has to notice, so the log line and the metric are part of the change, not an extra. When the pool account does not decode at all, the payment program already refuses every payment against it; leaving it unchanged at freeze is consistent with that.

### C. Treat the block as invalid

The validator would check before freezing whether the slot can be completed and mark the slot dead if it cannot, as replay does for a block it cannot verify.

| | |
| --- | --- |
| Leader | Has no way to withdraw a block it has broadcast. It would need a new path to abandon its own block, in upstream code the candidate does not otherwise change. |
| Replay | Marks the slot dead and votes for a fork without it. |
| Network | Continues on the fork that skips the block. |
| Payments | The payment that led to the refusal is not in the surviving fork, and can be sent again. Each time, the leader that includes it loses its block. |

On its own this lets one transaction cost a leader a block as often as it is submitted. It only works together with D, and with D it is no longer needed.

### D. Refuse the payment that would leave the pool uncompletable

The payment program would refuse, as it refuses any invalid payment, a payment after which the executing slot could not be completed. In the protocol library this is the general form of the empty-leaf rule: `with_payment` on a slot-anchored pool returns an error when the tree it would leave could not be recorded after the stored checkpoints.

| | |
| --- | --- |
| Leader | Executes the transaction, which fails. The block is valid and the pool is as it was. |
| Replay | The same execution and the same failure. |
| Network | Unaffected. |
| Payments | One payment is refused. Slot completion can then be refused only for a pool state the program did not write. |

This removes the cause where it arises and makes "every state the program writes can complete its slot" true by construction, without relying on the tree hash or the proof system. It costs one more computation of the tree root for each payment into a slot-anchored pool, and it is a change to which transactions succeed, so it is a consensus rule like any other in the program.

## Recommendation

Adopt **D and B together**.

D makes a refusal at freeze unreachable from any state that decodes and any payment that is accepted. B is what remains underneath: if a pool state from an earlier version, a fault we have not thought of, or a state written by a mistake in a later change cannot be completed, the validators stay in agreement and the chain stays up, with payments stalled and an operator alerted, instead of every validator stopping at once.

A is not kept alongside B. A validator whose own copy of the pool is damaged computes, under B, a bank hash that the rest of the network does not vote for, so it is out of agreement without a panic. Whether such a validator should also stop itself is a question about local faults in general and is not answered here.

C is not recommended.

## Rollout

Both parts change what a validator computes, so both need a coordinated validator release.

- **B** differs from the present behaviour only where a present validator stops. An old and a new validator can never root different states because of it: the old one halts where the new one continues. A mixed network is therefore safe, but it only keeps running through a refusal if validators with more than two thirds of the stake run the new rule. Wallets have to carry the matching rule in the same release line, so that a wallet replaying a slot without a checkpoint leaves its copy of the pool unchanged too.
- **D** changes the result of a transaction. For a payment that leaves an uncompletable tree, an old validator accepts it and may then complete the slot after all if a later payment in the same slot changes the tree, while a new validator has refused it. That is a divergence without a halt, so D must not run mixed with the old rule: it needs either an activation feature, as the slot anchors themselves have, or one stop in which every validator changes binary. Which of the two is a decision for the operators of the network at the time.

Neither part changes anything for a state that the present rules can complete.

## Not decided here

- The names of the log line and the metric, and which health checks read them.
- How a stalled pool is repaired once B has kept the chain running.
- Whether the legacy `NPOOL003` format needs any of this. It completes no slots.
