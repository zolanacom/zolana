# Bridge between the ZOL token on Solana and native ZOL: options

Status: options record, not a decision. Nothing is chosen here. No bridge is designed in detail, implemented or deployed, and this record sets no order or time for any of it. Choosing among the options belongs to the project's owner, after the questions listed for counsel in section 7 are answered. Devnet coins are valueless test coins and are distinct from the ZOL token issued on Solana; nothing below changes that.

## Context

[Decision 0005](0005-independent-privacy-l1.md) chose an independent chain and left the bridge for later: "Its asset custody, remote-state verification, replay protection, withdrawal rules and failure recovery require their own design and review. Bridging is not implemented and must not be described as inheriting Solana's settlement security." The [README](../../README.md#token) has since said publicly what the bridge is meant to do: "The planned bridge will lock ZOL on Solana and mint an equal amount of native ZOL on Zolana, **1:1**", and "holders will lock ZOL on Solana and mint the same amount on the Zolana network".

This record works out what those sentences require, sets out the ways a bridge could be built and the trust each one asks for, lists the failures every design has to survive, and lists what must exist before a bridge runs even on a test network. It ends with the decisions that are not engineering's to take and the facts that are missing.

Words used below. The **token** is ZOL on Solana, at the address given in the README. The **native coin** is the coin of the Zolana chain. The **lock account** is the token account on Solana that holds locked tokens. **Mint** and **burn** mean creating and destroying native coins through the bridge; **release** means paying tokens out of the lock account. **Finalized** means irreversible by the rules of the chain in question.

## 1. What the public statements require

| Statement | What follows |
| --- | --- |
| "lock ZOL on Solana" | The tokens are not destroyed. They sit in an account on Solana, and something controls that account for as long as they exist: a program, keys, or both. That control is custody of other people's tokens, whatever it is called. A lock also suggests a way back. No return path has been stated publicly; whether there is one is a decision (section 7). |
| "mint ... native ZOL on Zolana" | The bridge creates the chain's own coin, not a wrapped token inside a program. The runtime inherited from Agave makes every instruction leave the sum of balances unchanged (`UnbalancedInstruction` in `node/agave/transaction-context/src/lib.rs`), so today native coins appear only at genesis and through the reward code. A bridge therefore needs one of two things: a new protocol rule that creates and destroys coins on a verified bridge message, or a **reserve** created at genesis and held by a bridge program with no key, from which coins are paid out and to which they return. With a reserve, the supply figure that matters excludes the reserve, and the reserve must be at least as large as the token's whole supply for every token to be able to cross. Both forms are consensus-level work, like the shielded-payment program ([decision 0003](0003-native-validator-integration.md)). |
| "an equal amount", "1:1" | At the least: the amount minted equals the amount locked, in exact units. A bridge fee, if there is one, is a stated share of that amount and never extra coins. The token's decimals and the native coin's smallest unit must convert exactly, with a stated rule for amounts that cannot be represented on the other side. Read in the ordinary way the phrase says more: every native coin is matched by one locked token. Section 2 shows what that reading does to genesis, inflation and fees. |

## 2. What "1:1" implies for genesis, inflation and fees

The devnet's numbers are development parameters: "No production supply, issuance, fee or rent schedule has been chosen" (README). They are still the starting point, because a later network built from the same code inherits the same mechanisms unless someone changes them. On the devnet line today:

- **Genesis creates coins.** One run of a development harness creates the validators' stake and vote accounts and a funding account that holds nearly all test coins (`node/candidate/agave-4.3.2.patch`, the call to `LocalCluster::new_alpenglow` and the configuration before it).
- **Inflation is on.** The inherited reward code mints new coins at every epoch boundary and pays them to the stake accounts. This is the harness's default, observed on the devnet as stake balances that grow at each boundary. Nobody chose it.
- **Coins are burned.** Each vote account is charged 0.8 coin an epoch and the charge is destroyed ([vote-admission funding](../vat-budget-runbook.md)). The inherited fee rules also burn a share of every transaction fee (`burn_percent` in `node/agave/runtime/src/bank/fee_distribution.rs`).
- **Coins are parked for good.** Every account holds a rent minimum, and every shielded spend creates permanent marker accounts that hold theirs ([decision 0004](0004-durable-nullifiers.md)).

Each of these either creates native coins that no locked token stands behind, or removes native coins while their tokens stay locked.

| Mechanism | Effect on "every native coin is matched by a locked token" | Choices |
| --- | --- | --- |
| Genesis balances: stake, vote accounts, operator and fee accounts, any treasury | Coins exist before anyone has locked anything | (a) Genesis contains only coins matched by tokens locked beforehand, with the lock referenced in the published genesis. Someone must own those tokens and lock them. (b) An unbacked genesis allocation, published, with "1:1" then describing the conversion rate only |
| Staking rewards from inflation | New coins every epoch with no lock | (a) No inflation. Validators are paid from fees and from a rewards account funded with backed coins, which runs down. (b) Inflation stays, and each issue is matched by tokens minted into the lock account on Solana. That needs a live mint authority on the token, held by the bridge. (c) Inflation stays unbacked and is published |
| Burned fees and the burned vote charge | Native coins fall while locked tokens do not. The difference can never be released | (a) Nothing is burned: fees and charges go to validators or to the rewards account. (b) Each burn is matched by burning tokens from the lock account. (c) The gap is accepted and published as a running total |
| Rent minimums and permanent markers | No change in supply. The coins exist and cannot move, so their tokens stay locked | None needed for the invariant. It is a cost question for the fee schedule |
| Bridge fee | None if it is a share of the minted amount. Unbacked coins if it is added on top | A share, or no fee |
| First fee | A holder who arrives through the bridge has no native coins to pay for the minting transaction or for the minimum balance of a new account | A relayer that submits the mint and is paid a stated share of it, as a relay already is for shielded fees ([decision 0032](0032-shielded-fees.md)); or the holder obtains native coins first |
| Units and range | Balances are 64-bit counts of the smallest unit. The token's supply and decimals decide whether every amount converts exactly both ways | A fixed conversion factor and a rounding rule that never mints more than was locked |

Under choice (c) for inflation, or (b) for genesis, native coins outnumber locked tokens. Coins are interchangeable, so the lock account then cannot pay out every holder who wants to return, and the last to try find nothing left to release. That is a fractional reserve whether or not it is called one, and "1:1" should not be said of it without that explanation.

### The invariant a public monitor would check

Let `V` be the token balance of the lock account at a finalized Solana slot, and `C` the native coins that exist at a finalized Zolana slot outside the bridge's own reserve. Let `locked` and `released` be running totals kept by the bridge program on Solana, and `minted` and `burned` running totals kept by the bridge on Zolana. Let `G` be the genesis supply outside the reserve.

1. **No coin without a lock:** `G + minted <= locked`, comparing a Zolana state with any Solana state at or after the last Solana slot that the Zolana state has acknowledged. `G` is zero, or is matched by a lock made before genesis and counted in `locked`.
2. **No release without a burn:** `released <= burned`, compared the same way in the other direction.
3. **The lock account holds what the totals say:** `V >= locked - released`. Less means tokens left by some other path.
4. **Nothing else creates coins:** `C = G + minted - burned + issued - destroyed`, where `issued` is protocol issuance and `destroyed` is protocol burn. The supply rule chosen from the table fixes both.

Together, when nothing is issued without a matching lock: **`C <= V` at all times, and `V - C` equals the transfers in flight plus the published total of coins destroyed.** A monitor recomputes this from public data on both chains and raises an alarm when the difference goes negative, or moves by an amount that no bridge message explains.

For the check to mean anything: the native supply and the four totals must be values that consensus fixes and any node can serve; the monitor must read its own node on each chain, because a monitor that asks the project's endpoint is checking the project's word (README, "Wallets trust their RPC endpoint"); its code must be public; and someone other than the bridge's operator must run it.

The shielded pool does not weaken the check. Shielded value is backed by a public balance in the pool account, and a withdrawal larger than that balance is refused (`InsufficientBacking` in `protocol/payments/src/state.rs`). A flaw that let someone forge shielded notes could take other users' backing out of the pool, but it could not raise `C`. Zcash enforces the same boundary and calls it a turnstile ([ZIP 209](https://zips.z.cash/zip-0209)).

## 3. Design options

Two choices are separate from the verification model and apply to all of the models.

**One direction or two.** The public sentences describe one direction: lock on Solana, mint on Zolana. A bridge whose lock program has no release instruction at all cannot have its lock account emptied by a forged message, a stolen key or a failure of Zolana's consensus, because there is nothing to call. What remains is the risk of coins created without a lock. The price is that nobody can go back. A two-way bridge puts the locked tokens of everyone who stays on Zolana behind whatever authorises a release. Zolana's validators already define what the native coin is, so holders of native coins trust them under any design; a return path extends that trust to the tokens on Solana.

**Where the bridge lives on Zolana.** Either a built-in program, as the shielded pool is, changed only by a validator release and a feature activation; or a program deployed through the loader, with an upgrade authority. Whether the loader path is open on a given network is a property of its genesis and has to be stated for that network.

The four models differ in what authorises a mint on Zolana and a release on Solana.

| | A. Signer set | B. Each chain verifies the other | C. Optimistic with challenges | D. Third-party bridge protocol |
| --- | --- | --- | --- | --- |
| What authorises a transfer | `m` of `n` named signers, as a multi-signature or as one threshold key, who watch both chains and sign what they saw | A proof, checked by a program on the receiving chain, that the sending chain finalized the lock or the burn | A bonded party asserts the transfer; it executes after a waiting period unless someone proves it false | The provider's verifier network attests the message; the provider's programs on both chains check the attestation |
| Assumption | Fewer than `m` signers are dishonest or compromised, and at least `m` stay available | Each chain's own consensus holds, and the verifying code is correct | At least one honest watcher is running and can get a transaction onto the chain inside the waiting period, and disputes can be decided correctly | The provider's quorum is honest, its programs are correct and its upgrade keys are safe |
| Who can steal | Any `m` signers, or whoever obtains `m` keys: the whole lock account, and minting without limit | Whoever controls a finalizing share of stake on the sending chain; anyone who finds a flaw in the verifier | The asserting party, whenever every watcher is down or censored for one waiting period; anyone who finds a flaw | The provider's quorum; the holder of the provider's upgrade authority; anyone who finds a flaw in the provider's code or in the integration |
| Who can freeze | `n - m + 1` signers, by refusing or by losing their keys | Nobody by choice, if anyone may relay proofs. A halt, or a break in the validator-set history, on either chain stops it | Any watcher allowed to dispute, at the cost of a bond; the party that decides disputes | The provider, through its pause or its governance; its verifiers, by not serving the chain |
| What a user must trust | The named signers and how they keep their keys | Zolana's validator set for releases on Solana, Solana's for mints on Zolana, and the verifier code | That watchers exist and are awake, and whoever decides disputes | The provider, its verifiers and its governance, on top of this project's integration |
| Operating burden | Signer machines, hardware key storage, rotation, people on call, and a node of each chain for every signer | Relayers, which affect only liveness; following validator-set changes on both chains without a gap | Watchers that must never all be offline together; bonds; handling disputes | The provider must add the chain and its operators must run Zolana nodes; this project still runs its own configuration and limits |
| Audit surface | Small: two programs and the signer software. The key ceremony and the operating procedure matter as much as the code | Large: two consensus verifiers, proof formats and validator-set tracking, all new consensus-critical code | Medium to large: everything in the dispute path, plus whichever of A or B decides a dispute | The integration and its configuration. The provider's code is reviewed by others, but it is large and changes when the provider changes it |
| How it has failed elsewhere | Ronin: five of nine keys were taken. Harmony's Horizon bridge: two keys were enough. Multichain: the keys were in one person's hands | Wormhole on Solana: a flaw in signature checking let an attacker mint without a deposit. BNB Chain's bridge: a forged proof passed verification | Nomad: an upgrade made every unproven message valid, and the waiting period protected nobody | Kelp DAO's rsETH: the route relied on a single verifier, and that verifier was fed false chain data |

Sources for the last row are listed at the end. They are other parties' accounts; figures and attributions differ between them.

### A. Signer set

The simplest to build and to explain, and the model behind the largest losses. It is custody by the signers. A set made of the project's own people or machines is one custodian however many keys it has; independence means separate organisations, separate infrastructure and separate jurisdictions where that matters. A threshold key hides who signed; an on-chain multi-signature shows it. Signers believe the nodes they read, so each needs its own node of each chain.

### B. Each chain verifies the other

The only model that adds no new trusted party, and the largest piece of new code. Three points decide whether it delivers that.

- **The release path rests on Zolana's validators.** Today every devnet validator is run by the project, on one host (README, "Operated by the project"). On such a network a proof of Zolana's finality is the project's own signature, and model B is model A with one signer. B gives what it promises only when operators outside the project hold enough stake that the project cannot finalize alone. This is what decision 0005's sentence means in practice: tokens locked on Solana are as safe as the weaker of the two chains and the bridge code, not as safe as Solana.
- **The mint path needs Zolana to verify Solana.** That means following Solana's validator set and stake from epoch to epoch, checking a supermajority's votes on a block, and proving that the lock record belongs to the state that block commits to. Solana's block hash does not commit to a tree over all accounts, proofs for light clients have been proposed rather than settled ([state verification proposal](https://docs.anza.xyz/proposals/simple-payment-and-state-verification), [SIMD-0052 discussion](https://forum.solana.com/t/simd-0052-add-transaction-proof-and-block-merkle-for-light-clients/297)), and Solana's consensus protocol is itself being replaced ([SIMD-0326 discussion](https://forum.solana.com/t/simd-0326-proposal-for-the-new-alpenglow-consensus-protocol/4236)). A verifier written against one version has to be kept correct against the next.
- **Restarts break the chain of evidence.** A verifier follows one validator set to the next. A fresh genesis, a coordinated restart or a return to an earlier state on either chain interrupts that. The procedure that re-anchors the verifier is a privileged action, and whoever holds it is a signer in the sense of model A.

### C. Optimistic with challenges

Something has to decide a dispute about whether a lock happened on another chain, and the only candidates are a verifier (B) or a signer set (A). So C is an addition to A or B, not a replacement: it adds a waiting period to every transfer and in exchange lets one honest watcher stop a theft. On a young network with few independent parties watching, "one honest watcher is always awake" is a weak assumption. Existing designs of this kind settle disputes through an external oracle ([Across security model](https://docs.across.to/reference/security-model-and-verification)).

### D. Third-party bridge protocol

- **The protocols differ in who verifies.** Wormhole has one fixed set of 19 guardians, of which 13 must sign ([glossary](https://wormhole.com/docs/reference/glossary/)); its token framework can lock on one chain and mint on others, with rate limits ([overview](https://wormhole.com/docs/products/native-token-transfers/overview), [rate limiting](https://wormhole.com/docs/products/native-token-transfers/configuration/rate-limiting)). LayerZero and Hyperlane let the application choose its verifiers ([LayerZero security stack](https://docs.layerzero.network/v2/concepts/modular-security/security-stack-dvns), [Hyperlane modular security](https://docs.hyperlane.xyz/docs/protocol/ISM/modular-security)). An application that chooses a single verifier, or runs all of them itself, has model A with more code.
- **The provider has to support the chain.** Its verifiers must run Zolana nodes and its programs must be deployed on Zolana, which needs an agreement and an open loader path. No provider has been contacted, and none has said it would support this chain.
- **The last step stays here.** These frameworks deliver a token inside a program. The native coin is not one. Turning an attested message into native coins, by a reserve or a minting rule, is this project's consensus-level code under every provider, and so is the supply rule of section 2.

### Combinations and limits

Two models can both be required, for example a proof under B and a signer set under A. Theft then needs both to fail, and either can freeze.

Some limits belong to every model: act only on finalized state; a cap on the total locked; limits on minting and release in any period, with a queue beyond them; a delay on large releases; a pause that can stop transfers but cannot move tokens, with a higher bar to resume than to pause; and the monitor of section 2 running before the first transfer.

## 4. Shielded balances at the boundary

The Solana side is public whatever is built: the sending account, the amount, the time and the Zolana destination named in the lock stay on Solana's ledger. A bridge does not make a holder's history on Solana private, and it never hides an amount that crosses it.

| Variant | Path | Visible at the boundary | Cost |
| --- | --- | --- | --- |
| S1. Public first | Mint to a public Zolana account. The holder then deposits into the pool as today. Leaving: withdraw to a public account, then burn | The Solana account, the amount and the Zolana public account; then the deposit's amount and account (README: "Deposits and withdrawals reveal their amounts and public accounts"). The Solana account and the deposit are linked on public ledgers | None to the pool. The bridge touches public balances only and the shielded program is unchanged |
| S2. Mint into the pool | The lock names a shielded address; the mint adds backing and a note in one step | The Solana account, the amount and the time. No Zolana public account appears. The shielded address written into the lock is public on Solana | The bridge and the pool become one unit to audit; there is a new way to create notes; a change to the pool then touches the bridge |
| S3. Burn from the pool | A shielded withdrawal bound to the bridge and to a Solana destination, in the way withdrawals are already bound to a recipient ([decision 0008](0008-recipient-bound-withdrawals.md)) | The amount, the time and the Solana destination. No Zolana public account | The same coupling as S2, on the way out |

S1 is the only variant that leaves the shielded program as it is. S2 and S3 can be added to any custody model later.

In every variant privacy begins after the value is in the pool, and it depends on how many other deposits there are and on how amounts and times line up. Someone who brings an unusual amount in and takes the same amount out links the two ends with no flaw in the cryptography. Wallet text at the boundary has to say so.

## 5. Failure cases every option must handle

| # | Case | What goes wrong | What a design must state |
| --- | --- | --- | --- |
| 1 | Keys lost | Fewer than `m` usable keys: nothing can be authorised and the tokens stay locked | How a set that has lost keys is replaced, by whom, and why that path is not itself a way to steal |
| 2 | Keys compromised | `m` keys in other hands: the lock account is emptied and coins are minted until someone notices. At Ronin the theft was not noticed when it happened | Limits that bound the loss in any period; who can pause and how quickly; rotation; that an old set cannot install a new one without a public delay |
| 3 | All keys with one party | One person, account or organisation can reach `m` keys or the machines that hold them (Multichain) | Signers in separate organisations; no shared administrator, cloud account or backup |
| 4 | Flaw in a verifier or program | A forged message is accepted (Wormhole, BNB Chain, Nomad) | Independent audit; limits; invariants 1 to 3 detect it within one check; who bears the loss |
| 5 | Signers or watchers fed false chain data | They sign for a lock that never happened (Kelp DAO) | Each reads its own node of each chain; no shared data provider; several independent sources must agree |
| 6 | Reorganisation on Solana | A mint follows a block that is later dropped | Act only on finalized slots; say what happens when Solana's cluster is restarted from an agreed slot, as has happened ([outage report](https://solana.com/news/02-06-24-solana-mainnet-beta-outage-report)) |
| 7 | Rollback or reset of Zolana | A burn already released on Solana disappears from Zolana: the coins exist again and the tokens are gone. A mint disappears while its lock remains: the holder's value is stuck. Earlier test networks have been replaced by fresh ones (README) | That the chain is never restored to a state earlier than the last burn released on Solana, checked by the restart procedure against the total recorded on Solana; that a lost mint can be claimed again; that a fresh genesis is a new deployment (case 11) and says what becomes of the old lock account |
| 8 | Zolana halted | Tokens are locked on Solana while Zolana cannot mint. After a short halt transfers wait. An earlier private pilot network stopped finalizing, and a restart did not re-establish consensus ([vote-admission funding](../vat-budget-runbook.md)); after a halt like that the locked tokens have no chain to be released from | Whether the lock program refuses new locks when Zolana has not been seen to finalize recently; whether an emergency release exists, who holds it and under what public rule; that such a release is a custody key and belongs under "who can steal" |
| 9 | Solana halted | Releases wait while Zolana continues | Burns stay valid and are released on recovery; nothing expires into a loss |
| 10 | Replay within a deployment | One message is used twice | A permanent record of consumed messages on both sides, as spent markers are permanent ([decision 0004](0004-durable-nullifiers.md)), that survives every upgrade |
| 11 | Replay across deployments | A message or signature from a test deployment, an earlier genesis or a redeployed program is accepted by another | Every message binds both chains' identities (payment authorisations already bind the network and genesis, [decision 0008](0008-recipient-bound-withdrawals.md)), both program addresses, the token's mint, the direction, a deployment number, a nonce, the recipient and the amount. Test and production never share keys. A redeployed program does not start with an empty record of consumed messages |
| 12 | The token's mint authority | If it exists, its holder can create tokens at will, lock them and mint native coins. Every invariant holds, and the supply is whatever that holder decides | The state of the authority (section 7, inputs). If it is revoked, that is permanent ([set authority](https://solana.com/docs/tokens/basics/set-authority)), and the choices in section 2 that mint tokens to match issuance are closed |
| 13 | The token's freeze authority | If it exists, its holder can freeze the lock account, which stops every release, or any holder's account | The state of the authority; if it exists, who holds it and under what rule |
| 14 | Features of the token program | If the token uses the token-extensions program, a transfer fee makes the amount received differ from the amount sent, a permanent delegate can move tokens out of the lock account, and a transfer hook runs another program on every transfer ([extensions](https://solana.com/docs/tokens/extensions)) | Which token program and which extensions (inputs). The lock program counts what arrived, not what was sent |
| 15 | Upgrade of the program on Solana | The upgrade authority can replace the program with one that pays everything out: it is a custody key. A program made immutable cannot be repaired ([program deployment](https://solana.com/docs/core/programs/program-deployment)) | Which it is: immutable, or an authority held by a signer set with a public delay. A build that anyone can reproduce and compare with what is deployed |
| 16 | Upgrade on the Zolana side | A validator release changes the bridge's rules, or an upgrade resets or wrongly initialises its state (Nomad) | Who approves releases and feature activations, since they are the upgrade authority. Upgrade tests that replay every earlier message and expect each to be refused |
| 17 | Change of validator set or signer set | A verifier misses a change and stops, or accepts a set that is no longer current | The handover rule, the longest gap tolerated, and who holds the procedure that re-anchors it |
| 18 | Transfers that cannot complete | The recipient account cannot receive, the amount cannot be represented, or no relayer is running | Every message can be completed or refunded by a stated rule; anyone may relay; nothing expires into a loss |
| 19 | Pause with transfers in flight | Value has left one side and has not arrived on the other | What is promised about transfers in flight, and who may resume |
| 20 | Supply rule changes | Issuance or burning changes and the bridge's accounting does not follow | The supply rule of section 2 is fixed by consensus, and the monitor's fourth term follows it |
| 21 | Late detection | A theft goes unnoticed | The monitor's alarm reaches people who do not depend on the operator; a public status |
| 22 | Impersonation | A site or program presents itself as the bridge and collects "locks" | The addresses of the real programs are published in this repository first. Until then the README's statement stands: nothing implements the bridge |

## 6. What must exist before any bridge is deployed on a test network

1. The owner's choices in section 7 on the supply rule, the direction and the verification model, and counsel's answers to the questions there.
2. The facts listed as inputs in section 7, recorded.
3. A written specification: the message format with the bindings of case 11, the state machines for each direction, the limits, the pause, upgrade and recovery procedures, and an answer for every row of section 5.
4. A review of that specification from outside the project before code is written. Nothing in this repository has had an outside review (README, "Not audited"), and a bridge is the wrong place to start without one. An audit of the code before any deployment that could hold the real token.
5. On the Zolana side: a test network whose identity is stable, or whose resets the bridge treats as cases 7 and 11; a statement of finality that a third party can check without the project's endpoint; a supply figure fixed by consensus; issuance, fee and burn rules chosen on purpose for that network, even as test values; a genesis procedure that can produce the chosen starting supply, which the present harness cannot be told to do; and a rehearsed way to activate a feature on a running network ([decision 0008](0008-recipient-bound-withdrawals.md) notes that this needs a coordinated validator upgrade and an activation plan).
6. A test token: a separate mint created for testing on a Solana test cluster. The real ZOL token is never locked by a test deployment, and devnet coins stay valueless test coins whatever a test bridge mints.
7. Keys generated for the test and used nowhere else.
8. The monitor of section 2, running against the test deployment before the first transfer, with an alarm that reaches someone.
9. Tests: property tests of the invariant, and fault injection for each row of section 5, including a rollback, a halt, two deployments side by side for replay, a lost key and an upgrade.
10. Runbooks for pause, rotation and incidents, and the wording users will see.
11. Public statements checked against the design, so that nothing says more than the design delivers.

## 7. Decisions that are not engineering's

### For the owner

1. Does "1:1" mean that every native coin is matched by a locked token, or only that the conversion rate is one to one? Does the public sentence stay as written while that is open?
2. Genesis: no supply outside a backed allocation, or an unbacked allocation. If backed, who locks the tokens behind the validators' stake and the operating accounts.
3. How validators are paid: fees only, a backed rewards account, issuance matched on Solana, or unbacked issuance.
4. Whether fees and the vote charge are burned, and if so whether the burn is matched on Solana or published as a gap.
5. One direction or two. If one, that it is said before anyone locks.
6. The verification model, A to D or a combination. For A: who the signers are, how many, and the threshold. For D: which provider; none has been approached.
7. Who may pause, resume, upgrade and rotate, and whether an emergency release exists.
8. The cap on total locked and the limits per period, and who may change them.
9. The shielded boundary: S1 alone, or S2 and S3 as well.
10. A bridge fee: none, or a share, and who receives it.
11. Who bears a loss if the bridge fails.
12. What must be true of the Zolana network before real tokens may be locked: operators outside the project, audits, uninterrupted operation. A condition, not a date.
13. If the token still has a mint or freeze authority: revoked, handed to the bridge, or held under a published rule.
14. Who outside the project runs the monitor.

### For counsel

Questions only. This record offers no answer to any of them.

1. Which legal entity would operate a bridge and hold or control its keys? Is holding or controlling the lock account custody or transfer of value that needs a licence or registration, and where? Who may be a signer?
2. How are the token and the native coin classified where they are offered? Do the published sentences about locking and minting an equal amount affect that?
3. Is "1:1" a statement about backing or redemption on which holders may rely? What follows if the supply rule makes it untrue for a time?
4. What did the token's launch materials say about supply, authorities, the bridge and the native coin, and is there a duty to correct or update anything?
5. What policy should apply to statements about a bridge that does not exist yet, and who approves them?
6. Do rules on privacy-enhancing assets affect operating a bridge, its signers or validators, or listing? Do variants S2 and S3, which move value directly into or out of the shielded pool, change the answer? What screening duties arise at the boundary for the operator, the signers and relayers?
7. Who is liable for a loss, and what terms and risk statements must a holder see before locking?
8. Do payments to validators from a rewards account, or agreements with signers or with a provider, raise regulatory or tax questions?

### Inputs needed

None of these is recorded in this repository, and no recommendation above depends on a guess at any of them.

- The token on Solana: which token program it uses and which extensions are enabled; total supply and decimals; whether a mint authority exists and who holds it; whether a freeze authority exists and who holds it; who can change its metadata.
- How the supply is distributed, and what the project could itself lock, since that decides who could back a genesis allocation.
- The token's launch materials: what was said about supply, authorities, the bridge and the native coin.
- On the Zolana side: the inflation settings in force on the devnet line, read from the chain; how fees are split and burned on the candidate line as built (the reference in section 2 is to the Agave 3.0.14 snapshot); whether deploying programs is enabled by the genesis in use.
- Whether any provider under model D would support this chain. Nobody has been asked.

## What this record does not do

It chooses nothing and schedules nothing. It contains no specification, no code and no parameter values. It does not change the README's statements: mainnet and the bridge are not live, nothing in this repository implements a bridge, and devnet coins are valueless test coins distinct from the ZOL token on Solana.

## Sources

Accounts of other bridges and their failures, by the parties involved or by security firms. They were read for this record as information; none is endorsed, and their figures differ.

- Ronin: [Back to Building: Ronin Security Breach Postmortem](https://roninchain.com/blog/posts/back-to-building-ronin-security-breach-6513cc78a5edc1001b03c364)
- Harmony Horizon: [Harmony's Horizon Bridge Hack](https://medium.com/harmony-one/harmonys-horizon-bridge-hack-1e8d283b6d66), [Halborn's explanation](https://www.halborn.com/blog/post/explained-the-harmony-horizon-bridge-hack)
- Multichain: [Blockworks report](https://www.blockworks.com/news/multichain-founder-family-arrested), [Cointelegraph report](https://cointelegraph.com/news/multichain-stops-operations-over-lack-of-funds)
- Wormhole: [CertiK incident analysis](https://www.certik.com/blog/wormhole-bridge-exploit-incident-analysis), [Kudelski Security analysis](https://research.kudelskisecurity.com/2022/02/03/quick-analysis-of-the-wormhole-attack/)
- BNB Chain bridge: [Immunefi analysis](https://immunefi.com/blog/bug-fix-reviews/hack-analysis-binance-bridge-october-2022/)
- Nomad: [Nomad's root cause analysis](https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd), [Immunefi analysis](https://immunefi.com/blog/bug-fix-reviews/hack-analysis-nomad-bridge-august-2022/)
- Kelp DAO's rsETH: the two parties' accounts differ on who chose the configuration ([LayerZero's account as reported](https://www.coindesk.com/tech/2026/04/20/layerzero-blames-kelp-s-setup-for-usd290-million-exploit-attributes-it-to-north-korea-s-lazarus), [Kelp DAO's account as reported](https://www.coindesk.com/tech/2026/04/20/kelp-dao-claims-layerzero-s-default-settings-are-what-actually-caused-the-usd290-million-disaster))
- Shielded pool boundary: [ZIP 209](https://zips.z.cash/zip-0209), [Turnstile Enforcement Against Counterfeiting](https://electriccoin.co/blog/turnstile-enforcement-against-counterfeiting)
