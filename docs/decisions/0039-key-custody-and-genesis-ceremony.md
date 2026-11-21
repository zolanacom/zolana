# Key custody on a public network, and a genesis ceremony: requirements and options

Status: design record, not a description of anything that exists. It states what key custody and a genesis ceremony must satisfy before Zolana runs a network that holds value or includes validators outside the project, and sets out the options where a choice is open. Nothing here is implemented, chosen or scheduled. The devnet is a test network with valueless coins, run entirely by the project (see the [README](../../README.md#status-and-limitations)); it does not meet these requirements and is not claimed to.

## Context

[Decision 0007](0007-testnet-keys-and-sponsor.md) separated key roles for a local rehearsal (treasury, payment sponsor, validator identity and voter, vote withdrawal and stake control each have their own key, and only identity and voter are plaintext on the validator) and listed what was still missing before any external network: real offline or hardware custody, compromised-key rotation, and selected parameters and operators. The [rehearsal runbook](../testnet-key-sponsor-runbook.md) describes that rehearsal and says of itself that it is "a custody rehearsal, not actual offline custody". [Decision 0005](0005-independent-privacy-l1.md) chose an independent chain, which means the project cannot borrow another network's validator set, treasury controls or upgrade process: each has to be designed here.

This record takes the next step on paper. It defines the roles, says which keys may exist where, describes how a genesis is produced so that nobody has to be trusted about its contents, and lists what a rehearsal has to show before a real ceremony is held. Requirements are numbered so that a ceremony script, a checklist and a review can refer to them.

Words used below. A **networked host** is any machine that has been connected to a network since its keys were generated, including a workstation and a build machine. A **cold** key has never existed on a networked host in usable form. A **hot** key is on a networked host because software has to sign with it unattended. A **custodian** is a named person who holds a cold key or a share of one. A **quorum** is the smallest set of custodians that can use a shared key.

## 1. Principles

- **P1. A validator host holds only what it must sign with unattended**: the node identity and the voting key. Anything that can move funds, change who may vote, change a commission, activate a protocol change or sign a release is somewhere else.
- **P2. No single person, machine or location can use a key that controls pooled funds or protocol changes.** A set of keys held by one organisation's staff on one organisation's machines is one custodian, however many keys there are.
- **P3. Every copy of a key is the key.** A backup of a host contains that host's keys. A password stored beside the ciphertext it protects protects nothing on that machine. A restored copy made for a test is a copy. Custody is a count of copies and of who can read each one, kept as a written inventory.
- **P4. The genesis is public and reproducible.** Its inputs are public keys and published numbers. No private key is an input to the tool that builds it, and the tool creates none.
- **P5. Every key has a written answer to two questions before it is created**: what is done when it is lost, and what is done when someone else has it.
- **P6. A stolen hot key must be survivable.** What it can do is bounded by design (balance, authority, lifetime), and the bound is stated.
- **P7. Procedures are proven by people other than their author, on a network built for the purpose, before they are used for real.**

## 2. Roles and separation of duties

| Role | Does | Must not |
| --- | --- | --- |
| Ceremony coordinator | Publishes the inputs, runs the script, keeps the transcript | Hold a share of any key generated in the ceremony |
| Custodian | Holds one cold key or one share; takes part in signing after checking what is signed on their own device | Hold a second share of the same key; prepare the transactions they approve alone |
| Witness | Observes generation and signing; signs the transcript; at least one is independent of the project | Handle secret material |
| Validator operator | Generates and holds every key of their own validator; runs the node | Give any private key to the project or to another operator |
| Treasury proposer | Prepares a spend and its written reason | Be the only approver; broadcast without the quorum's signatures |
| Release manager | Builds and proposes a release; publishes what is needed to reproduce it | Sign a release alone |
| Incident lead | Declares an incident, runs the procedures in section 9, publishes the notice | Be the only person able to do so |
| Record keeper | Keeps the key inventory, the role table and the log of every use of a cold key | Hold a share of a key whose use they record alone |

Requirements:

- **R1.** The role table (who holds which role and which public key) is public for every key that controls pooled funds, stake delegated by the project, protocol activation or releases. Custodians may be named by role and organisation where naming a person would endanger them; the number of distinct organisations is always public.
- **R2.** No person holds a quorum of any shared key, and no organisation does where the key's purpose is to limit that organisation.
- **R3.** The quorum for funds and the quorum for protocol changes are different sets, overlapping in fewer members than either quorum needs.
- **R4.** Every use of a cold key is logged before it happens (purpose, transaction or message digest, approvers) and the log is published after it.
- **R5.** A role can be handed over without moving a private key between people wherever the underlying authority can be re-pointed on chain; otherwise the key is replaced, not passed on.

## 3. Key classes and where each may live

| Key | Signs | Class | Held by | If stolen, the thief can | Bounded by |
| --- | --- | --- | --- | --- | --- |
| Node identity | Blocks and network messages; pays vote fees | Hot | Operator, on the validator | Impersonate the node, equivocate, spend the identity account's balance | A small fee balance; replacing the identity through the withdraw authority |
| Voting key (authorized voter, and any aggregate-signature voting key derived from or registered with it) | Votes | Hot | Operator, on the validator | Vote in the validator's name, including conflicting votes | Rotation by the withdraw authority; the validator's share of stake |
| Vote account address key | Creation of the vote account only | Cold, then destroyed or sealed | Operator | Nothing, provided it was never made an authority | R6 |
| Vote withdraw authority | Withdrawals from the vote account, commission, replacement of voter and identity | Cold | Operator | Take the vote account's balance and the validator's future commission; lock the operator out | Low standing balance; delegators can move stake away |
| Stake authority | Delegation and deactivation of a stake account | Cold | The delegator (for genesis and programme stake: a quorum) | Redirect or deactivate stake, changing who decides consensus | Activation and deactivation take effect only at epoch boundaries; lockups; R27 |
| Stake withdraw authority | Withdrawal of stake; replacement of both stake authorities | Cold | The delegator, separately from the stake authority | Take the stake | Lockup with a custodian key held by a different quorum |
| Treasury or reserve | Transfers of pooled funds | Cold, shared | A quorum of custodians in different organisations | Take everything the key controls | Section 6: threshold control, limits, an operating account |
| Operating account | Routine, pre-approved payments | Hot or warm | The project's operations role | Spend the float | The float is small, refilled only by the treasury quorum, and its size is public |
| Protocol activation (feature activation, and any program upgrade authority) | Turns on changed rules | Cold, shared | A quorum distinct from the treasury's (R3) | Activate rules the validators did not agree to run, if the code is already in their binaries | Section 7 |
| Release signing | Validator and wallet releases | Cold root, shared; a short-lived hot subkey only if builds require it | Release quorum | Publish malicious software under the project's name | Threshold signatures; reproducible builds; revocation (section 7) |
| Relay, sponsor and faucet signers | Service transactions | Hot | The service operator | Spend the service's balance | Finite, reserved allowances as in [decision 0007](0007-testnet-keys-and-sponsor.md); never a treasury authority |
| Service TLS keys and private certificate authorities | Channels between services and to users | Hot (leaf); offline (any authority key) | The service operator | Impersonate a service to its clients | Short lifetimes with automatic renewal; an authority key that is not on the host that uses its certificates |
| Backup encryption | Reads every backup | Recovery key cold; any automated backup password on the backed-up host only | Operator | Read every key that was ever on a backed-up host | P1 and P3: a validator host's backup then contains hot keys only |
| Administrative access (host logins, provider, DNS, package registries, source hosting) | Everything a host or an account can do | Personal, hardware-backed, with a second factor | Named administrators, at least two | Replace software, redirect users, read hot keys | No shared credentials; per-person keys; R9 |

Bridge keys are not covered. [Decision 0005](0005-independent-privacy-l1.md) requires a bridge to have its own design and review; its custody would be the most valuable key set of all and must not be folded into the treasury's.

Requirements:

- **R6.** A vote account's address key and a stake account's address key are never left as an authority of that account. Voter, withdraw, stake and stake-withdraw authorities are distinct keys from the first block.
- **R7.** These never exist on a networked host, at genesis or afterwards: vote withdraw authorities, stake and stake-withdraw authorities, treasury and reserve keys or shares, protocol-activation keys or shares, release-signing root keys or shares, any recovery key for backups, and every secret generated in the ceremony.
- **R8.** A validator host, and every backup made of it, contains exactly its identity and voting key and nothing else from the tables above. This is checked by a tool that lists key-shaped files on the host and in a restored backup, not by assertion.
- **R9.** Accounts that can change DNS, replace published software or reach a host console are held by at least two named administrators with hardware-backed second factors, and have a documented recovery path that does not depend on one person or one device. Certificate issuance for the project's names is restricted to the project's own issuing account where the certificate authority supports that.
- **R10.** Hot service keys are created on the host that uses them, are never copied to a workstation, and are replaced, not restored, when a host is rebuilt, unless the role is pinned on chain and replacing it is a recorded procedure.

## 4. Offline generation and the witness procedure

- **R11. Equipment.** Cold keys are generated either inside hardware that does not release the private key, or on a computer that has never been networked and is not networked afterwards, started from published, verified media. The choice and its exact versions and digests are part of the published inputs.
- **R12. Entropy.** Generation does not rest on one source. Where the equipment allows it, physical randomness supplied by the participants is mixed with the device's own.
- **R13. Witnessing.** Each generation is seen by the coordinator and at least two witnesses, one of them independent of the project. What they attest to is the procedure (the equipment, the media digests, that no network device was present, the public keys read back, the sealing of backups), never the secret.
- **R14. Proof of possession.** Every public key that enters the genesis or the role table arrives with a signature by that key over a statement that names the network, the role and the holder. For aggregate-signature voting keys this is a cryptographic requirement, not only a clerical one. A key whose proof fails is not used.
- **R15. Backups of cold keys** are made in the ceremony, as shares or sealed copies, each in tamper-evident packaging, each held in a different place by a different custodian, each listed in the inventory. A backup is verified to restore before the original is relied on.
- **R16. The transcript** records every step, every public key, every digest and every deviation. It is signed by the coordinator and the witnesses and published. Recording devices do not face secret material.
- **R17. An aborted ceremony is void.** Every key generated in it is destroyed and none is reused. Keys from any rehearsal are never used on a real network.

Options for holding a cold key:

| Option | For | Against |
| --- | --- | --- |
| Hardware signing device per custodian | The key does not leave the device; the custodian sees what is signed on the device's own screen | Device and firmware become trusted; the device must support the chain's transaction formats well enough to display them; supply and replacement must be planned |
| Never-networked computer with published software | Fully inspectable; no vendor dependence | The key exists as a file; procedure and physical security carry the whole weight; moving signed data in and out is a channel that has to be controlled |
| Hardware security module in a controlled facility | Strong access control and audit; suits high signing volume | Cost; concentrates custody in one facility and one vendor unless several are used; the least transparent to outside witnesses |

## 5. The genesis ceremony

A genesis fixes who can vote, who holds stake, what exists and under which rules. The ceremony's purpose is that anybody can check all of it afterwards without trusting those who were in the room.

- **R18. Published inputs before the ceremony.** The parameter set (supply, allocation, issuance, fees, rent, epoch length, minimum stake, lockups, any charge on validators), the allocation table with a named controller for every account, the software versions with source revisions and digests, the ceremony script, and the role table. The inputs are frozen and their digest announced before any key is generated.
- **R19. Operators generate their own keys.** Each validator operator generates identity, voting, vote-withdraw and stake keys on their own equipment under section 4 and submits public keys with proofs of possession. The project never sees an operator's private key.
- **R20. The genesis tool takes public inputs only.** It is deterministic: the same inputs give the same genesis and the same hash on any machine. It generates no key, writes no private file, and funds no account that is absent from the allocation table. A convenience account created by tooling, with a key nobody was assigned, is a defect that voids the genesis.
- **R21. Independent reproduction before launch.** At least two parties outside the project build the genesis from the published inputs with the published tool and obtain the same hash. Their statements are part of the transcript.
- **R22. Checks on the result, each performed by a tool whose output is published**: the total of all accounts equals the published supply; every funded account appears in the allocation table and has a controller with a valid proof of possession; no authority of any vote or stake account equals that account's own address (R6); no stake is controlled by a single key where the table says a quorum; the active protocol features are exactly the published list; no single operator, the project included, holds stake above the bound in R27.
- **R23. Publication.** The genesis, its hash and the signed transcript are published through channels that do not share an administrator. Wallet and validator releases carry the hash as a constant; a wallet does not learn which network it is on from the endpoint it is about to trust.
- **R24. Start.** Validators start from the published genesis with their own keys on their own hosts. The first finalized blocks are checked by observers who did not take part.
- **R25. No leftovers.** After the start, the ceremony's working media are destroyed or sealed under the inventory, and the check of R8 is run on every validator host that the project operates.

## 6. Splitting and rotating stake and vote authorities

- **R26. Split.** For every validator: identity, voting key and vote withdraw authority are three keys, the first two hot, the third cold. For every stake account: stake authority and stake-withdraw authority are separate cold keys, and for stake that the project or a foundation delegates to operators, both are quorum-controlled and locked up under a custodian key held by a different quorum.
- **R27. Concentration bound.** No operator, and no group under common control, the project included, holds or controls stake at or above the share that can halt finalization alone; the project's own share is set well below it, and the bound and the current distribution are published. A network that the project can finalize alone, or halt alone, is described publicly as exactly that.
- **R28. Rotation without downtime where the protocol allows it.** The voting key is replaced by the withdraw authority and the change takes effect at an epoch boundary; the identity is replaced through the withdraw authority; the withdraw authority and the stake authorities are replaced by themselves or by a quorum. Each of these has a written, rehearsed procedure that states the instruction used, when it takes effect and how the previous key is retired.
- **R29. No double signing during rotation or a host move.** A validator's signing state (its record of votes cast) moves with its keys, and two instances never run with the same identity or voting key. The procedure for moving a validator says which instance stops first and how that is confirmed before the other starts.
- **R30. Rotation triggers** are written down: a change of staff with access, a host rebuild or move, a suspected exposure, a failed inventory check, and a regular interval set in the operating policy. A rotation that has never been exercised is treated as not available.
- **R31. Operating costs do not depend on discretionary transfers.** If the protocol charges validators or requires a minimum balance to keep voting, a validator's income under the published parameters covers it, or the shortfall is funded by a rule that needs no key held by the project. A network whose validators stop when somebody forgets a payment has a custody problem, not only an operations problem.

## 7. Threshold control of the treasury and of upgrades

### Treasury

- **R32.** Pooled funds are controlled by k of n custodians in different organisations, with n large enough that the loss of n - k shares is survivable and k large enough that no single organisation reaches it.
- **R33.** The custodians sign only what they have each decoded and checked on their own device, against a proposal published beforehand.
- **R34.** Recurring payments come from an operating account with a small, public float. The treasury quorum meets to refill it, not for every payment.
- **R35.** The mechanism works within the chain's transaction-validity rules. If a transaction is valid only for a short span of blocks, there is a tested way to sign over a longer interval, such as a durable nonce, before any funds are placed under an offline quorum.

Options for the mechanism:

| Option | What it is | For | Against |
| --- | --- | --- | --- |
| A. Multisignature program on chain | Funds sit in an account that a program releases on k approvals | Approvals, signers and limits are visible on chain; signers can be replaced by the quorum; rate limits and delays can be enforced by code | Needs a program runtime that can host it, or a new built-in; the program becomes part of the audited surface and, if upgradeable, has its own authority to protect |
| B. Native multisignature account rule | The validator itself enforces k of n for designated accounts | No general program runtime needed; small, purpose-built | A consensus change; every validator must run it; needs its own review; less flexible afterwards |
| C. Threshold signature off chain | Custodians jointly produce one ordinary signature; the chain sees a single key | No change to the chain; works at genesis | Key generation and signing are interactive protocols whose implementations need review; the chain shows neither who signed nor the threshold; replacing a custodian means re-sharing or moving the funds; device support is limited |
| D. One key split into shares | The key is reassembled from k shares when used | Simple; widely understood | The whole key exists in one place at every use, so the room and the machine are trusted each time; suited at most to a rarely used recovery key, under witness |
| E. Less to control | Allocate at genesis into locked accounts with fixed rules, and fund recurring needs by protocol rules, so that little is left under any discretionary key | Removes risk instead of guarding it | Inflexible; mistakes in the rules need a protocol change; does not remove the need for one of A to D for what remains |

E is not an alternative to the others but a way to shrink what they protect, and should be applied first. Between A, B and C the choice depends on whether the network will host general programs at launch, which is undecided; C is the only one available without any change to the chain, and A or B the only ones in which the threshold is publicly verifiable. D alone does not meet P2 for funds in regular use.

### Upgrades

An upgrade here can mean three things: a new validator or wallet release, the activation of changed rules on the running network, and a change to a deployed program if the network hosts programs.

- **R36. Releases** are signed by a quorum, can be rebuilt from source by others to the same digest, and are verified by operators and wallets against keys obtained independently of the download. A lost or exposed release key is revoked through a path that does not depend on that key.
- **R37. Activation** of changed rules requires both a quorum decision and evidence that validators holding a stated supermajority of stake run software that implements them. Activation is announced before it takes effect, with enough notice for operators to refuse.
- **R38. No hidden switch.** If any key can halt the network, pause a program, freeze an account or alter balances outside the published rules, that fact is public, and the key is held under the same threshold rules as the treasury. If none exists, that is stated and checkable.
- **R39. Programs that hold other people's funds** are either immutable or have an upgrade authority held by a quorum with a public delay between proposal and effect.

Options for who decides activation:

| Option | For | Against |
| --- | --- | --- |
| Project quorum with published members | Fast; accountable; workable with few operators | The project controls the rules; operators can only refuse to run a release |
| Council that includes independent operators | Operators have a say before code ships | Needs agreements, and members who stay available |
| Stake-weighted signalling by validators, with a quorum able only to delay | Control follows the security assumption of the network | Stake concentration becomes control over rules; slower; needs tooling for signalling |

## 8. Bringing in independent operators

- **R40.** Before the first outside operator: a published join procedure that needs no private help, minimum hardware and bandwidth from measurement, software an operator can build and verify, and a standing test network on which the operator first runs.
- **R41.** The operator generates all keys (R19), keeps the withdraw authority cold, and proves possession. The project keeps no copy and no way to reconstruct one.
- **R42.** Stake delegated by the project or a foundation stays under the delegator's quorum (R26) and can be withdrawn from an operator without the operator's cooperation. The criteria for delegation and for its withdrawal are public.
- **R43.** Independence is stated and checked as far as it can be: a different organisation, hosting provider and administrative domain from the project and from other operators. Operators under common control count as one for R27.
- **R44.** Each operator has a named contact for incidents and has taken part in at least one coordinated restart on the test network.
- **R45.** Leaving is as defined as joining: how stake is deactivated, how the vote account is closed, what the operator must destroy and attest to.

## 9. Incidents: loss and compromise

A host that has been entered by someone unknown is treated as having leaked every key that was ever on it, including copies in its backups.

| Key | Lost | Compromised or suspected |
| --- | --- | --- |
| Identity | Create a new one and re-point the vote account with the withdraw authority | Stop the node; replace as for loss; check for conflicting blocks or votes signed in its name and publish what is found |
| Voting key | Authorize a new one with the withdraw authority; effective at the next epoch boundary | The same, immediately; the validator does not vote with the old key again; other operators are told at once |
| Vote withdraw authority | The vote account can no longer be administered: create a new vote account, move delegations, let the old one run out | Race: replace the authority from the cold key if still possible; otherwise treat the vote account as hostile and move delegations away |
| Stake authority or stake-withdraw authority | The other authority, or the lockup custodian where one exists, re-points it; if both are lost the stake is frozen for good | Re-point from the uncompromised authority at once; if both are compromised the stake is at the thief's disposal and the response is at network level (R27 limits the damage) |
| One treasury share | Re-share or move the funds to a new key set while a quorum still exists | The same, with urgency; the exposed share's holder is replaced |
| Treasury quorum | Funds are frozen for good | Funds are gone. What limits the damage is what was decided beforehand: the float, lockups, on-chain limits where the mechanism has them, and immediate public notice |
| Protocol-activation or release quorum | Replace through the documented recovery path; until then no upgrade is possible | Revoke; operators and wallets refuse the old key; publish digests of every legitimate release |
| Service signer | Replace; recover or write off its balance | Replace; its allowance bounds the loss |
| Administrative access | Recover through the second administrator | Remove the access, rotate everything it could read (P3), rebuild affected hosts from verified media |

Requirements:

- **R46.** Every row above exists as a written procedure with the exact instructions, and has been carried out in a rehearsal.
- **R47.** Each custodian shows at a regular interval, without exposing the key, that their share is still usable. A share that cannot be shown is treated as lost while a quorum still exists.
- **R48.** An incident that affects users' funds, the validator set or published software is disclosed publicly and promptly, with what is known, what is not, and what users and operators should do. Evidence is preserved before anything is repaired.
- **R49.** At least two people can declare an incident and start these procedures, and their contact details are known to every operator.

## 10. What a rehearsal must demonstrate before a real ceremony

A rehearsal runs the real script, with the real roles played by the people who will hold them or by stand-ins who have not seen it before, on a network created for the purpose and discarded afterwards. It passes only if every item is shown and recorded:

1. An outside party rebuilds the genesis from the published inputs and obtains the published hash (R20, R21).
2. Every check in R22 runs as a tool and passes; a deliberately defective input (an unlisted funded account, a self-authorized vote account, a bad proof of possession) is caught.
3. An inventory tool run on every validator host, and on a restore of each host's backup, finds the identity and voting key and nothing else (R8).
4. A treasury payment is made by the quorum with one custodian absent, is refused with one fewer than the quorum, and each custodian checks the transaction on their own device (R32, R33).
5. Offline signing completes inside the chain's validity rules, including when the signers are not together (R35).
6. Voting key, identity, vote withdraw authority and both stake authorities are each rotated on the running network without a halt and without two instances sharing a key (R28, R29).
7. A validator is restored on a new host from its backup and rejoins, with the cold keys untouched (R8, R29).
8. An operator who was not involved in writing the procedure joins from the published documents alone, receives a delegation, and later leaves (section 8).
9. A release is signed by the quorum, rebuilt by a second party to the same digest, and an unsigned or wrongly signed release is refused by operators' tooling; a rule change is activated under R37 and an activation without the required evidence is refused.
10. One share is declared lost and replaced; one hot key is declared compromised and rotated; one administrator's access is declared compromised and removed, each by the written procedure (R46).
11. The ceremony is aborted once on purpose and restarted, and nothing from the aborted run is reused (R17).
12. The transcript is complete enough that a reader who was not present can verify every public key, digest and check, and it is signed by the witnesses (R16).
13. The rehearsal's own keys are destroyed, and their public keys are published as never to be accepted.

A failed item is repaired in the script and the whole rehearsal is run again; items are not signed off one at a time across different runs.

## Not decided here

The parameter set; k and n and who the custodians are; which of the mechanisms in section 7 is used; the hardware; who decides activation; the criteria for delegating stake; the legal form of the body that holds reserve funds; and everything about bridge custody. Each of these is a decision for the project's owner, several of them after outside review, and none is implied by this record.

## What this record does not change

No code, no network and no key. The local rehearsal of [decision 0007](0007-testnet-keys-and-sponsor.md) remains what it says it is. The devnet remains a test network operated by the project with valueless coins, and nothing here describes how it is run.
