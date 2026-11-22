# Wallet trust in chain reads: network pin, endpoint agreement, certificate verification

Status: section 1 is a decision and is implemented for the browser wallet. Sections 2 and 3 are design records: they state options, requirements and open questions. Nothing in them is built, chosen or scheduled, and neither describes a property the wallet has today.

## Context

The browser wallet checks a great deal on the device: transaction signatures, payment proofs, the continuity of the block headers it is given, and that replaying the payments it was given reproduces the pool account it was given ([`clients/browser-core/src/session.rs`](../../clients/browser-core/src/session.rs)). All of it is checked relative to data that one gateway supplies. The first line of that file says so: "RPC consensus is trusted". The [README](../../README.md#status-and-limitations) says the same: wallets "are not light clients and do not verify consensus independently".

Three things were trusted without any check:

1. **Which network this is.** The page fetched `/wallet-config.json` from the gateway and the worker used the network identifier and genesis hash in it as the reference for every later comparison. The gateway produces that document from its own profile (`config()` in [`tools/browser_gateway.py`](../../tools/browser_gateway.py)). The wallet compared the gateway's later answers with the gateway's first answer.
2. **Where history starts.** A first sync starts with no previous block hash (`begin_sync` with an empty checkpoint), so the first block applied is not tied to anything the wallet already holds.
3. **Where history ends.** The target slot, its block hash and the pool account all come from the same gateway, and `finish_sync` succeeds when the supplied history reaches that supplied target.

A gateway that lies, or is compromised, can therefore show a wallet a payment that never happened or hide one that did. This record takes the first step against item 1 and sets out what the next two steps would need.

The packaged desktop wallet already carries its network with it: its package contains the wallet profile (`wallet-profile.json`, written by `tools/package_wallet.py`), and the [invited testnet runbook](../invited-testnet-runbook.md) calls that profile "a pin, not a firewall". The browser wallet had no equivalent; section 1 gives it one, built from the same profile.

## 1. Decision: the network identity is part of the wallet build

A browser wallet bundle is built for exactly one network. The bundle contains a module, `network-pin.js`, that states the 32-byte network identifier, the genesis hash and the environment (`testnet` or `mainnet`). The worker loads it as part of its own code and treats it as the only source of the network identity. What the site serves at run time is compared with the pin and never used in its place.

### How the pin is supplied

The pin is a build input, not a constant in the source tree. [`tools/browser_wallet_pin.py`](../../tools/browser_wallet_pin.py) reads the public wallet profile of a network (`native-wallet-profile-v1`, the same file a gateway is started with), checks it against a stated SHA-256, and writes `network-pin.js` into the bundle directory. With `--assets-manifest` it also lists the module in the bundle's asset manifest and prints the manifest's new digest, which is the digest a gateway is started with.

```sh
python3 -B tools/browser_wallet_pin.py \
  --profile <public-profile.json> --profile-sha256 <digest> \
  --environment testnet \
  --assets-root <bundle directory> --assets-manifest <assets.json>
```

A devnet bundle is stamped with the devnet profile. A local rehearsal stamps its bundle with the profile of its own local network, whose genesis hash is new each time. No network's genesis hash is written in this repository; the tool reads none from a network and takes whatever the supplied profile states.

### What is refused, and when

| Moment | Check | On failure |
| --- | --- | --- |
| Worker start | The bundle has a valid pin | `network_pin`: no wallet is opened or created |
| Worker start | The served configuration names the pinned network and environment | `network_mismatch`: the wallet catalog is not opened, so nothing is read from or written to browser storage |
| First use of the gateway | The served transport description names the pinned network | `network_mismatch`: no RPC request is made |
| First use of the gateway | `getGenesisHash`, sent without the wallet's access proof, returns the pinned genesis hash | `genesis`: no signed request, invitation or sync is attempted |
| Every sync | The sync snapshot's genesis hash and network are the pinned ones (or, on the older path, `getGenesisHash` again) | `genesis`: the wallet core is not started and no checkpoint is written |

The user sees one sentence in each case: the site serves a different network than the one this wallet build is pinned to, and nothing was changed. The gateway makes the matching check when it starts: a bundle whose pin differs from the gateway's profile is not served ([`tools/browser_gateway.py`](../../tools/browser_gateway.py)). A bundle with no pin is still served, because its worker predates the pin; the new worker refuses to run without one.

### What the pin does and does not give

It gives a wallet an identity that does not depend on who answers. A gateway started with the wrong profile, an upstream node swapped for one on another network, or a bundle copied to a deployment for another network is refused before any wallet data is touched. It is also the fixed point that sections 2 and 3 need: several endpoints can only be compared, and a validator set can only be authenticated, against something the wallet holds before it asks.

It does not verify history. `getGenesisHash` is a statement by the gateway. A gateway that reports the pinned hash can still serve an invented history; the checks in the context section are unchanged.

It does not protect against replaced wallet code. Today the gateway that answers RPC also serves the bundle. Whoever can change the served code can change the pin with it. The pin becomes independent of the gateway only when the bundle is authenticated separately from it. [Decision 0035](0035-browser-first-wallet-delivery.md) records that delivery risk; this record does not reduce it.

One gap named in the context remains open. The pin is compared with what the gateway says its genesis hash is; it is not derived from the blocks. A first sync still starts with no previous block hash. Pinning the hash of the first block as well would let the wallet core check the first link, at the cost of a second build parameter and a change to the core's `begin_sync`. It would be a consistency check and not a proof, because the wallet does not recompute block hashes from block contents.

### Existing wallets

No storage format changes. The identifiers under which a wallet is saved (the catalog key and the database name) are derived from the network identifier and genesis hash, and the worker derives them from the pin exactly as it derived them from the served configuration. A wallet saved before this change opens as before, with the same password and state, when the new bundle is pinned to the network that wallet was saved on. A test fixes the derivation.

If a bundle were pinned to a different network than the one a saved wallet belongs to, that wallet would not be listed: the page would offer to create or restore one for the pinned network. The earlier wallet's data stays in browser storage under its own network's key and is not deleted, migrated or overwritten. Its recovery file remains bound to its original network and is refused on restore under any other.

The pin adds one small unsigned request (`getGenesisHash`) the first time a worker uses the gateway. Its cost on a slow connection was not measured.

## 2. Design record: agreement between several endpoints

The aim is the one stated in the README's limits: a wallet should not have to believe a single operator about finalized history. The proposal is that the wallet reads from one endpoint as now, asks other endpoints the questions below, and refuses to advance when the answers differ.

Agreement between endpoints is not a light client. It replaces "one operator is honest" with "the listed operators do not all lie in the same way". It has value only if the endpoints are operated independently: different operators, different hosts, each reading its own validator's ledger rather than forwarding another's answer. Every validator of the devnet is currently run by the project, on one host (README), so no arrangement of endpoints would give this property today.

### What is compared

| Item | Compared how | What it catches | What it needs |
| --- | --- | --- | --- |
| Genesis hash | Each endpoint against the pin, not against each other | An endpoint on another network | Exists (section 1) |
| Finalized target | The first endpoint names the target slot. Every other endpoint is asked for that slot's header at finalized commitment: block hash, previous block hash, parent slot and block height must be identical | Two different finalized chains; an endpoint that invents a tip | A header read that other endpoints will answer for this wallet |
| Saved checkpoint | The same header comparison at the wallet's saved slot | A chain that diverged before the wallet's last sync | The same |
| History content | A digest over the range from the saved slot to the target: for each block its slot, hash and parent, and for each payment transaction its signature and execution result. The wallet computes it from what it replayed; each other endpoint computes it from its own ledger | An invented payment, or an omitted one, inside blocks whose headers are genuine | A new gateway method, specified exactly so that independent implementations agree |
| Pool account at the target | Not compared directly: an endpoint answers account reads at its own current slot, not at a named past slot | | Follows from agreed history: the wallet already requires that replaying the history reproduces the pool account. Otherwise a new read of the pool as of a named slot |

The history digest is the item that matters most and the only one that needs new server code. The wallet checks that headers link to each other, but it does not check that a block's transactions hash to that block's hash. Endpoints that agree on headers therefore say nothing about the payments inside the blocks. Comparing headers alone would catch a forked or invented chain and would not catch the failure named in the context: a payment that never happened.

### What happens when endpoints do not agree

Two cases must be kept apart.

**No answer.** An endpoint is unreachable, rate-limits the wallet, or has not finalized the target slot yet. This is not disagreement. The wallet waits within a bound and asks again. If the required number of answers does not arrive, the sync ends without a new checkpoint, exactly as a failed sync does now: the last saved checkpoint and any pending payment stay as they were, and the wallet says it could not confirm the network's state.

**A different answer.** Two endpoints report different finalized data for the same slot. On an honest network this cannot happen, so it is never treated as a transient fault and never settled by a silent majority vote. Requirements:

- No checkpoint is written. The last agreed checkpoint stays.
- Sending is off, and no balance later than the last agreed checkpoint is shown.
- A pending payment whose outcome is unknown stays pending. The existing rule holds: the original packet is never replaced or sent again.
- Automatic checks stop until the user acts.
- The user is told that the endpoints disagree about finalized history, at which slot, and that this needs the operators' attention. The two conflicting headers are kept so that they can be reported; they are public data.

### Open choices

- **Agreement rule.** All listed endpoints must agree, or a stated number of them. With all-must-agree, a false result needs every listed operator to lie alike, and any one of them can stop wallets from syncing. With m of n, n − m endpoints may be down, and m colluding operators can deceive. The rule and the list belong in the build next to the pin.
- **Whether a halt persists.** A halt that clears on the next attempt lets a wallet resume as soon as answers agree again. A halt that persists until the user acknowledges it is safer, since finalized history should never conflict, but it needs a record in wallet storage. That is a storage addition and must be designed and reviewed on its own; this record does not make it.
- **Who is asked what.** Every additional operator that receives a signed request learns what the first one learns: the wallet's membership identity, its address on the network and when it is active (README, "The gateway operator can link activity"). Comparison reads that carry no wallet identity, as `getGenesisHash` already does, would tell other operators only that some client at an address asked about a slot. That requires those reads to be open and rate-limited on each gateway, which is an operator's decision.

### What the browser needs

- The page's content policy allows connections to its own origin only (`connect-src 'self'` in `tools/browser_gateway.py`), and the gateway refuses requests from other origins. Other endpoints need to be listed in the policy and need to accept cross-origin reads from the wallet's origin for the comparison methods.
- Access to an invited network is granted per gateway. Either each endpoint admits the wallet, or the comparison reads need no admission.
- The endpoint list has to be delivered the way the pin is: as part of the bundle, not by any endpoint.
- The comparison roughly doubles the small reads of a sync and adds one digest request per endpoint. A digest over a first sync covers every block since genesis; whether endpoints can compute it at that length within a request has to be measured, and it interacts with any later change to how far back a first sync reaches.

## 3. Feasibility note: verifying finality certificates in the browser

This note asks what it would take for the wallet to check finality itself instead of believing an endpoint's `finalized`. It is based on reading the consensus code of Agave 4.3.2 at the commit named in the [candidate's README](../../node/candidate/README.md); file names below are in that source tree. Nothing here was built or run, and the candidate's patches were not checked line by line for changes to these structures (a search of them finds none).

### What a certificate is

Validators vote with BLS signatures on BLS12-381, public keys in G1 and signatures in G2, under the ciphersuite tag `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. A certificate is one aggregate signature plus a bitmap saying which validators, by rank, are in it (`votor-messages/src/certificate.rs`). A block is final in one of two ways (`votor-messages/src/finalized_slot.rs`, thresholds in `certificate.rs`):

- **fast**: one certificate over the block (slot and block identifier) carrying at least 80% of stake;
- **slow**: a notarization certificate over the block and a finalization certificate over its slot, each carrying at least 60%.

The signed message includes the cluster's shred version (`votor-messages/src/wire.rs`), so a verifier must know it. A block's footer can carry the producer's highest known finalization proof for an earlier block (`BlockFooterV1.block_final_cert` in `entry/src/block_component.rs`), so proofs are in the ledger. The RPC interface has a method for the certificate of the consensus changeover (`getAgGenesisCert`) and, as far as was found, none that returns the finalization proof of an arbitrary block.

### Sizes

These are sums of field sizes from the structures, with *n* the number of validators in the epoch's rank list (at most 2,000, `MAX_ALPENGLOW_VOTE_ACCOUNTS`). They were not measured from a ledger.

| Object | Size | n = 4 | n = 100 | n = 2,000 |
| --- | --- | --- | --- | --- |
| Aggregate signature, compressed | 96 bytes | | | |
| Signer bitmap | 3 bytes + n/8 | 4 B | 16 B | 253 B |
| Fast finalization proof (slot, block identifier, one aggregate) | about 142 bytes + n/8 | about 143 B | about 155 B | about 392 B |
| Slow finalization proof (two aggregates) | about 243 bytes + n/4 | about 245 B | about 269 B | about 743 B |
| Validator list for an epoch: public key (48 bytes compressed) and stake (8 bytes) each | 56 bytes × n | 224 B | 5.6 kB | 112 kB |

The proofs are small. One per sync is negligible next to the history the wallet already downloads.

### Cost of one verification

- Decode the bitmap; add up the public keys of the signers (one G1 addition each) and their stakes; compare the stake with the threshold.
- Decompress the aggregate signature and check it is in the right subgroup.
- Hash the vote message to G2.
- One pairing check: two Miller loops and one final exponentiation. The slow path is two such checks.

Once per validator list: decompress and subgroup-check every public key. Aggregation is only sound if each key's owner has proved possession of it. The runtime carries keys as "proof-of-possession verified" (`runtime/src/epoch_stakes.rs`), so a wallet either relies on an authenticated list having been admitted under that rule, or fetches and checks n proofs itself (96 bytes and one more pairing check each).

No time is stated here because none was measured. The validator uses `blst`, which is C and assembly, through `solana-bls-signatures`. Whether that builds for the wallet's Wasm target with the pinned toolchain, or a pure-Rust pairing library has to be used and shown to produce identical results for this ciphersuite, is unknown. The count of operations per sync is small and fixed, which is the reason to think the cost is acceptable; the measurement has to confirm it on the slowest supported device.

### What the wallet would have to hold

1. **The pin** (section 1).
2. **The shred version** of the network: a second pinned value, or one derived from genesis.
3. **A validator list it can trust for the epoch of the certificate**: rank order, public keys, stakes, total stake.
4. **A way from that list to the next epoch's list.**
5. **A way from the certified block identifier to the data the wallet acts on.**

Items 3 to 5 are where the work is. The signature check is the easy part.

- **First list.** The genesis hash is the hash of the genesis configuration, and on a network that runs this consensus from its first block the initial vote accounts, with their BLS keys and stakes, are in that configuration. A wallet that downloads the configuration and hashes it against the pin would hold an authenticated first list. The size of that file and the exact derivation of the list from it have to be confirmed.
- **Later lists.** The list changes at epoch boundaries from stake and vote account state. The state commitment in a block (the bank hash, `hash_internal_state` in `runtime/src/bank.rs`) covers the parent's hash, a signature count, the last block hash and a lattice hash of all accounts. A lattice hash is not a Merkle tree: there is no short proof that one account has one value. So the next list cannot be proved from a certified block with what the protocol provides now. The options are a protocol addition that commits each epoch's list in a block (final under the previous list's certificate), a list shipped with each wallet release (which moves the trust to the release and limits how long a build stays usable), or accepting the list from endpoints under section 2's agreement.
- **From certificate to payments.** A certificate covers a slot and a block identifier. The identifier is a Merkle root over the block's shreds (`DoubleMerkleMeta` in `ledger/src/blockstore_meta.rs`), not the block hash that JSON-RPC returns and not a hash of the transaction list. To tie the transactions it replays to a certified identifier, the wallet needs either the block's shreds, from which it recomputes the root, or Merkle proofs for the shreds that hold the footer and the payment transactions. No gateway method serves either. The footer contains the bank hash, which covers the block hash, so header continuity could be anchored this way; the payments inside a block could not without the shreds.
- **How many certificates.** One certificate finalizes a block and all its ancestors. A sync would verify one for its target and then needs the ancestry from the blocks it replays to that target, through each block's parent identifier (`BlockHeaderV1`). For a first sync from genesis that is one proof of ancestry per block, which is the same growth problem as first sync itself and would be solved, if at all, by authenticated checkpoints.

### Questions to answer before deciding

1. Does a BLS12-381 verifier matching the validator's results build for the wallet's Wasm target, and how long do one pairing check and one list preparation take in the supported browsers?
2. How large is the genesis configuration, and does hashing it in the wallet reproduce the pinned genesis hash and yield the first validator list?
3. Which gateway methods would be needed to serve a finalization proof for a slot, the footer of a block with its Merkle proof, and the shreds or proofs for payment transactions; how large are those answers for an ordinary block?
4. Is a protocol change to commit each epoch's validator list acceptable for this network, and what does it cost in block space?
5. Is the result worth more than section 2 while every validator is run by one operator? A certificate proves that the listed stake signed. If one party holds that stake, the wallet learns what it learns from that party's endpoint.

## Decisions that are not engineering's to take

- Whether a gateway should refuse to serve a bundle that has no pin, once every served bundle is stamped.
- Whether the public devnet's genesis hash is published in this repository, or stays a value supplied when a bundle is built.
- The agreement rule for section 2, the operators whose endpoints are listed, and whether a disagreement halt persists.
- Whether gateways open identity-free comparison reads to clients that are not their members.
- Whether to study certificate verification further before independently operated validators exist.
