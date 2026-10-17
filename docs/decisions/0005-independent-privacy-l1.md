# Independent privacy L1 and native coin

Decision: continue an independent Agave-derived privacy L1 with its own native asset. A Solana asset bridge is later work. Solana-mainnet settlement and a privacy application deployed on Solana are outside the current implementation scope.

The native asset pays transaction fees and is the stake/reward asset for the network's own validator consensus. Shielded deposits, private transfers and withdrawals operate on real native backing. No production supply, inflation, fee or rent schedule is chosen by this decision; the existing amounts are disposable development parameters.

The independent validator runtime lets the protocol directly authenticate shielded proofs and apply private payment state, native backing and permanent nullifier effects atomically. The current minimum design also supports transparent accounts and transfers; it does not make every application or all network metadata private.

A future bridge can connect supported Solana assets without changing where this L1 reaches consensus. Its asset custody, remote-state verification, replay protection, withdrawal rules and failure recovery require their own design and review. Bridging is not implemented and must not be described as inheriting Solana's settlement security.

Forking Agave is compatible with several architectures: independent L1s, custom execution networks and systems that commit state to another chain. Settlement is additional infrastructure rather than a consequence of copying the runtime. This project currently chooses independent finality, with wallet safety, load testing, archive availability, production parameters and independent review ahead of any public release.

Development remains local. No public testnet or mainnet deployment is authorized by this decision.
