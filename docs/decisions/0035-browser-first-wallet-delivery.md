# Browser-first wallet delivery

**Update: after this decision, browser-local proving, encrypted vault recovery and shared native/browser replay were integrated in `clients/browser-core`, `clients/wallet-core` and `clients/browser-wallet`. Market demand, independent security and mainnet readiness remain unproven.**

Decision, 2026-10-22, after comparing delivery routes against the product goals. The intended production experience is chosen first and that same architecture is exercised on testnet, rather than creating a disposable testnet product.

## Goals and current state

Zolana remains an independent privacy L1 with native ZOL. The goal is fast private cash: a recipient verifies final execution and can spend the incoming note again within a few seconds, with locally held keys and private transaction construction. Solana users should be able to try it with minimal setup. Browser delivery does not itself create a reason for a new chain/coin or establish competitive superiority.

Current wallet HTML/JS calls a loopback-only Python helper, which pipes secrets to the device-local Rust wallet. It is not a standalone hosted web wallet. Uploading today's password-decrypting helper to our host would move secrets to that host and is not the selected route. Rust uses Orchard0.16/Orchard v2 and Halo2, local decryption/proving/signing, Unix files/locks and durable pending-payment recovery. Validator native execution already exists independently of client packaging.

## Decision

Select a **browser-local cryptographic client as the mainnet public delivery target**. The public entry point should be a website, with no required Python, Terminal, desktop app or new extension. Testnet must exercise that same client, key custody, proof path, recovery and onboarding architecture with test coins. Keep proving, decryption and authorization on the device. Keep the native implementation as the internal reference; preserve all existing wallets and formats. Defer further Apple distribution work. Do not build browser, extension and native consumer products in parallel.

An optionally installed extension, trusted-wallet integration, hardware signer or native app may later improve key isolation for users who want it. None is a mandatory mainnet replacement for the website. These are separate integrations with explicit support requirements, not existing capabilities or simultaneous build priorities. Choosing a hosted mainnet wallet requires accepting and mitigating its executable-delivery risks, not postponing them until after testnet. It is not an assertion that hosted hot wallets are the safest long-term vault.

| Route | Fits our goals | Cost or tradeoff | Priority |
| --- | --- | --- | --- |
| Website with local WASM | Link-based access; cross-platform desktop reach; private construction stays on device | Untested proving memory/time; browser storage/recovery; compromised web deployment can replace wallet code | Mainnet target; validate this same route on testnet |
| Bundled browser extension | Familiar desktop wallet experience; signer origin isolated from sites; packaged reviewed code | Same WASM port plus permissions, messaging, store review/update work; an install remains | Later for stronger signing separation |
| Native app | Reuses tested native proving/storage and predictable performance | Current external Python/Terminal and Mac-only limitations; packaging/signing for every OS | Keep reference; defer consumer packaging |
| Straightforward remote prover | Less device computation | Can disclose private witness details to operator; local seed alone does not solve this | Not the default privacy path |

## Fastest bounded next milestone

Use an isolated local test harness and fresh disposable identities. First prove one existing Zolana payment with the exact current Orchard version/authorization rules in a browser worker, then verify the output with the unchanged native/validator code. Use existing browser build patterns before creating new infrastructure.

[ChainSafe WebZjs](https://github.com/ChainSafe/WebZjs) already supplies WASM bindings, worker/thread startup and IndexedDB patterns; [ZCG's release announcement](https://forum.zcashcommunity.com/t/metamask-users-can-now-access-shielded-zec/51711) records browser-local proving. Its current wallet declares Orchard0.12 and implements Zcash-specific transactions/lightwalletd/PCZT/fees. Ours is0.16 with its own envelope, authorization, history and shielded fees. Reuse build/worker patterns; do not downgrade cryptography, adopt old circuit assumptions or import the whole incompatible wallet engine. Its old benchmark numbers are not ours.

Before committing to a full browser wallet:

1. Measure startup/download, memory, proof creation and decryption in real Chromium and Safari on the development Mac; name hardware/network and distinguish first use from warm use.
2. Validate current-network proof/wire equivalence with the native reference. No new chain or proof-system change is needed just to evaluate delivery.
3. Establish encrypted browser storage, backup restoration and durable pending operations. Terminate a tab/browser during submission, drop the connection and restart; reconcile the original payment and nullifiers without duplicate sends.
4. Measure actual Alice-to-Bob spend readiness and Bob-to-Charlie re-spending through the existing Linux host, including gateway/finality/history. Report samples/distributions; an optimistic pending state does not count. Under five seconds is the target, not a result of this decision.
5. Review gateway origin/CORS policy deliberately. Current direct browser Origin requests are refused; do not disable existing wallet-origin/session protections or expose raw RPC.

If this small slice cannot meet memory, recovery and latency requirements, retain the internal native reference and reopen the public architecture decision before a broad rewrite or privacy-weakening shortcut. Do not silently substitute a downloaded mainnet client or promise an arbitrary browser/device guarantee from the existing two warm native measurements.

## Security assessment

Browser local proving is modern and established, but WASM is not an isolated secret vault. A compromised first-party site can steal an unlocked seed or alter a recipient. No third-party scripts on the wallet origin, tight content policy and reviewed immutable assets reduce exposure without solving malicious first-party delivery. Mainnet needs an explicitly reviewed delivery/key-custody threat model, independent security acceptance, complete browser recovery, authenticated releases and operational readiness. Testnet validates the intended implementation; successful test-coin transfers do not establish safety for valuable funds.

Avoid asking newcomers to install executable software from a new chain merely to try a payment. A website lowers that visible trust/adoption barrier without eliminating software trust. Do not ask users to import their existing Solana recovery phrase into our site. Existing-wallet deposit authorization and private Zolana key management are distinct capabilities; generic Phantom connection is not a completed integration. SOL/USDC access also requires the separately planned bridge/asset work and must not be implied by this delivery decision.

Other privacy projects already offer browser-local proving, hosted web access or installed wallets. Neither local proving, browser access nor downloading an app is unique to this project. The chain still has to demonstrate useful privacy, shielded fees, reliable finalized spendability, decentralization/security and asset utility separately.

No browser implementation or new payment was performed for this decision. Apple enrollment/signing remains unperformed; the local Apple preparation code is retained and may be reused later.

## Custody clarification

The custody tradeoff is explicit: a self-custodial browser HOT WALLET, retaining first-party executable-delivery risk. Local proving is not isolation from malicious wallet code. No mandatory installed signer is silently substituted on mainnet. Native remains the reference; stronger installed/hardware custody is optional future work. Current RPC trust and member/IP linkage are disclosed, not solved by WASM. This is planning, not a new implementation or security/market acceptance.
