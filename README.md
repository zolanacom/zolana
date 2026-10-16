# Native private payments

Local development of protocol-native shielded payments for an independent Agave-derived network. The project name is undecided.

This repository starts from upstream Agave source and a new development history. Networking and consensus are retained while a separate payment module is evaluated. Public transfers remain supported in the minimal design; privacy is an additional native capability, not a claim about every transaction or application.

## Layout

- `protocol/payments/`: bounded payment validation and submission primitives.
- `clients/cli/`: local proof and payment development commands.
- `node/agave/`: upstream validator source with gated native-payment registration.
- `node/adapter/`: metered native execution, staging and real coin accounting.
- `node/validator-check/`: signed-transaction integration tests using Agave Bank.
- `docs/decisions/`: architecture and scope decisions.

See LOCAL-001 for the first implementation milestone and its validation record. The standalone verifier and real-proof offline fixture are implemented. Native runtime integration and coin accounting are implemented locally; see LOCAL-002 and [the integration design](docs/decisions/0003-native-validator-integration.md). Nothing in this repository has been deployed or connected to a production network.

## Run the local proof fixture

```
sh tools/dev.sh fetch --locked
sh tools/dev.sh run --offline --locked -p payment-lab -- proof-smoke
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked -p native-payment-program --test runtime
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked -p native-validator-check --test bank
sh tools/check.sh
```

This uses a project-local dependency cache and the installed Rust 1.92 toolchain. The fixture uses public synthetic test keys and creates no real funds. It verifies real proofs and authorization, stages/decodes the payment and confirms local decryption of payment and change. The proof-smoke command is not a wallet or an on-chain transfer. The separate runtime and Bank tests execute synthetic native payments. A live RPC validator network has not been launched; the pool is limited to 128 payments pending scalable storage.

## Attribution

Upstream attribution is preserved in [THIRD_PARTY.md](THIRD_PARTY.md) and vendored notices.
