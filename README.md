# Native private payments

Local development of protocol-native shielded payments for an independent Agave-derived network. The project name is undecided.

This repository starts from upstream Agave source and a new development history. Networking and consensus are retained while a separate payment module is evaluated. Public transfers remain supported in the minimal design; privacy is an additional native capability, not a claim about every transaction or application.

## Layout

- `protocol/payments/`: bounded payment validation and submission primitives.
- `clients/cli/`: local proof and payment development commands.
- `node/agave/`: preserved upstream validator source, with native integration tracked separately.
- `docs/decisions/`: architecture and scope decisions.

See LOCAL-001 for the first implementation milestone. Nothing in this repository has been deployed or connected to a production network.

## Attribution

Upstream attribution is preserved in [THIRD_PARTY.md](THIRD_PARTY.md) and vendored notices.
