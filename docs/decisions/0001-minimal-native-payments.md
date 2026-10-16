# 0001: Minimal native-payment capability

Status: accepted scope; cryptographic dependency feasibility pending.

Keep Agave networking, consensus, public accounts and existing transaction envelopes. Add a native built-in for a shielded native-coin domain. Validation must execute independently on every validator and commit its state through bank-hashed accounts.

Start with a maintained Orchard library as a candidate, a bounded bundle shape, staged proof data and publicly funded shared sponsors. The first milestone proves that validation checks the proof, spend signatures and binding signature, with network-separated authorization. It does not implement a validator, a complete wallet or a production protocol by itself.

The minimal version permits public transfers. General private smart contracts, private trading, production bridging, additional assets, fee reimbursement and mandatory privacy across all user payments are deferred. No private-payment or throughput claim is made before validator integration and measurements.

Use existing secure circuits unchanged. Pin the selected release, supported circuit and dependency graph after inspecting actual registry availability and advisories. Do not substitute a historical insecure circuit for convenience. Keep validator builds separate from the payment workspace until dependency compatibility is established.
