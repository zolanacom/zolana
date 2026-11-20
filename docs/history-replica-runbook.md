# Independently replicated recovery history

Use a separately operated receiver host and storage before inviting external testers. The commands below are finite loopback rehearsals; nothing is deployed or exposed remotely. They transfer public chain ciphertext history, not operator or wallet backups. Keep canonical archival RPC for old unknown payment outcomes.

Create a new owner-only operator directory and initialize a new receiver root plus a dedicated sender credential. Initialization refuses existing paths, including interrupted setup; preserve evidence rather than reinitializing a partially created root. The network file must pin the original network/genesis.

```sh
mkdir -m 700 .local/replica-operator
python3 -B tools/history_replica.py init \
  --root .local/replica-operator/receiver --network .data/<network>/network.json \
  --credential-out .local/replica-operator/sender.key
```

Use isolated local test certificates, never install their CA into system trust:

```sh
python3 -B tools/local_test_tls.py --directory .local/replica-operator/tls
chmod 600 .local/replica-operator/tls/ca.crt
python3 -B tools/history_replica.py serve \
  --root .local/replica-operator/receiver --port 27980 \
  --cert .local/replica-operator/tls/server.crt --key .local/replica-operator/tls/server.key \
  --duration 600
```

The listener is TLS-only on `127.0.0.1`; its certificate and Host must match the pinned origin. A future separate-host/private-tunnel deployment must preserve this end-to-end authority and use reviewed long-lived service management/certificates. These short-lived development certificates and finite commands are not a hosted testnet configuration.

Push a captured verified source mirror, with no wallet or raw RPC credential:

```sh
python3 -B tools/history_replica.py push \
  --network .data/<network>/network.json --source .data/<network>/recovery-history-mirror \
  --url https://127.0.0.1:27980 --credential-file .local/replica-operator/sender.key \
  --ca-file .local/replica-operator/tls/ca.crt
```

A successful receipt identifies the exact durably committed manifest hash, retained slot, segment count and bytes. Retry the same source after interruption or a missing reply. Never clear receiver directories, edit descriptors, replace immutable payloads or reset the network to force a retry. A corrupt/different existing file fails closed. Keep the previous committed directory and all failed evidence for operator recovery.

To require replication automatically, provision the collector's private network root with:

```json
{
  "format": "native-history-replication-v1",
  "url": "https://127.0.0.1:27980",
  "ca_sha256": "<SHA-256 of the dedicated CA PEM file>"
}
```

Save this as `history-replica.json`, with the history-only credential in `history-replica.key` and exact pinned CA PEM in `history-replica-ca.crt`. All three files must be owned by the collector identity and mode 0600. Configure while paused. Do not use wallet, faucet, sponsor or raw RPC credentials. The collector durably creates `history-replica-required.json`; the requirement survives restart and missing configuration fails closed. The supervisor pauses validators and ingress if a required durable replica cannot be verified. Restore receiver connectivity/storage/pins and restart the same original service; do not remove the marker to open ingress.

Recover committed history with the source host unavailable:

```sh
python3 -B tools/history_replica.py fetch \
  --network .data/<network>/network.json --destination .local/replica-operator/restored-history \
  --url https://127.0.0.1:27980 --credential-file .local/replica-operator/sender.key \
  --ca-file .local/replica-operator/tls/ca.crt
```

Use one operator per download destination. The download directory and sibling `-download` staging directory must remain owner-only. The destination publishes a complete verified manifest last and refuses a rollback or changed immutable prefix. Keep these directories after failure. A restored wallet must still verify this history against a trusted current RPC, including finalized pool and nullifiers. Missing history or a rehashed payment omission must fail rather than return a partial balance.

The v6 sealed service bundle includes the replica runtime and verifies upgrades from v1–v5 while preserving private state and an intentionally paused job. Preparing a bundle does not start validators or configure any remote receiver. A local acceptance's temporary replica policy is removed only to restore its recorded pre-test absence after cleanup; the history and private evidence remain intact.

Repeat the actual process-crash transport test against a preserved, validated archive containing at least four immutable segments:

```sh
nice -n 15 python3 -B tools/history_replica_acceptance.py run \
  --fixture .data/<validated-archive-fixture> --root .local/replica-operator/new-transport-check
```

Repeat new real-payment/snapshot-peer acceptance, with no existing validator processes:

```sh
RAYON_NUM_THREADS=2 nice -n 15 python3 -B tools/replica_localnet.py \
  --root .data/<new-short-name> --replica-root .local/replica-operator/new-live-check
```

This has a ten-minute limit and stops owned validators/receiver on success or failure. It tests real required-receiver outage/restart, fresh-seed recovery with both source history stores unavailable, recovered-witness spending, second seed restoration, exact pool/nullifiers, canonical pending-payment safety and damaged/rehashed history rejection. It never operates the original protected wallet/ledger root.

Actual off-host placement, alert delivery, storage/certificate operations, broader adversarial testing and independent review remain deployment work. History replication alone is not a backup of the entire chain.
