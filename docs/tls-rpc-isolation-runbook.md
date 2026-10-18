# Local TLS and raw RPC isolation

Use a new private rehearsal following the [key setup runbook](testnet-key-sponsor-runbook.md). Preserve all existing fixtures, source seeds, budgets and pending journals. These commands create local files/listeners only, never public hosting, OS certificate trust or firewall rules.

For fresh hardened rehearsals, use the [private host transport](host-isolation-runbook.md) with `--hardened-host` to close raw TCP port impersonation. The original capability-only mode below remains for compatibility with existing fixtures.

Before starting either validator, install the durable raw-RPC policy:

```sh
python3 -B tools/rpc_isolation.py --root .data/new-private-rehearsal
```

The helper requires stopped raw RPC/WebSocket ports, creates an owner-only random capability and digest marker, and enables `raw_rpc_isolation` in that fixture's network metadata. Managed launches and no-voting replay inspections then require the credential on raw HTTP and disable raw WebSockets. A missing/mismatched/shared credential or partial policy restore blocks restart. Do not delete the marker, flag or key to repair a failure; restore the original complete operator files. Keep the capability out of URLs, logs, Git, profiles and tester packages. Trusted operator clients use `--rpc-access-file <private-file>` with their loopback fixture RPC; standalone tester profiles reject that option.

Create local certificates in a **new** private operator directory:

```sh
python3 -B tools/local_test_tls.py --directory .local/new-tls-private
```

No trust is installed globally. Keep `ca.key` offline and separate from the TLS services. Only the leaf certificate and its matching owner-only key enter service arguments. The generated CA lasts three days and normal leaves last two; this short-lived setup is for local development. Preserve the CA when renewing a leaf. Do not replace original wallet/admission data or funded raw credentials during certificate renewal.

Prepare a dedicated faucet with an operator source profile pointing directly at authenticated loopback raw RPC, with invitation mode omitted/false. Add its credential when creating that new faucet:

```sh
target/debug/native-faucet init --root .data/new-private-rehearsal/faucet \
  --profile operator-source-profile.json --password-file <private-password-file> \
  --max-claims 2 --rpc-access-file .data/new-private-rehearsal/rpc-access.key
```

Fund its fixed private/gas reservoir through the explicit original ceremony, supplying the operator RPC credential for that setup. It does not auto-refill. The faucet keeps its own owner-only credential copy and durable `operator_rpc` marker; missing source credentials never cause anonymous fallback. Operator sponsor/treasury material remains separate from runtime distribution.

The invited tester profile uses HTTPS for both endpoints, `invite_required: true` and the public CA PEM. Export the profile/package explicitly:

```sh
python3 -B tools/package_wallet.py --network .data/new-private-rehearsal/network.json \
  --label 'Local HTTPS rehearsal' --rpc https://127.0.0.1:18898 --transport https \
  --faucet https://127.0.0.1:8780 --invite-only \
  --local-tls-ca .local/new-tls-private/ca.crt --output <new-local-archive>
```

Complete the [invitation setup](invited-testnet-runbook.md) with that full HTTPS profile before accepting claims, then run:

```sh
python3 -B tools/test_faucet.py --root .data/new-private-rehearsal/faucet \
  --password-file <private-password-file> --port 8780 \
  --tls-cert .local/new-tls-private/server.crt --tls-key .local/new-tls-private/server.key
python3 -B tools/testnet_gateway.py --root .data/new-private-rehearsal/faucet \
  --password-file <private-password-file> --port 18898 \
  --tls-cert .local/new-tls-private/server.crt --tls-key .local/new-tls-private/server.key
```

Missing TLS arguments, missing/shared private keys or mismatched leaf/key material must fail before listener binding. HTTPS clients reject an untrusted CA, expired leaf or wrong IP SAN; never disable certificate verification to recover. The normal wallet opens on its device-local HTTP UI as before; its backend CLI makes verified HTTPS requests to the pinned services. No browser-wide trust change is needed.

For restart or certificate renewal, stop only owned services, retain the original CA/public profile, install a matching new valid leaf/key, and restart with the same faucet root and password. Recover pending transactions and upload rent using the original wallet records. Repeated invitations/claims, quota exhaustion and revocation remain durable across TLS restarts. Coordinated validator recovery uses the existing guarded prepare/start helpers and original towers/ledgers; raw authentication remains enabled during inspection and resumed serving.

Repeatable acceptance requires a new short root and private evidence directory:

```sh
python3 -B tools/tls_localnet.py --root .data/new-tls-check --evidence <new-private-evidence-directory>
```

It tests actual raw HTTP/REST/file denial, closed WebSockets, real Rust-client certificate rejection, direct HTTPS grants and a private payment whose finalized reply is deliberately withheld before client SIGKILL. It restarts both validators and TLS services with a renewed leaf, resolves the original payment/rent, and checks quota/revocation after service SIGKILL. It refuses existing roots and never automatically resubmits a failed value operation. See LOCAL-018 for the actual results. Public DNS/TLS, unprivileged service-user separation and external firewall/peer exposure remain deployment work.
