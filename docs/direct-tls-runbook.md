# Direct HTTPS pilot ingress

The default faucet/gateway listeners still bind loopback and require their exact loopback audiences. The opt-in direct TLS adapter separates the socket bind from the HTTPS audience already pinned by native admission and tester profiles. It is local-tested implementation, not an installed pilot, external reachability result or proxy adapter. Existing protected service/keys, profiles and user wallets are not modified.

Use **direct TLS termination** at the faucet/gateway process. The peer quota identity is the actual TCP/TLS socket IP. Forwarding/proxy IP and routing headers are rejected; a reverse proxy/CDN would collapse client identities and is not supported by this adapter. Do not put it behind one or expose a parallel bypass listener. Raw validator RPC remains the existing private Unix/operator transport; never expose that interface as the tester endpoint. IPv4 binds are currently supported; IPv6 and PROXY protocol are not.

## Review a separate listener configuration

Prepare one owner-only configuration per RPC/faucet endpoint, under the intended dedicated service identity. It contains exactly these fields (replace illustrative values with reviewed inputs; the shown hashes are not valid deployment credentials):

```json
{
  "format": "zolana-direct-tls-v1",
  "audience": "https://rpc.pilot.example:8443",
  "bind_ip": "0.0.0.0",
  "port": 8443,
  "certificate_sha256": "<SHA-256 of the exact certificate-chain file>",
  "key_sha256": "<SHA-256 of the exact private-key file>"
}
```

The audience must equal the native admission policy and wallet profile **byte for byte**, including explicit port spelling. It must be canonical lowercase HTTPS, without path, userinfo, query or fragment. A numeric IPv4 bind is independent of that audience. `0.0.0.0` is allowed only through this explicitly reviewed file; it is never inferred from a hostname or enabled by default. The audience port and bind port must match. Different public ports require the corresponding tester profile; no port rewrite is inferred. Review the complete configuration-file SHA-256 independently and pass it explicitly. Editing bind, audience, certificate or key requires reviewing a new digest; keeping the old command fails closed. Keep the TLS key/config owner-only and avoid symlinks. No OS trust store is changed.

The server loads the actual certificate/key pair before binding. Clients must verify hostname, chain and expiry against their selected trust roots. A pinned file hash alone does not establish certificate validity or external trust. For DNS audiences, the TLS SNI must match that exact hostname; missing/wrong SNI fails the handshake. IP audiences accept IP clients without SNI. HTTP Host must match the exact audience authority. Duplicate Host, Content-Length, Content-Type or access-proof headers, browser Origin, Transfer-Encoding and forwarding headers fail before admission/RPC work. The original bounded JSON/RPC method allowlist, native membership proofs, signed audience bindings and durable quotas remain authoritative.

## Launch after the separate deployment review

```sh
python3 -B tools/testnet_gateway.py \
  --root <reviewed-cohort-faucet> --password-file <private-password-file> \
  --port 8443 --tls-cert <reviewed-chain.pem> --tls-key <private-key.pem> \
  --listener-config <rpc-listener.json> --listener-sha256 <reviewed-file-digest> \
  --history <verified-retained-mirror> --archive-rpc <fixed-private-canonical-rpc>

python3 -B tools/test_faucet.py \
  --root <reviewed-cohort-faucet> --password-file <private-password-file> \
  --port 8444 --tls-cert <reviewed-chain.pem> --tls-key <private-key.pem> \
  --listener-config <faucet-listener.json> --listener-sha256 <reviewed-file-digest>
```

Both flags are required together; supplying either alone fails. An HTTPS audience always requires both TLS files and never falls back to HTTP. The default CLI behavior is unchanged. These entry points do **not** verify cohort funding, install a service, provision accounts/firewalls, create certificates or start validators. The faucet command starts its existing finite native grant worker; do not launch it against an unfunded or unreviewed pilot. A separate reviewed cohort/runtime binding with readiness, retention health, funding and service supervision is still needed before actual activation. This adapter does not supply those gates.

Restart the processes with the same original native root, listener file/digest and profiles. Admission, claim IDs, quotas, revocation and pending payment records stay in their original native journals. No restart code resets or replenishes them. Certificate rotation is an explicit reviewed configuration change and restart, not a trust downgrade or automatic fallback. Actual certificate renewal/supervision and firewall/external-device verification remain deployment responsibilities.

## Local acceptance

```sh
python3 -B -m unittest discover -s tools -p 'direct_tls_test.py'
RAYON_NUM_THREADS=2 nice -n 15 python3 -B tools/direct_tls_localnet.py \
  --root .data/new-direct-tls --evidence .local/new-direct-tls-evidence
```

The focused suite checks real DNS SNI independently from the loopback bind, authority/header attacks, TLS trust failures and native admission/edge-quota recovery across actual HTTPS-process SIGKILL. The bounded runner uses only fresh loopback ledgers and a private test CA, exercising native wallet grant/send/restore across gateway/faucet and validator crashes. No DNS override, external listener, trust-store change or protected service update is needed. It always cleans up its owned validators/processes. These checks do not demonstrate internet reachability, independent host placement, physical phone/Safari behavior, a Linux supervisor or production security review.
