# Local private host RPC transport

Create a new short, owner-only private rehearsal following the [key setup](testnet-key-sponsor-runbook.md). Preserve all existing funded fixtures and original recovery records. Enable the private transport before its first validator launch:

```sh
python3 -B tools/rpc_isolation.py --root .data/new-host --hardened-host
```

This creates a new structured operator credential, permanent digest marker and network policy. Normal raw RPC selectors 18899/19899 and replay selectors 28899/29899 map to private Unix sockets in that root. The validator opens no raw HTTP TCP listener or WebSocket listener. Those numeric ports can be occupied by unrelated processes without receiving any operator traffic. Socket paths must fit the portable 104-byte limit and have canonical, owner-only parents. Keep the fixture at its original absolute path; relocating it requires a separately reviewed migration, not hand edits to the credential.

Use the existing [TLS runbook](tls-rpc-isolation-runbook.md) to initialize a new operator faucet with `--rpc-access-file` pointing at this structured credential. Keep the operator source profile on its logical `http://127.0.0.1:18899` selector. The faucet copies the complete transport material and persists its Unix requirement; gateway forwarding and native worker connections then use the same pinned Unix socket. Invited tester profiles contain HTTPS endpoints and public CA only. Never export operator credentials, paths, socket files or private TLS keys.

For restart, preserve the complete original network, marker, structured credential, faucet source, admission/claim journals, wallet pending records, towers and ledgers. Use the existing guarded prepare/coordinated-start helpers after stopping both validators. A stale socket left by SIGKILL is recovered under its lifetime lock; do not delete live socket/lock files or relax permissions. Missing/mismatched policy or unsafe paths must be repaired from their original complete files, with no TCP fallback or new value operation. Separate no-voting inspection routes also remain on Unix transport.

Repeatable acceptance creates a fresh network and evidence directory:

```sh
python3 -B tools/host_localnet.py --root .data/new-host-check \
  --evidence <new-private-evidence-directory>
```

The test holds malicious HTTP listeners on all four old raw/inspection ports, runs two actual validators, distributes two private/gas grants through verified HTTPS, withholds a finalized private payment reply, kills its client and both validators, then recovers the original payment and nullifiers after coordinated restart. It also repeats TLS-service SIGKILL, quota and revocation checks. The impostors must receive zero requests and no operator capability throughout. Private material is retained after a failure; do not rerun the complete funding ceremony on that root.

Unix permissions and peer UID checks require a dedicated OS service identity to exclude unrelated programs running under the desktop user's own UID. This local setup does not create that account, isolate the administrator, or deploy public peer/TPU networking. See [decision 0015](decisions/0015-private-host-rpc-transport.md) for the exact boundary.
