# Run the local Zolana portal

The portal is a read-only companion to the blockchain and wallet. It starts no validators and has no spending keys, password fields, admission proofs, RPC transport or arbitrary-file routes. Python's standard library is sufficient. Start from the repository:

```sh
python3 -B tools/network_portal.py --port 8780
```

That mode displays an honest disconnected-history state. For recorded activity, explicitly select an owner-only public network profile and retained-history snapshot:

```sh
python3 -B tools/network_portal.py \
  --profile /private/tmp/reviewed-public-profile.json \
  --history /private/tmp/reviewed-public-history \
  --port 8780
```

The profile supplies the independently selected genesis and network domain. The archive root must be real, desktop-owned and private. Only the manifest's referenced immutable segments are opened. Every checksum, boundary and ancestry link is checked; malformed/mismatched inputs fail before listening. The index is capped at 100,000 blocks/transactions and 256 MiB of segment input. Responses contain summaries, hashes, signatures and public fees/execution status, without raw transaction data or logs. The selected snapshot is indexed at startup; Refresh queries that index. Restart explicitly to select a newer captured snapshot. This is not live RPC or canonical payment-status evidence.

Optional `--health /Library/NativePayLocal/health/heartbeat.json --health-owner 450 --health-genesis <SAME_GENESIS>` reads the existing public heartbeat. A missing/mismatched genesis binding is rejected. Unknown/stale/mismatched process observations cannot claim a running validator service. The UI labels finality as **last observed**, separate from the saved-history tip. No private service directory is opened.

Optional `--wallet-genesis <WALLET_GENESIS>` provides only a public identifier for the wallet handoff. A mismatch with the explorer is displayed by the portal. The portal does not unlock, replace or repin a wallet. Local test units are not assigned a new conversion or monetary value.

A retained archive holds only the native-payment subset of each block, so its counts are payment-subset counts, not complete full-block transaction counts. The feed adds finalized full-block metadata and may have a separate recent coverage window. Its genesis must match the independently selected public profile. Do not infer complete historical coverage or use the explorer as payment-recovery authority.

## Local finalized feed

With sealed service bundle v8 installed, add `--feed /Library/NativePayLocal/health/explorer.json --feed-owner 450`. Only this public service-owned file is read. Its parent must be mode 755 and owned by the selected service UID; its bounded regular file must be mode 644, have one link and pass exact schema/network/ancestry validation. The service exports no private RPC socket or credential. While running it captures up to 32 finalized blocks per sample, retains at most 2,048 blocks/2 MiB, rechecks its original last checkpoint on restart, and atomically publishes the projection. A gap beyond the bounded backfill limit requires explicit operator work.

The portal merges block identity and the retained payment subset against full blocks. A failed check preserves the last good index. Stale/unavailable feed data remains saved evidence. Source/coverage is explicit, public voting identities are last observations, and no independent finality proof is claimed. Visible-page activity refreshes every five seconds while details, expanded pagination and dialogs remain stable.

To run a wallet for the same network beside the portal, launch the wallet UI with `--network-profile` and its own `--data-dir`; `--previous-wallet-port` links to a separately running older wallet. Its `/api/network` exposes only the public label/genesis without a wallet-session token. An existing directory bound to a different profile is refused.

Stage and review `tools/explorer_service_acceptance.py` and the v8 service bundle before a batched administrator-authenticated run. The finite `run-explorer-test` controller verifies exact original state, observes the desktop portal, crashes/restarts the supervisor, and leaves the normal service unloaded and validators paused even on failure. Preserve failed evidence; its single guarded recheck accepts only the known paused desktop-observation timeout and preserves the previous session.

Routes:

| Surface | Behavior |
| --- | --- |
| `/#network` | Network overview and recorded activity |
| `/#explorer` | Blocks/transactions, bounded pagination and search |
| `/#explorer/<slot-or-hash-or-signature>` | Reloadable detail lookup |
| `/#validators` | Managed-service state, historical finality and identity availability |
| `/#build` | Actual native payment scope, ZOL and network identity |
| `/#status` | Description of the connected public feed and of the readiness evidence still needed |
| Open wallet | Link to the wallet page (`/wallet.html`), which this standalone server does not itself serve; network mismatch information is shown when `--wallet-genesis` differs |

The server binds only `127.0.0.1`, has eight bounded workers and socket deadlines, exact Host/origin checks, no CORS, CSP and a fixed static-file map. All POSTs are refused. No user-provided URL, shell command or RPC method is forwarded. HTTP is local development; external hosting/TLS and independent hosted operations need separate work.

Validation:

```sh
python3 -B -m unittest discover -s tools -p 'network_portal_test.py'
node --test clients/network-portal/*.test.mjs
```

No public testnet, stake directory, mainnet economics, DEX/private swaps, Solana bridge or independent security review is implied.
