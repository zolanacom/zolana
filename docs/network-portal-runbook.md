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

Optional `--wallet-genesis <EXISTING_WALLET_GENESIS>` provides only a public identifier for the existing wallet handoff. A mismatch with the explorer is displayed before opening the separate device-local wallet at port 8765. The portal does not unlock, replace or repin a wallet. The established standalone wallet storage path retains its legacy name after Zolana branding. Local test units are not assigned a new conversion or monetary value.

The current local acceptance uses the public profile at `.local/service-wallet-acceptance-021/refreshed-profile.json` and the original-chain replica at `/private/tmp/native-history-replica-030-qr3okobj/final-downloaded-history`. It contains 7,101 recorded blocks and 120 transactions through slot 7,523. The heartbeat's last observed slot is 7,811; these are intentionally different coverage boundaries. The user's preserved `.data/l3` wallet remains on its older genesis. Do not substitute one network for the other.

Routes:

| Surface | Behavior |
| --- | --- |
| `/#network` | Network overview and recorded activity |
| `/#explorer` | Blocks/transactions, bounded pagination and search |
| `/#explorer/<slot-or-hash-or-signature>` | Reloadable detail lookup |
| `/#validators` | Managed-service state, historical finality and identity availability |
| `/#build` | Actual native payment scope, ZOL and network identity |
| Open wallet | Explicit handoff to the existing wallet, with network mismatch information |

The server binds only `127.0.0.1`, has eight bounded workers and socket deadlines, exact Host/origin checks, no CORS, CSP and a fixed static-file map. All POSTs are refused. No user-provided URL, shell command or RPC method is forwarded. HTTP is local development; external hosting/TLS/authenticated live explorer ingestion needs separate work.

Validation:

```sh
python3 -B -m unittest discover -s tools -p '*_test.py'
```

No public testnet, stake directory, mainnet economics, DEX/private swaps, Solana bridge or independent security review is implied.
