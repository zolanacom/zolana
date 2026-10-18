# Local invitation admission rehearsal

Keep raw validator RPC and gossip on operator-loopback. The gateway and faucet below are also loopback-only. The [local TLS/isolation runbook](tls-rpc-isolation-runbook.md) adds HTTPS and raw RPC capabilities. Public TLS, firewall routing, independent validator hosting and operational release review remain deployment work; no external hosting or invitations are created by this procedure.

Use a **new** pre-funded faucet root following the [test distribution runbook](test-faucet-runbook.md). Its source profile points directly to operator RPC, has `invite_required` omitted/false, and uses a dedicated reservoir seed. Never point the worker at its own invited gateway. Preserve that source profile and all original budgets/journals.

Create a second public tester profile with the same network/genesis and:

```json
{
  "rpc": {"transport": "loopback-http", "url": "http://127.0.0.1:18898"},
  "faucet": {"transport": "loopback-http", "url": "http://127.0.0.1:8780"},
  "invite_required": true
}
```

These are fields within the complete validated public profile, not a standalone profile. The packaging tool adds them with `--invite-only --rpc http://127.0.0.1:18898 --faucet http://127.0.0.1:8780 --transport loopback-http`. No codes, admission ledger, source seed or server executable enter the package.

Before any claim, enable admission:

```sh
target/debug/native-faucet access-init --root .data/new-invited-faucet \
  --profile invited-profile.json --daily-admissions 3 --rpc-limit 2000
```

Daily admissions must fit the original faucet lifetime capacity. This setup refuses an existing admission ledger or any existing claim. A partial setup is deliberately closed: preserve the original files for operator recovery, never delete its permanent marker or reinitialize a funded seed.

Issue a code to a **new owner-only output file**; stdout contains only its hashed identity and expiry:

```sh
target/debug/native-faucet invite-issue --root .data/new-invited-faucet \
  --output private-invitation.json --expires-in 86400
```

Use `--bind-fee <tester-fee-address>` when that wallet authority is known. Otherwise anyone holding the unused code can redeem it first. The output contains the code and must be kept out of logs, URLs, Git, screenshots and bug reports. This local-only task does not send invitations. Revocation uses the nonsecret `invite_id` returned at issuance:

```sh
target/debug/native-faucet invite-revoke --root .data/new-invited-faucet \
  --invite-id <hashed-invitation-id>
```

Start the worker/admission service and separate RPC gateway with the original owner-only source password file:

```sh
python3 -B tools/test_faucet.py --root .data/new-invited-faucet \
  --password-file <private-file> --port 8780
python3 -B tools/testnet_gateway.py --root .data/new-invited-faucet \
  --password-file <private-file> --port 18898
```

The gateway checks upstream genesis before listening. Raw validator RPC must remain inaccessible to testers outside the gateway. A client profile is a pin, not a firewall. In a remote deployment HTTPS termination, Host forwarding and socket-peer accounting require explicit validation: these loopback services intentionally ignore forwarded-IP headers. Do not assume the local tests prove public network isolation or protection against a distributed flood.

Wallet flow: create → save/confirm encrypted recovery → **Join testnet + get test coins** → fixed grant finalization → user-paid private sends. **Check existing access** recovers an admitted seed without a code. Receive, encrypted recovery and offline key restoration remain available before admission. Restoring does not recreate a grant or replenish budgets. The CLI offers `join --invitation-file <private-file>` and `access-status`; password input remains bounded stdin/private input. The invited `--check` handshake verifies genesis only; pool/history checks require unlocking an admitted wallet.

On crash, restart the same services and roots with the original ledgers, seed and pending/staging/outcome records. Redemption saved before a missing grant reservation is completed by the same wallet's retry. Codes cannot be redeemed for a second wallet. Revocation/expiry denies new protected RPC and claim operations; accepted grant obligations still recover normally. An exhausted minute/day limit waits for its actual next time boundary. Restarting, restoring a seed, reissuing a package or adding reservoir funds does not reset limits. If clocks move backwards, fix the operator clock and preserve state.

Repeatable fresh-root acceptance:

```sh
python3 -B tools/invite_localnet.py --root .data/new-invite-check \
  --evidence <new-private-evidence-directory> \
  --browser-script <temporary-playwright-script> \
  --playwright-module <cached-playwright-module>
```

This creates private rehearsal keys, funds one finite reservoir, disables operator sponsor material after setup, uses two real validators, races code redemption, tests rejection/quotas/revocation and service/validator recovery, then verifies actual browser admission and a native private send. It refuses existing roots unless one of the explicitly named narrow failed-checkpoint guards validates the original state; completed evidence cannot be resumed. It never automatically repeats a failed value operation. Evidence and original journals are preserved even on failure. See LOCAL-017 for the accepted run and limits.
