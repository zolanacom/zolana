# Local macOS service identity

The installer creates a new no-login `_nativepay` account/group, a root-owned `/Library/NativePayLocal` runtime and `/Library/LaunchDaemons/local.nativepay.validator.plist`. Private state is owned by the service account under the installed `.data` directory, mode 0700. The service uses separate loopback ports and does not stop or replace the demo wallet at 8765. The original demo remains on its original disposable network.

Prepare a new local, secret-free bundle:

```sh
python3 -B tools/service_account.py prepare --output .local/new-service-bundle
```

Review its exact manifest and digest, the account, paths and launchd configuration before administrator execution. The root bootstrap must pin both the installer bytes and manifest digest, run system Python in isolated mode, and pass the reviewed desktop UID. It must not execute an unverified user-writable installer or alter sudoers. Administrator authentication belongs in the macOS prompt; never send the administrator password through chat, files or command arguments.

The sealed administrator command supports `install`, `update`, `test` and `verify`. Install refuses existing service account/group names, installation paths and launchd plists. It generates keys only as the unprivileged service identity, then launches the fixed daemon. A partial setup is retained for explicit recovery; rerunning initialization or deleting state is not a repair path.

An update requires a new reviewed bundle and both bootstrap digests, just like installation. The administrator bootstrap verifies the pinned new installer before invoking its `update` action. Update verifies the existing seal, stops a loaded launchd group, replaces only changed manifest-listed code, verifies the new seal and restores its original loaded/paused state. Failed verification restores the previous code and manifest. It never changes `.data`, `SERVICE.json`, account membership or the launchd plist. Keep this operation supervised: an abrupt interruption during code replacement requires explicit seal repair before restart, retaining all private state.

The v2 inventory added the isolated wallet gateway, faucet binary and TLS setup module. V3 added automatic verified history retention and a captured-manifest local mirror. V4 added the separate authenticated retained-history gateway reader and updated wallet/cache provenance. V5 added canonical archival RPC for old pending outcomes. V6 added the independent TLS history-replica helper. Current v7 adds sanitized health publication and the separate read-only operator observer. Its updater also provisions the service-owned 0755 public `health` directory outside `.data`; a failed update removes a newly created empty health directory along with new code and restores the original manifest. Existing unsafe directories are rejected. Private data, service identity and raw Unix RPC restrictions remain unchanged.

The updater recognizes exact v1–v6 inventories for migration and preserves whether the daemon was loaded: an intentionally paused service stays paused. Initial verified collection precedes ingress; later verification/lag/capacity failure parks ingress and validators. See the [retention runbook](recovery-history-runbook.md) for bounds, status and interrupted-copy recovery, and the [operator health runbook](operator-health-runbook.md) for unprivileged status, durable local alerts and remaining external delivery work. See the [isolated wallet runbook](isolated-wallet-runbook.md) for public-profile export and bounded desktop-client acceptance. Those fixed local fixture grants are not an external testnet release.

The runtime supports macOS system Python 3.9; desktop-only ledger compression tools can require newer Python. Launchd uses Interactive process type to avoid the severe CPU throttling observed with Background. This is scheduling policy, not administrator membership. Limit concurrent test networks and stop unused services to reduce CPU and disk load.

Run privileged `test` from the installed sealed command after installation. It checks real cross-UID file/socket denial, a finalized private payment whose response is lost before wallet SIGKILL, supervisor/validator SIGKILL and coordinated restart, exact private balances/nullifiers, and missing-original-credential startup refusal. The original key file is restored without regeneration. Results go to the installed `ACCEPTANCE.json`; no credentials or seeds are exported. A test interrupted after beginning must recover its original journals, never submit replacement setup payments or reset allowances.

Stopping uses the administrator's `launchctl bootout system /Library/LaunchDaemons/local.nativepay.validator.plist`; retain the account, original private state, backups and sealed manifest. Restarting uses `launchctl bootstrap system` with that original plist. An administrator can read these files and is explicitly trusted. Ordinary desktop applications must not obtain a service login password, writable runtime directory, raw RPC capability or administrator bypass.

The sealed `history-check` action performs one fixed bounded gateway-reader check as the service identity and reports only counts/checkpoint/digest. It is an administrator diagnostic, not an HTTP authentication bypass or a client-controlled path. `history-status` remains the last collector record.
