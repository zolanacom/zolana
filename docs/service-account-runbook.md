# Local macOS service identity

The installer creates a new no-login `_nativepay` account/group, a root-owned `/Library/NativePayLocal` runtime and `/Library/LaunchDaemons/local.nativepay.validator.plist`. Private state is owned by the service account under the installed `.data` directory, mode 0700. The service uses separate loopback ports and does not stop or replace the demo wallet at 8765. The original demo remains on its original disposable network.

Prepare a new local, secret-free bundle:

```sh
python3 -B tools/service_account.py prepare --output .local/new-service-bundle
```

Review its exact manifest and digest, the account, paths and launchd configuration before administrator execution. The root bootstrap must pin both the installer bytes and manifest digest, run system Python in isolated mode, and pass the reviewed desktop UID. It must not execute an unverified user-writable installer or alter sudoers. Administrator authentication belongs in the macOS prompt; never send the administrator password through chat, files or command arguments.

The sealed administrator command supports `install`, `update`, `test` and `verify`. Install refuses existing service account/group names, installation paths and launchd plists. It generates keys only as the unprivileged service identity, then launches the fixed daemon. A partial setup is retained for explicit recovery; rerunning initialization or deleting state is not a repair path.

An update requires a new reviewed bundle and both bootstrap digests, just like installation. The administrator bootstrap verifies the pinned new installer before invoking its `update` action. Update verifies the existing seal, stops its launchd group, replaces only changed manifest-listed code, verifies the new seal and restarts the original service. Failed verification restores the previous code and manifest. It never changes `.data`, `SERVICE.json`, account membership or the launchd plist. Keep this operation supervised: an abrupt interruption during code replacement requires explicit seal repair before restart, retaining all private state.

The runtime supports macOS system Python 3.9; desktop-only ledger compression tools can require newer Python. Launchd uses Interactive process type to avoid the severe CPU throttling observed with Background. This is scheduling policy, not administrator membership. Limit concurrent test networks and stop unused services to reduce CPU and disk load.

Run privileged `test` from the installed sealed command after installation. It checks real cross-UID file/socket denial, a finalized private payment whose response is lost before wallet SIGKILL, supervisor/validator SIGKILL and coordinated restart, exact private balances/nullifiers, and missing-original-credential startup refusal. The original key file is restored without regeneration. Results go to the installed `ACCEPTANCE.json`; no credentials or seeds are exported. A test interrupted after beginning must recover its original journals, never submit replacement setup payments or reset allowances.

Stopping uses the administrator's `launchctl bootout system /Library/LaunchDaemons/local.nativepay.validator.plist`; retain the account, original private state, backups and sealed manifest. Restarting uses `launchctl bootstrap system` with that original plist. An administrator can read these files and is explicitly trusted. Ordinary desktop applications must not obtain a service login password, writable runtime directory, raw RPC capability or administrator bypass.
