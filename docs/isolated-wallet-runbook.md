# Local standalone wallet with isolated validators

Use the existing installed service identity. Prepare a v2 bundle using `tools/service_account.py prepare` and apply it through the same reviewed manifest/installer digest bootstrap described in the [service runbook](service-account-runbook.md). The updater supports the exact old v1 inventory without recreating the account, keys, genesis or ledgers. It preserves whether the daemon was loaded; updating a paused daemon does not restart validators.

While the original service is running, the sealed administrator command `ingress-init` performs one explicit finite setup: private TLS material, source seed, 5,000,000 private reservoir units, 1,000,000,000 public source gas units, and two lifetime invitation/grant slots. It saves a phase before each value operation and refuses an interrupted setup. Preserve all files for original-journal recovery; never delete a phase marker or repeat funding to repair a failure. Once setup is ready, restart the original daemon to open its two HTTPS listeners and worker.

The administrator command `client-export --client alice --output /private/tmp/<new-private-file>` creates a desktop-owned mode-0600 file containing only the public profile and an invitation. The other fixed acceptance client is `bob`. Existing issued invitations are reused; no private service seed, capability or source password is exported. Do not paste export contents into chat, URLs, Git or logs. Copy the profile into the standalone wallet's separate data directory and supply the invitation only through its normal Join flow. Keep the original legacy wallet directory and genesis unchanged.

The existing wallet starts with:

```sh
python3 -B tools/wallet_ui.py --network-profile <public-profile.json> \
  --data-dir <new-desktop-wallet-directory> --port 8766 --duration 3600
```

It accepts no validator-root or sponsor option in this mode. Onboarding remains create/restore → confirm encrypted recovery → join → receive finite test coins/gas → user-paid private sends. Raw RPC is available only through private service Unix sockets. Merely copying the source RPC URL into a desktop profile does not grant access.

Repeatable desktop-UID acceptance uses new private evidence once, then the same evidence for subsequent actions:

```sh
python3 -B tools/service_wallet_acceptance.py onboard --root <private-evidence> \
  --alice-export <private-alice-export> --bob-export <private-bob-export>
python3 -B tools/service_wallet_acceptance.py payment --root <same-private-evidence>
```

The harness creates two independent encrypted seeds and private backups, redeems the original invitations, waits for the original grants, checks desktop file/socket denial, then sends 50,000 units with a quoted user-paid fee cap. It saves `send_started` before submission and refuses to repeat a started payment. An interrupted payment must resolve its original pending journal explicitly before continuing; never reset evidence or issue replacement grants. Completed payment checkpoint verifies 950,000/1,050,000 balances and fingerprints original wallets, backups and profiles.

After the administrator SIGKILL/recovery check has verified original canonical pool/nullifier state, service identities, admission/claim ledgers and sponsor budget, run:

```sh
python3 -B tools/service_wallet_acceptance.py verify --root <same-private-evidence>
```

This rechecks original client files/balances, admission, the same completed grants and raw-RPC denial through the restarted service. It does not automatically submit another payment. A finalized payment checkpoint followed by restart is distinct from an acknowledgement-loss test while the wallet has a pending payment; report those results separately.

`tools/service_ingress_recovery.py` is an administrator-reviewed acceptance helper, not a daemon entry point. Execute its exact digest-reviewed bytes with isolated system Python only after the desktop payment checkpoint completes. It snapshots the original canonical state and private file hashes, SIGKILLs the owned launchd service, waits for replacement processes and new finality, and checks exact state before any subsequent client requests can update quota counters. It refuses an existing started checkpoint instead of silently starting another crash experiment. Its report is installed as `INGRESS-RECOVERY.json`.

An older local CA fixture lacked X.509 key identifiers required by newer strict TLS clients. New fixtures include those extensions. For an existing funded fixture, `tools/repair_service_test_tls.py` is a one-time digest-reviewed migration run as the original service UID while the daemon is stopped. It reissues certificates with the original CA and leaf keys, retains old certificates/profiles, and updates only the public CA certificate pin. It never generates replacement keys or repeats funding. Export the refreshed public profile, then use `service_wallet_acceptance.py refresh-ca --root <same-private-evidence> --new-export <new-private-export>`. This explicit certificate refresh verifies the original CA public key and refuses changes to genesis, endpoints or other profile fields, backs up old profiles, and verifies encrypted wallets and recovery files are untouched. An interrupted migration requires explicit recovery from the retained files; do not clear markers or recreate wallets. The normal wallet profile binding remains strict, and TLS verification is not weakened.

Stop the extra daemon afterward with the original `launchctl bootout system` plist command. Retain its keys, ledgers, admission ledger, claims, backups and sealed manifest. The supervisor also pauses before startup below 1.5 GiB free disk and stops running writers below 1 GiB. Reclaim space outside active state before an explicit restart; do not auto-delete ledgers or backups. The local CA/leaf certificates are short-lived, with no global trust-store changes. Public hosting and remote tester distribution remain separate work.
