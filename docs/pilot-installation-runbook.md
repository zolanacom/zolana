# Pilot installation and ten-tester funding

This is a local preparation workflow for a **separate macOS arm64 pilot**. It does not install over `/Library/NativePayLocal`, change preserved wallets, purchase/contact hosts, configure DNS/firewalls, create accounts or load a service. Both validators currently share one host and loopback peer transport. Linux and independent validator hosts require additional work.

The bundle uses existing development binaries. It is not a signed/notarized public release or a claim that embedded build paths have been removed from every validator executable. Review the manifest digest through an independent trusted channel. A checksum establishes integrity against that reviewed digest, not publisher identity.

## Review the installation

From the repository's trusted checkout:

```sh
python3 -B tools/pilot_install.py prepare --bundle /absolute/private/host-bundle
python3 -B tools/pilot_install.py check --bundle /absolute/private/host-bundle --manifest-sha256 REVIEWED_DIGEST
python3 -B tools/pilot_install.py rehearse --bundle /absolute/private/host-bundle --manifest-sha256 REVIEWED_DIGEST --prefix /absolute/private/installation-rehearsal
```

The fixed allowlist contains the runtime/helper code, provisioning/installation tools, four native executables and upstream notices. No wallet, operator backup, password, TLS key, capability, ledger, cohort or invitation export is copied. Extra files, links, changed inputs, changed installed code and mismatched identities/digests are refused. An interrupted complete temporary copy can resume; a partial/changed temporary file is retained for review, never overwritten. Installation retries preserve `.data` and use an exclusive installation lock. There is no automatic upgrade or replacement of an existing different installation.

`HOST-SETUP.txt` is part of the reviewed manifest. It describes the actual host ceremony: provision a dedicated `_zolanapilot` no-login user/group with home `/var/empty` and shell `/usr/bin/false`; independently place the trusted bundle under a root-controlled real directory with root-owned private files; invoke the independently trusted install tool as administrator. `install` accepts only `/Library/ZolanaPilot`, requires that pre-existing dedicated identity and root-controlled ancestors, seals code read-only and creates owner-only `.data` for that identity. It never writes `/Library/LaunchDaemons` or invokes `launchctl`.

Create the new private network and cohort **at their final installed paths, as the service UID**. Absolute network/socket/cohort/TLS/code pins are intentional. Never copy a funded developer network elsewhere and edit its binding, genesis or capability to make it start. Keep the old protected service and pilot installation separate. An actual dedicated-account installation, service-account access-denial test, launchd lifecycle and reboot test remain host acceptance gates; a current-UID copy rehearsal does not establish those results.

## Authorize the exact finite funding ceremony

The ten-slot cohort must be unused: no issued invitation or claim, no runtime binding. Prepare its funding intent and review a separate provisioning digest:

```sh
python3 -B tools/pilot_provision.py prepare --network-root NETWORK_ROOT --root COHORT_ROOT --plan-sha256 COHORT_DIGEST
python3 -B tools/pilot_provision.py run --root COHORT_ROOT --provision-sha256 PROVISION_DIGEST --password-file FAUCET_PASSWORD --cold-password-file COLD_PASSWORD --sponsor-password-file SPONSOR_PASSWORD
```

These are raw **valueless development test units**:

| Allocation | Amount |
| --- | ---: |
| Private reservoir | 10,000,000, in exactly two 5,000,000 deposits |
| Public gas/retry reservoir | 6,000,300,000 |
| Separate treasury transaction fee cap | 10,000 |
| Private grant per tester | 1,000,000 |
| Public gas grant per tester | 150,000,000 |
| Lifetime invitation slots | 10 |

The public amount is the conservative budget covering the native faucet's bounded attempts; it is not ten times only the happy-path gas grant. Existing sponsor deposit, request and lifetime caps are retained. The fixed `fund-faucet-check` one-billion fixture transfer cannot fund this ceremony and must not be repeated or reset to simulate it.

`pilot-treasury-sign` only signs the exact finite public allocation from the encrypted original treasury to the encrypted cohort wallet's fee authority. It checks the private isolated network, destination's initial zero balance, role identity and a separate fee cap, and never broadcasts. The Python ceremony saves/fsyncs that exact signed transaction before submitting it. `pilot-treasury-check` validates the saved signature and exact signed instructions offline. Recovery queries the original signature and requires successful finalized status plus inclusion in the canonical finalized block. A lost response or process crash reuses the same bytes/signature. An expired unresolved signature, missing canonical evidence, wrong genesis, failed transaction or changed receipt stops the ceremony. It **never signs a replacement or automatically refills**; obtain canonical operator review rather than deleting its journal.

The two private deposits use permanent request IDs `pilot-ten-deposit-01` and `pilot-ten-deposit-02`. The ceremony retains start markers, native sponsor reservations and wallet pending/staging journals. On restart it resolves/reclaims original journals before using canonically verified balances to recover a lost completion checkpoint. Unexpected funds/notes, changed markers and exhausted original sponsor reservations stop the operation; a process loss before upload may need explicit original-reservation review. Do not change request IDs or relax sponsor limits. Completed provisioning can be checked again only while the cohort remains unused; issued admission/runtime binding forbids another ceremony.

After provisioning, obtain a **fresh** `pilot_funding.py verify` receipt; its native scan must verify the complete private balance is spendable in two inputs and finalized public funds meet the budget. Use that receipt immediately with the separate [runtime binding](pilot-runtime-runbook.md). Cold recovery and sponsor custody should then leave the running service; native grants/private sends/withdrawals use the funded faucet and users' fee authorities. The provisioner is never called automatically by the runtime or service manager.

## Render a disabled manager configuration

```sh
python3 -B tools/pilot_install.py render --binding-sha256 ORIGINAL_BINDING --output /absolute/private/local.zolana.pilot.plist
```

The reviewed plist binds `/Library/ZolanaPilot/.data/pilot` and the original digest to `_zolanapilot`, `/usr/bin/python3`, two Rayon threads and low-priority background execution. It has `Disabled=true`, bounded restart throttling, `AbandonProcessGroup=false` and a 90-second shutdown allowance. Root-owned immutable code, exact UID/GID, private state and Python interpreter must be checked on the intended host. A separately authorized deployment must explicitly install/enable/load it. Local tests kill owned subprocess groups; they do not substitute for verifying launchd's actual descendant cleanup on the target host.

Real TLS/firewall configuration, independent history plus canonical archive, human alert receipt, supported external-device recovery and trusted client delivery remain required. Neither a completed local allocation nor this inert bundle establishes public availability.
