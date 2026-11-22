# Deployment description

A deployment is one installed network: its name, its directories, its service accounts, its loopback
ports, its unit names, how many validators it runs and the hashes it is bound to. The tools used to carry
these as typed constants, so a second network on the same host, or a test network beside a production
one, meant editing a copy of every tool.

`tools/deployment.py` now holds them in one place. Its `DEFAULT` is the description the tools have always
used. With nothing set, every tool behaves exactly as before: the same paths, the same accounts, the same
rendered units, byte for byte. `tools/deployment_test.py` holds that fixed by comparing every rendered
unit with its recorded SHA-256.

## Selecting a description

| Environment variable | Meaning |
| --- | --- |
| `ZOLANA_DEPLOYMENT` | Absolute path of a JSON description. Unset means the built-in one. |
| `ZOLANA_DEPLOYMENT_SHA256` | Optional SHA-256 of that file's exact bytes. Required by the tools that are installed alone (below). |

A description that is named is never replaced by the built-in one. If the file is missing, unreadable,
invalid or differs from its SHA-256, the tool stops.

```sh
python3 -B tools/deployment.py show                         # the description in use
python3 -B tools/deployment.py check second.json            # validate a file
python3 -B tools/deployment.py compare default second.json  # can the two share a host?
python3 -B tools/deployment.py lint                         # see "The lint" below
```

`compare` lists every name, directory, account, port and unit the two descriptions share, and exits 1 if
there is one. Two descriptions with an empty list can be installed side by side.

## Fields

A description is complete: every field is required, and unknown fields are refused.
`tools/fixtures/deployment_second_v1.json` is a full example.

| Field | Read by | Built-in value |
| --- | --- | --- |
| `name` | `compare` | `zolana-native-058` |
| `network.genesis_hash`, `network.domain` | `native_network_service.py`, `native_cohort_service.py` | `null`: taken from the sealed service configuration, as before. A value here is compared with that configuration and a different network is refused. |
| `network.upstream_commit` | `native_network_service.py` | the validator source line the runner must report |
| `validators` | `native_network_service.py` | `3` (the runner accepts one to three) |
| `service.prefix`, `etc`, `state`, `run` | the service, cohort, planner, fault gate and acceptance tools | the four `zolana-native-058` roots |
| `service.users`, `service.link_group` | service, cohort and acceptance tools | `zolana058v`, `zolana058g`, `zolana058t`, `zolana058link` |
| `service.ports` | service and acceptance tools | `38443`, `38444` |
| `service.units`, `service.sockets` | service, cohort and acceptance tools | the four `zolana-native-058-*` units |
| `service.module`, `service.module_sha256` | cohort service, startup wrappers, history candidate | `native_linux_service.py` and its SHA-256 |
| `service.label`, `cohort.label` | unit descriptions | `LOCAL-058`, `LOCAL-060` |
| `cohort.pilot`, `cohort.rehearsal` | `native_cohort_service.py`, `native_pilot_cohort.py`, `native_cohort_fault.py`, `public_pilot_ingress.py`, `public_tls_certificate.py` | directories `cohort-060` and `cohort-060-rehearsal`, unit stems, ports `39443`/`39444` and `40443`/`40444` |
| `history.*` | `compact_history_collector.py` | history root, wallet binary, operator profile |
| `history_candidate.*` | `native_history_candidate.py` | the `zolana-native-063` overlay and the SHA-256 of the configuration it extends |
| `startup.*` | `native_validator_startup.py`, `native_snapshot_startup.py` | installed wrapper paths and the snapshot runner path |
| `public_tls.root`, `ingress_config`, `certificate_source`, `service_uid`, `ports` | `public_tls_certificate.py`, `public_pilot_ingress.py` | the `zolana-native-074` files, user number `994`, ports `443`/`8444` |
| `public_tls.minimum_validity_seconds` | the same two tools | `3600`: validity a certificate must still have when deployed or loaded |
| `public_tls.lifetime_days` | no tool in this repository | `null`. The loopback certificate is issued by an installer that is not in this repository; the field is the one place for it to take the lifetime from. |
| `pilot.*` | `pilot_linux.py` | `/opt/zolana`, `zolanapilot`, the approval file |

The cohort size, grants and budgets are policy, not installation identity, and are not in the description.

## How each tool reads it

**Tools that run beside their siblings** (`native_pilot_cohort.py`, `native_cohort_fault.py`,
`compact_history_collector.py`, `public_pilot_ingress.py`, `native_service_acceptance.py`) import
`deployment`.

**Sealed entry points started with `python3 -I`** (`native_cohort_service.py`,
`public_tls_certificate.py`, `native_network_service.py`) cannot import a sibling, so they execute
`deployment.py` from beside themselves, without a bytecode cache. A bundle that holds one of these tools,
or `native_cohort_fault.py`, must also hold `tools/deployment.py`. The sealed bundle check already
refuses any module in `tools/` that the manifest does not list, so the description module is verified
with the rest.

**The validator and gateway service.** `native_linux_service.py` is the accepted service source. Two
startup wrappers and their tests bind its exact bytes, so it cannot be changed. For any other
description, `native_network_service.py` runs that same source with each typed value replaced by a value
from the description. Its `REPLACEMENTS` table is the whole difference; the source must have the accepted
SHA-256 and every replacement must match exactly, or nothing runs. A deployment selects it with
`"module": "native_network_service.py"`, and its bundle holds both files.

**Tools installed alone** (`native_validator_startup.py`, `native_snapshot_startup.py`,
`native_history_candidate.py`, `pilot_linux.py`) are installed as a single file or as part of an exact
file list, with no room for `deployment.py`. They keep their built-in values and read their own fields of
the named description themselves. The first three require `ZOLANA_DEPLOYMENT_SHA256` and a root-owned
mode `0444` file under root-owned directories. `deployment_test.py` holds their built-in values equal to
the built-in description.

**Installed services** re-read a named description as a sealed file (root-owned, mode `0444`, every
directory above it root-owned and not writable by others) before they load any other code. Units rendered
while a description is named carry two lines so that the service reads the same file:

```
Environment=ZOLANA_DEPLOYMENT=/etc/example/deployment.json
Environment=ZOLANA_DEPLOYMENT_SHA256=<sha256 of the file>
```

Units rendered for the built-in description have no such lines and are unchanged.

## A second deployment

1. Write the description; `check` it; `compare default` it.
2. Render with it named:

   ```sh
   ZOLANA_DEPLOYMENT=/abs/second.json python3 -I -B tools/native_network_service.py render --output units-second
   ZOLANA_DEPLOYMENT=/abs/second.json python3 -I -B tools/native_cohort_service.py render --output cohort-second
   ```
3. Build its bundle with `native_linux_service.py`, `native_network_service.py` and `deployment.py` in
   `tools/`, install the description as a sealed file, and put the SHA-256 of the installed
   `native_network_service.py` in `service.module_sha256` if a startup wrapper is used.

What the tests cover: validation, the built-in description leaving every rendered unit unchanged, the two
descriptions rendering at the same time from one checkout with no shared name, and every guard of the
accepted service passing against `native_network_service.py`. What they do not cover: an installed run. No
second deployment has been started on a host from these tools, and the tools that create the service
accounts, directories and sealed configuration are not in this repository.

## The lint

`python3 -B tools/deployment.py lint` runs in `tools/check.sh`. It fails when a file under `tools/`
types

- a path under `/opt`, `/etc`, `/srv`, `/run`, `/var/lib`, `/var/log`, `/Library`, `/home` or `/root`
  (a short list of places every host has is exempt),
- a systemd unit name,
- a name with a three-digit generation number, or one of the project's account names,
- a 64 or 40 digit hexadecimal hash,
- a base58 address of 32 bytes, or
- an IPv4 address that is not loopback, unspecified or a documentation range

unless `tools/deployment_pins.json` records that exact value for that file with a reason. The tests,
`tools/fixtures/` and `tools/deployment.py` itself are exempt. Names that end in a version, such as
`zolana-native-cohort-plan-v1`, are file and message formats and are not flagged. Ports are not flagged:
a bare number cannot be told from any other number.

The record can only shrink. An entry that no longer matches its file fails the lint too, so a tool that
stops typing a value has to give up its entry.

What is still recorded, and why:

| Reason | Files |
| --- | --- |
| `accepted-source` | `native_linux_service.py`: bound by SHA-256, run through `native_network_service.py` for other descriptions |
| `replacement-table` | `native_network_service.py`: the text it replaces |
| `installed-alone` | the two startup wrappers, the history candidate, `pilot_linux.py`: built-in values kept, description read |
| `local-macos-service` | `service_account.py`, `service_runtime.py` and the acceptance tools of the local macOS service: one install root, account and label shared by all of them, not described yet |
| `macos-pilot` | `pilot_install.py`, `pilot_host.py`: not described yet |
| `explorer` | `tools/devnet_explorer/`: installed on its own, settings in its unit files, not described yet |
| `source-pin`, `protocol-constant`, `release-record`, `acceptance-rig`, `copy-record` | build inputs, program addresses and records that do not name an installation |
