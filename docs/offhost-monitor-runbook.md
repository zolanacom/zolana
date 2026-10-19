# Prepare off-host observation and remote alert delivery

The three roles are an unprivileged source-host HTTPS exporter, an independent observer, and an HTTPS durable alert inbox. They do not need validator keys, wallet keys, raw RPC credentials or administrator membership. The exporter reads the existing public heartbeat and fixed macOS launchd job; observer/inbox support Python 3.9+ on macOS/Linux. This is preparation with local tests, not hosted monitoring.

Build a new secret-free package:

```sh
python3 -B tools/monitor_package.py --output .local/new-monitor-bundle
```

The command emits a directory and deterministic ZIP, plus their manifest/archive digests. Identically named builds in different parents produce identical bytes. Retain the reviewed manifest digest through a separate trusted channel; the manifest alone is not a release signature. The package contains four runtime modules, a checked entry point, MIT/third-party notices, README and three example configurations. It includes no capabilities, TLS secrets, validator binaries or checkout-specific user paths.

Use `python3 -I /absolute/bundle/run.py ...` after extracting. Before importing application code, the entry point verifies exact inventory, file hashes, ownership and directory/file write permissions. Keep the code separate from writable state, configs and credentials. Do not add logs or configuration files inside the checked code directory.

Copy each role example outside the bundle, chmod it 0600 and replace its deployment identity, origins, paths and pinned CA digests. Create separate monitoring-only keys into new private files:

```sh
python3 -I /absolute/bundle/run.py keygen --deployment HEX32 --role health-read --output NEW_HEALTH_READ_FILE
python3 -I /absolute/bundle/run.py keygen --deployment HEX32 --role alert-write --output NEW_ALERT_WRITE_FILE
```

`HEX32` is one selected 32-character lowercase hexadecimal deployment identity shared by these roles. New tokens are random; do not use the example placeholder deployment for a real deployment. Provision only the health-read key to the exporter/observer and only the alert-write key to the inbox/observer. Keys, configs, CA files and TLS leaf/private-key files must be owned by their process operator and mode 0600. Existing output files are never overwritten by key generation. Share these role-specific files through a separately reviewed secure channel. Never substitute raw RPC or wallet material.

Local finite commands:

```sh
python3 -I /absolute/bundle/run.py receive --config /private/receiver.json --duration 120
python3 -I /absolute/bundle/run.py export --config /private/exporter.json --duration 120
python3 -I /absolute/bundle/run.py watch --config /private/observer.json --duration 120
```

The default duration is sixty seconds; local mode accepts 1–600 seconds and permits only literal `127.0.0.1` origins/listeners. A separate `check` invocation samples once and attempts one pending delivery using the same exclusive journal. Stop the watcher first; concurrent writers are refused. No OS service, firewall rule, certificate trust or external account is installed.

Actual off-host operation requires selected reviewed hosts/origins, valid pinned TLS configuration and `--allow-network`. Only that explicit mode permits an indefinite foreground `--duration 0` and server `--bind 0.0.0.0`. Configure supervision, least-privilege operator accounts, inbound access rules, backups and a watchdog separately. Put the observer outside the source host's failure domain. A local process separation rehearsal does not prove separate-host availability.

Production examples use `expect_running: true`: an unloaded validator job is an incident even if the exporter is reachable. The preserved local Mac rehearsal deliberately uses false because validators are intentionally paused. That policy is pinned to the journal along with the deployment, origins and CA digests. Do not change a pending journal's route or expected-running policy to silence an alert; a reviewed migration is needed. Bounded planned-maintenance/paging policies remain deployment work.

Only `/v1/health` and `/v1/alerts` exist in their respective roles. Health requests use a fresh random challenge and require a matching deployment/challenge and a source observation within ten seconds of the observer's clock. Keep clocks synchronized. Old/cached responses, unknown fields, invalid public heartbeat data and mismatched identities cannot establish recovery. Loss of the exporter alerts even after a previous intentional pause. A fresh heartbeat alone cannot hide stale finality samples or stopped finalized-slot progress. The source job/state remains trusted; these counters are not consensus proofs.

TLS validates hostnames and the pinned CA, with a TLS 1.2 minimum. The client sends directly to the configured origin, uses no environment proxy and follows no redirects. HTTP body/response sizes are bounded; socket read deadlines cover slow trickles. OS DNS resolution still follows the host resolver's timeout policy. The implementation uses the standard-library [HTTPS client](https://docs.python.org/3/library/http.client.html) and [TLS context](https://docs.python.org/3/library/ssl.html).

The observer saves each event before sending. A successful response must contain the exact deployment, event ID, canonical content hash and literal `durable: true`. Only then is the event marked delivered. One bounded attempt per sampling cycle and retry backoff capped at thirty seconds let observation continue through a delivery outage. Undelivered incident/recovery events keep their original order and IDs. A crash after remote commit but before local acknowledgement retries the same event; the inbox reuses its stored receipt. Delivery is at least once, with one stored inbox record per immutable event ID.

The inbox stores events in its owner-only `inbox.json`, atomically fsynced before acknowledgement. It rejects changed-content retries and wrong deployments. It retains at most 1,024 events and fails visibly when full; the observer preserves up to 128 recent/pending events and never prunes pending events or its open incident. Neither is an unlimited audit archive. Corrupt/missing initialized state, route mismatch or an uncertain storage commit must be investigated with the original evidence retained. Do not replace a journal to bypass an outage.

This inbox is the remote machine-delivery destination. It does **not** send email, Telegram, Slack or a human page. Connect a selected notification system through a separately reviewed relay/adapter and test human receipt before relying on it. A durable inbox receipt does not prove that someone was notified. The observer and its delivery channel also need an independent watchdog; no process can reliably announce its own host loss.

Follow-up [human paging preparation](human-paging-runbook.md) adds a separately runnable PagerDuty Events v2 adapter in the v2 standalone bundle. Its finite mock-provider crash/retry tests passed locally; no real account or notification is configured. The inbox remains independent of downstream provider failures. Provider acceptance still does not establish human receipt.

Run the full finite local crash rehearsal with `python3 -B tools/monitor_rehearsal.py`. It uses a fresh standalone package, local test certificates and new scoped keys; it reads the actual installed sanitized paused-source status as the desktop user. It never starts validators, reads private service data, modifies the installed service or sends external messages. It retains result/progress/logs under a new owner-only `/private/tmp/native-offhost-monitor-032-*` directory and links them from `.local/offhost-032-stage.json`.
