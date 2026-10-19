# Prepared human paging integration

The `page` action consumes the durable monitoring inbox and prepares PagerDuty Events API v2 trigger/update/resolve delivery. It runs separately from inbox ingestion, with its own owner-only state and provider credential. It never opens private validator/wallet state or raw RPC. Local mode accepts only a literal loopback HTTPS mock; no actual provider account or human notification was configured by this work.

PagerDuty documents the integration key, action and deduplication key in its [Events v2 request/response reference](https://docs.pagerduty.com/developer/api/reference/events-v2/send-event/create-v2-event). Its [alert-event documentation](https://docs.pagerduty.com/developer/send-alert-event) describes how trigger updates and resolves correlate through the same routing/deduplication keys. The adapter records a matching HTTP 202 success as **provider accepted**, not proof that a person received or acknowledged a page. It never submits the provider's human `acknowledge` action.

Build a new v3 monitoring bundle with `python3 -B tools/monitor_package.py --output .local/new-paging-bundle`. It retains the checked entry point, exporter/observer/inbox/pager roles and notices, and adds the independent watchdog modules/configuration examples. The nineteen-file bundle contains no integration key or TLS secrets. Review and retain its manifest/archive digests independently; this is integrity checking, not release signing.

Copy `pager.example.json` outside the bundle and set the deployment, source inbox, separate paging-state directory, endpoint and pinned CA file/digest. Configs, provider credential and CA must be owned by the process operator and mode 0600; inbox/state directories must be 0700. The adapter reads the receiver's atomically published inbox snapshot, so it needs that inbox operator's read access. Do not place the paging state inside the inbox or vice versa. Keep both outside the code bundle.

Provision the provider's real integration key only when explicitly configuring live paging. The private credential schema is:

```json
{
  "format": "native-pagerduty-key-v1",
  "deployment": "YOUR_DEPLOYMENT_HEX32",
  "routing_key": "PROVIDER_INTEGRATION_KEY"
}
```

The deployment is the same lowercase 32-hex identity used by the inbox. The integration key must be the provider-issued 32-hex Events v2 key. Monitoring capability files, wallet material and raw-RPC credentials are rejected. The local rehearsal creates a random dummy key solely for its mock; it cannot page a real service.

Finite local command:

```sh
python3 -I /absolute/bundle/run.py page --config /private/pager.json --duration 120
```

Default duration is sixty seconds; loopback mode allows 1–600 seconds. Reviewed live configuration additionally requires `--allow-network`. Its only non-loopback provider target currently allowlisted is `https://events.pagerduty.com/v2/enqueue`; regional/custom endpoints need an explicit reviewed adapter change. Indefinite foreground operation is `--duration 0` only with that explicit network flag. Preparation does not install supervision, provider accounts, contact methods, escalation schedules or a watchdog.

The TLS client validates the exact host and pinned CA with a TLS 1.2 minimum. It uses no environment proxy and follows no redirect, including redirects to another provider region. Socket reads have an absolute deadline and responses are bounded to 8 KiB. HTTP content-length/chunked acceptance is supported. OS DNS resolution retains its resolver policy. Provider response/error text is never copied into the journal or console output; failure reasons are static codes.

The journal pins inbox path/deployment, provider endpoint, CA and integration-key fingerprint. Restart against another key/route fails rather than moving an unresolved incident. Snapshot truncation, reordering, canonical prefix edits, corruption/deletion of initialized state, unsafe modes or a concurrent pager also fail visibly. Preserve the original files; do not create a fresh state directory as a recovery shortcut. The source inbox remains append-only and bounded by its existing 1,024-event policy. The relay retains accepted metadata for that prefix and permits at most 128 simultaneous observer streams; it refuses capacity overflow before sending another page.

One outage cycle per observer stream uses a stable incident key. Fault changes update that incident; actual recovery or explicit `operator_paused` resolution closes the same key. A new outage creates a new key. Interleaved observer streams stay separate. A resolution with no known active page is recorded as `no_active_page` without notifying the provider.

Plans, attempt counts and next retry times are persisted before sending. Only a matching success advances the cursor. Network/5xx failures and malformed/mismatched acceptance preserve the pending action with exponential retry backoff capped at 300 seconds. HTTP 429 honors a valid seconds/date Retry-After with a one-day operational cap; malformed values use backoff. Retry deadlines survive restart. Backward clock movement stops delivery. Provider 400/401/403/404/422 rejections remain blocked across restart, with the original pending action retained. Ingestion into the independent inbox continues while paging is unavailable or blocked.

After fixing a rejected request, stop the pager, review the cause and re-arm its original action:

```sh
python3 -I /absolute/bundle/run.py page-retry --config /private/pager.json
```

Use the same explicit network flag for live configuration. This command validates the unchanged route/source and persists `retry_armed`; it sends **no** provider request. Restart `page` to attempt that same action. It does not change integration keys or clear incident history. Rotating an invalid/compromised key, changing a provider or migrating journals requires a separately reviewed migration that accounts for existing open incidents.

Crashes after provider acceptance but before local commit may resend a trigger/resolve with the same key. The mock confirms active-incident deduplication and idempotent resolution. This is at-least-once submission, not exactly-once human notification: provider-side manual resolution can let a retried trigger create a new incident, and provider ingestion, routing, suppression, escalation and contact delivery remain outside the adapter's local evidence. The status field `human_receipt_verified: false` means human receipt was not verified.

Run `python3 -B tools/paging_rehearsal.py` for the finite local process-crash acceptance. It uses a newly extracted bundle, a real TLS inbox, a test-only mock provider and new dummy credentials. It tests unavailable/rate-limited/rejected delivery, continued inbox ingestion, provider and relay SIGKILL, persisted retry and explicit retry recovery. It starts no validators and sends no real notifications. Results/logs stay in a new owner-only `/private/tmp/native-human-paging-033-*` stage, linked from `.local/paging-033-stage.json` and `.local/paging-033-result.json`.

Before relying on live paging, select/configure an on-call service and escalation policy, verify a real person receives and acknowledges a deliberately announced test page, verify recovery, and monitor the pager/delivery channel independently. Actual host supervision, source-host platform support, provider-region selection, storage/backup capacity, signing and independent review remain deployment work.

The [independent watchdog](watchdog-runbook.md) now observes actual completed monitor/pager cycles and overdue/blocked queues through a separate read-only agent. It uses its own durable queue and separately provisioned Telegram lane, so primary paging need not work for its alert delivery. Local failure/restart tests passed; actual off-host placement, real bot/chat, human receipt and external watchdog supervision remain unconfigured.
