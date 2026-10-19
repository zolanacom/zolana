# Independent monitor and pager watchdog

The watchdog observes completed main-loop work from the primary monitor and pager through a narrow read-only HTTPS agent. It keeps its own journal, event inbox and Telegram relay. It can alert while the primary inbox, pager or PagerDuty endpoint is unavailable. This is source/package preparation with loopback failure tests; no real bot, host or notification is configured.

Build a fresh v3 bundle with `python3 -B tools/monitor_package.py --output .local/new-watchdog-bundle`. The nineteen-file package contains eight runtime modules, a checked entry point, six config examples, notices, README and manifest. Keep the reviewed manifest/archive digests independently; integrity checks are not release signing. Extract outside writable state and use `python3 -I /absolute/bundle/run.py ...`.

The primary `watch` and `page` roles now atomically publish `watchdog.json` inside their existing private state directories. Progress contains role/deployment, random process instance, PID, sequence, start/last-completed times, phase, pending count/oldest time, static delivery failure and the pager integration fingerprint. It contains no paths, credentials, wallet data or arbitrary provider text. Progress advances only after actual main-loop work, not in a background thread. Stopping records a stopped phase without refreshing the completed-work timestamp.

Copy `watchdog-agent.example.json` and `watchdog.example.json` outside the bundle. Replace every placeholder and use one matching deployment identity. The first adapter requires monitor, pager and progress agent to run as the same unprivileged operator on their host; target owners must equal that UID. It does not collect another UID's private files or aggregate targets on different hosts. Configure only the two exact progress paths. The agent exports neither raw files nor directory listings. Role state directories must be 0700; configs, capabilities, TLS material, progress and CA files must be operator-owned regular files at 0600.

Create a separate read-only capability into a new private file:

```sh
python3 -I /absolute/bundle/run.py keygen --deployment HEX32 --role watchdog-read --output /private/watchdog-read.json
```

Give that capability only to the agent and independent watchdog. It permits only `/v1/watchdog`, with a fresh challenge and matching deployment. Observations must be within ten seconds of the watchdog clock. Keep clocks synchronized. It grants no primary alert-write, health-read, signing or RPC authority. This initial adapter trusts the publishing operator's progress, not an adversarially compromised host.

Set `primary_integration_sha256` to the primary pager's reviewed `route.integration_sha256` from its private `state.json`. This is a SHA-256 fingerprint, not the routing key. Match agent/provider origins and certificate hostname/CA pins. Keep the watchdog's `root` separate from primary directories; it creates `observations`, `events` and `delivery` beneath that root. Place the watchdog outside the monitored host's failure domain for real use. Local process separation alone cannot survive losing the whole Mac.

Provision a separate Telegram bot/chat only when configuring live delivery. The private credential schema is:

```json
{
  "format": "native-watchdog-telegram-key-v1",
  "deployment": "YOUR_DEPLOYMENT_HEX32",
  "bot_token": "PROVIDER_ISSUED_BOT_TOKEN",
  "chat_id": -123456789
}
```

The chat identifier is an integer for the intended chat; the token is a provider-issued bot credential. Monitoring capabilities and PagerDuty keys are rejected. The bot token appears in the required request path, so never enable HTTP access tracing or log request URLs. This adapter emits only static statuses, stores a credential fingerprint and never persists the secret URL. It submits plain static alert/recovery text with a stable incident key, without wallet or raw provider details. Telegram documents [sendMessage and its returned Message](https://core.telegram.org/bots/api#sendmessage) and the rate-limit [retry_after parameter](https://core.telegram.org/bots/api#responseparameters).

Finite local commands, using newly generated dummy credentials and loopback mocks:

```sh
python3 -I /absolute/bundle/run.py watchdog-agent --config /private/watchdog-agent.json --duration 120
python3 -I /absolute/bundle/run.py watchdog --config /private/watchdog.json --duration 120
```

Default duration is sixty seconds; local mode allows 1–600 seconds and literal `127.0.0.1` endpoints/listeners. Real off-host origins need reviewed TLS and explicit `--allow-network`. Only that mode permits `--duration 0` or a non-loopback bind. The only non-loopback notification endpoint allowlisted is `https://api.telegram.org`. No proxy or redirect is followed. TLS verifies the exact hostname and pinned CA with TLS 1.2 minimum; JSON responses are bounded to 16 KiB and socket reads share an absolute deadline. OS DNS keeps its resolver timeout policy.

Default thresholds are a two-second sampling interval, fifteen seconds without completed work, sixty seconds of startup grace and sixty seconds of overdue pending delivery. Review these against actual cycle/network/storage latency; source HTTPS and delivery attempts take time. A live process can still alert for blocked or aged delivery. Replayed sequences cannot renew progress forever. Starting replacements keep the existing incident until completed healthy work; repeated starting instances share bounded grace. A stopped role alerts until a completed replacement restores it. Planned maintenance/silencing policy remains deployment work.

Watchdog state pins deployment, agent/provider origins and CAs, both integration fingerprints and thresholds. Restart keeps the incident, observations, original action, retry deadline and accepted cursor. Network/5xx and malformed acceptance retry; 429 respects valid retry information; provider 400/401/403/404 rejection remains blocked. Only literal successful acceptance with matching chat, message identifier and text advances the delivery cursor. No arbitrary provider error is saved. After correcting rejection, stop the watchdog and explicitly re-arm:

```sh
python3 -I /absolute/bundle/run.py watchdog-retry --config /private/watchdog.json
```

Use the same network flag for live configs. This command sends nothing and preserves the original route/action. Restart `watchdog` for delivery. Do not delete initialized state, change destinations or reset queues to silence failures. Credential/route/threshold migration needs separate review for unresolved incidents. The independent inbox retains at most 1,024 events and the observer journal at most 128 recent/pending events; exhausted or corrupt state fails visibly. Storage exhaustion is not an unlimited notification spool.

Telegram has no idempotency argument for sendMessage. Crash after acceptance but before local commit can duplicate the same message/key. The local rehearsal deliberately proves that behavior. Already committed acceptance is not resent on restart. Neither successful API acceptance nor a recorded recovery proves a person saw the message; `human_receipt_verified` remains false. Before launch, configure and verify real announced alert/recovery receipt through this separate channel, and externally supervise the watchdog's own host/process/channel. Loss of the watchdog itself cannot reliably announce itself.

Run `python3 -B tools/watchdog_rehearsal.py` for bounded local acceptance. It extracts a fresh v3 bundle, runs actual monitor/pager/agent/watchdog processes and test-only TLS providers, injects hangs and crashes, and tests persisted retry/recovery. It reads only installed public paused-source status and never starts validators or sends payments/external messages. New evidence stays under owner-only `/private/tmp/native-independent-watchdog-034-*`, with pointers in `.local/watchdog-034-stage.json` and `.local/watchdog-034-result.json`. See LOCAL-034 evidence.
