# Local operator health and alert outbox

The v7 sealed service publishes `/Library/NativePayLocal/health/heartbeat.json` as UID 450, mode 0644, in a service-owned 0755 directory under the root-owned installation. This is a fixed, bounded schema containing process/phase/time/finality/disk counters and static reason codes. It contains no wallet addresses, payment signatures, balances, invitation data, keys, passwords, raw exception text or private file paths. Private service data and Unix RPC sockets retain their existing access restrictions.

The heartbeat runs in a separate thread from lifecycle/RPC work. Finality samples come from both finalized RPC slots every five seconds. A fresh heartbeat does not establish live finality; the independent observer also checks sample freshness and progress. Retention/replica verification still controls admission and validator parking; public status does not grant RPC access or replace those guards. Publication failure parks owned workers. Cleanup preserves a blocked/failed cause instead of reporting successful shutdown as recovery.

Run the read-only observer as the desktop operator, without administrator authentication:

```sh
/usr/bin/python3 -I -c 'import sys; sys.path.insert(0,"/Library/NativePayLocal/tools"); from operator_monitor import main; main()' check --journal "$HOME/.nativepay-operator"
```

Use `watch` instead of `check` for a persistent foreground observer. The journal directory must be owned by this operator and mode 0700. The observer verifies the sealed installation once per invocation, then reads the small public heartbeat and a fixed launchd label every two seconds. It never reads raw RPC credentials, signs payments, restarts services or sends external messages. `check` drains pending local events and prints current state. `watch` prints transition events only.

An unloaded launchd job is an intentional pause and stays quiet even if the last heartbeat is stale or absent. A loaded job has thirty seconds to publish matching status; repeated PID changes do not renew that grace indefinitely. Heartbeats expire after fifteen seconds; ready-state finality samples expire after fifteen seconds, and unchanged finalized slots alert after sixty seconds. Startup is limited to 180 seconds across repeated restarts. Invalid status, process mismatches, static failed/blocked causes and launchd probe failures are visible. Future times/clock rollback fail visibly; these wall-clock thresholds are operational checks, not proofs against a malicious clock or hostile same-user journal edits.

Each incident, recovery or operator-pause resolution is written atomically before stdout delivery. Unchanged faults are deduplicated across observer restarts. Only actual ready health resolves an incident as `recovered`; an explicit unload resolves it separately as `operator_paused`. A crash after stdout flush but before delivery acknowledgement may replay the same event ID. Delivery is **at least once**; consumers should deduplicate by ID. No network alert transport or daemon is installed by this work.

The owner-only journal uses an exclusive OS lock, atomic replacement, file/directory fsync and an initialization marker. Missing/corrupt initialized state fails rather than silently resetting incident history. Preserve that directory for investigation; restarting against a new directory loses monitoring continuity. Up to 128 recent/pending events are retained. Delivered older events can be pruned, but pending events and the open incident are never discarded to make room; a full pending outbox fails visibly. This local journal is not an audit archive or protection against disk loss.

Actual off-host observation, durable remote alert delivery, host-loss recovery, canonical archive redundancy and independent security review remain deployment work. The finite installed rehearsal is `tools/health_service_acceptance.py`; it is a reviewed administrator-only test controller, not a persistent command service.

Follow-up [off-host preparation](offhost-monitor-runbook.md) adds a separately runnable authenticated exporter, observer and durable HTTPS alert inbox. Their extracted-package crash/retry/host-loss protocol has been tested locally, with validators kept paused. Real host placement and human notification delivery are still separate deployment steps. Remote-bound journals cannot be consumed by this local stdout observer.
