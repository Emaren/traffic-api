# Traffic ingestion separation — stage 1 (not yet activated)

## Measured production reason

The 2026-10-16 live 12-hour Traffic snapshot on the 47 GiB SQLite store
logged `traffic_snapshot_ingest_slow=12.728s`,
`traffic_snapshot_select_slow=13.273s`, and
`traffic_snapshot_sessions_slow=4.212s`; the SQLite query plan confirmed
the timestamp/line-offset index is used. Approximately 0.25 MiB was unread
in the Nginx log at the time of inspection, so a large current-log backlog
was **not** established as the cause of slow ingestion. Existing pruning and
SQLite writer contention still need separate timing verification.

## Why stage 1 is intentionally inert

The API currently synchronizes Nginx logs whenever `load_recent_entries()`
runs, before it builds hot visitor/session graphs. Simply removing that
synchronous step would allow new visits to go missing from the database if
no independent ingest worker is running. The Traffic watchdog does not ingest
logs; it only probes HTTP endpoints. The audience archive and daily-rollup
timers are different and should not be enabled just to address ingestion.

This stage introduces `scripts/sync_traffic_logs.py`, which calls the
**existing** `sync_configured_logs_to_persistence()` routine, and versioned
`ops/systemd/traffic-ingest.{service,timer}` definitions.

The worker preserves existing log offsets, inode-rotation handling,
`INSERT OR IGNORE` idempotency, bounded commit batches, and existing
retention operation. It does NOT modify the API's request-time ingestion,
SQLite schema, visibility rules, archival truth, or production timers.
The timer is **not activated by a repository merge**.

### Production rollout sequence

1. Establish exact running API release and deployed systemd units. Check
   `systemctl list-timers --all`; some archive units are documented in the
   repository but absent/inactive on the current VPS. Do not enable them
   as part of this change.
2. Merge and deploy the worker and unit definitions. Keep
   `traffic-ingest.timer` **disabled** initially. Verify source log paths,
   database ownership, release hash, `systemd-analyze verify`, unit settings,
   space, and that the old API still serves visits.
3. During a controlled low-traffic period, run
   `systemctl start traffic-ingest.service` **once**, then inspect
   `systemctl show traffic-ingest.service -p Result -p ExecMainStatus`
   and `journalctl -u traffic-ingest.service --since '10 minutes ago'`.
   The worker prints only count/duration metrics, not IPs, headers, log
   paths or visitor identities.
4. Verify `traffic_ingest status=ok` and compare the ingest-state offset
   against the configured access log. Verify fresh visits appear in the
   observatory through existing API endpoints (allow for response caching).
5. **Separate stage 2, not in this PR:** deploy an explicit gated
   `TRAFFIC_...` setting to make API hot session reads avoid synchronous
   log ingestion. Keep that setting **off** initially. Include contract
   tests and an immediately reversible fallback to inline ingestion.
6. Enable the ingestion timer for a **brief supervised overlap** while the
   API still ingests inline, checking at least two successful runs, ingest
   offsets, new-visit freshness, timing and resource pressure. If the timer
   is unhealthy, disable it and leave inline ingestion untouched.
7. If the new writer has proven fresh and reliable, switch the stage-2
   setting to use the timer and cease synchronous API ingest. Monitor timer
   last/next schedules, offsets, failures, dashboard freshness and latency.
   Restore inline ingestion **before** disabling or rolling back the timer
   if any health or data-freshness check fails.

### Safeguards

- Run as `tony`, with the API's environment file and working directory.
- Non-overlap via systemd single-instance oneshot and advisory flock.
  SQLite WAL and unique event IDs remain the correctness safeguards against
  other processes writing concurrently; `_SYNC_LOCK` is only process-local.
- Low scheduling priority, half-CPU cap, memory/swap limits, and a bounded
  10-minute execution timeout protect WoloChain/AoE2WAR from one run.
- If every source is missing or persistence is disabled, the worker exits
  nonzero rather than pretending new traffic is being ingested.
- A bounded exit does not prove completeness: check offsets and active logs
  rather than relying solely on service health.
- A 47 GiB SQLite file must NOT be vacuumed, deleted, moved, or reindexed
  as an incidental part of this rollout. Preserve the existing volume and
  rollback snapshots.

## Stage 2 shipped OFF by default — controlled inline-to-timer handoff

The application now supports `TRAFFIC_DISABLE_INLINE_INGEST` as an
**explicit, off-by-default** runtime switch. Unless its value is
`1`, `true`, `yes` or `on` (case-insensitive), normal API
snapshot reads **and** the notification batch continue to call the
existing synchronous log ingester exactly as before. An arbitrary
or missing value cannot silently disable ingestion.

When the switch is explicitly enabled, only the API's interactive
snapshot/notification ingestion attempts are skipped; both still read
the durable SQLite data. The dedicated independent
`scripts.sync_traffic_logs` worker is **unaffected**, including
its source cursor, rotation and idempotent insert logic. This flag
is distinct from the independently disabled-by-default
`TRAFFIC_INGEST_RECEIPTS_ENABLED` source schema-migration flag.

**A GitHub merge, source-only VPS fast-forward, or test run does not
set either environment variable, install a systemd unit, enable
a timer, start a worker, restart the API, or alter the source DB.**
Production Traffic was observed with inline ingestion active,
one configured source and an absent `traffic-ingest.timer`
on 2026-10-21. A supervised standalone oneshot succeeded once:
10,230 parsed events in 21.536 seconds, but this was not a
recurring schedule. The 14:10 UTC private audit found both
source-to-ledger and ledger-to-IP backlog zero at that instant,
while the last successful source log-sync timestamp was
12:45 UTC. Matching cursors never prove Nginx log delivery
is current. Source 2's 182-day-old ingest state belongs to
a **retired** log path, not the running API.

### Operator rollout — independent supervised change, not an auto-deploy

1. Before anything, confirm `TRAFFIC_DISABLE_INLINE_INGEST`
   is **not enabled**, that `TRAFFIC_INGEST_RECEIPTS_ENABLED`
   remains **off**, and compare live API process log-path/DB
   configuration to `/etc/traffic-api.env` without printing
   credentials or raw visitor logs. Check root/data free space
   and the live Nginx source inode, size, prior ingest cursor,
   most recent successful sync, SQLite WAL and memory pressure.
   Back up production settings securely; don't paste secrets.
2. Install the **existing source-controlled** `traffic-ingest.timer`
   unit only in a separately approved controlled maintenance
   step; validate with `systemd-analyze verify` and keep
   disabled initially. The service already exists but was
   static/inactive in live observations.
3. With inline ingestion still **on**, execute one supervised
   low-priority dedicated ingest oneshot. Verify exact service
   `ExecMainStatus=0`, real source offset advance, and no
   workers overlapping excessively. Only then enable the
   separate timer for a short supervised overlap and
   inspect at least two successful scheduled ingest runs,
   lag over active Nginx source, source errors, database
   contention and application health.
4. **Only after** the timer is demonstrably reliable,
   explicitly enable `TRAFFIC_DISABLE_INLINE_INGEST=1`
   for `traffic-api.service` in the protected environment
   and restart **only** the API through its protected release
   process. Confirm the running process actually has the
   switch, the timer remains active, recent visits are fresh,
   and notifications continue. Never restart just because
   the Git HEAD changed.
5. Reversal: restore inline ingestion in the running API
   **before** disabling the independent timer, and verify
   fresh source offset progress. Stop the handoff if the
   scheduled worker fails, log rotation produces gaps,
   disk space falls below safe reserves, or source data
   falls stale. Retain the original public 131-day audience
   SHA unchanged and the legacy public publisher inactive.

**Important**: This architecture change does **not** certify
Oct20 or Oct21 for public publication. Per-event absolute
lateness evidence, completed-day acceptance policy,
historical-to-forward stitched session parity, stable global IP
classification and append-only release verification are
still separate mandatory gates. Never fill missing UTC days
with fabricated zeros.
