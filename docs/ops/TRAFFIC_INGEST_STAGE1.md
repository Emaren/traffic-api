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
5. **Separate stage 2, not in this PR:** provide an explicit gated
   `TRAFFIC_...` setting to make API hot session reads avoid synchronous
   log ingestion only after the timer's freshness is proven. Include
   contract tests and a rollback path that restores inline ingestion first
   if the worker fails.
6. Only after the stage-2 cutover and verification, enable
   `traffic-ingest.timer` on the VPS. Monitor timer last/next schedules,
   status, backlog and log errors, and confirm no duplicated expensive
   ingest/retention contention. Avoid running the timer continuously while
   the API still synchronizes on every cold request.

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
