# Traffic public audience V2 — resumable shadow recovery

**Status: candidate source, shadow-only; NO authorization to publish or enable any timer.** Owner issue: [#10](https://github.com/Emaren/traffic-api/issues/10).

The legacy full-history public-audience forge timed out at two hours processing over 18 million events on October 15, 2026. The operator explicitly disabled `traffic-public-audience-aoe2hdbets.timer`. Neither the 30-minute *project* rollup job nor `traffic_session_archive` provides the exact public audience counts.

## Implemented pieces

- `scripts/public_audience_v2_checkpoint.py`: resumable pass one. Uses the same canonical project-host filter, firehose exclusion, timestamp ordering, visibility rules, and row normalizer as the original public forge; tracks (host, IP) requests, direct referrers, distinct paths and UAs in a private SQLite checkpoint, not the Traffic database. The first-pass IP classifier is compared with the original `build_ip_behavior` on deterministic fixtures.
- `scripts/public_audience_v2_sessions.py`: resumable pass two. Reuses `build_single_session`, `collapse_distributed_bursts` via `finalize_bucket`, and the original page/human classification contract. Active cross-batch sessions, expiry, finished burst buckets and per-day counts persist in the **same private checkpoint** transaction as the source cursor. Tests compare a multi-batch replay with the original unsegmented stream and verify rollback on interruption.
- Each pass computes a restartable SHA-256 chain of selected raw event fields. Completion is refused if raw rows/accepted counts or the two pass digests disagree. A stale, mutated, duplicated or missing source stream cannot earn a completed pass-two shadow receipt.
- `scripts/public_audience_v2_campaign.py`: a wall-clock- and step-bounded driver that can resume the two stages across invocations. `status` is read-only. `cycle` writes *only* the private shadow checkpoint.
- Shadow output includes the daily counts and a deterministic hash. It is **not** an authenticated final production dataset.

The checkpoint contains IP, user-agent, and path details. It is created with permissions 0600, must live outside the Git working tree, and must never be published, shared, or committed.

## Explicit production HOLD

**The original `traffic-public-audience-aoe2hdbets.timer` remains disabled/inactive.** Do not start the old service or call the original `rebuild_public_audience_archive.py --apply`, increase its timeout, or directly replace `traffic_public_daily_audience_rollups`. No V2 script writes that production table or modifies a systemd unit.

This branch does not independently prove that historical SQLite rows were immutable while pass one ran, handle a source rewind/truncation or delayed historical events after the frozen max-rowid, establish full real-world behavior/equivalence, or prove resource ceilings on the actual 18M+ corpus. Its source/inode, host/rule and raw-row hash controls are important but not substitutes for those remaining proofs. Active-hour traffic can continue ingesting while a frozen historical source epoch is processed; a subsequent qualification of late arrivals is required.

## Isolated development exercise

```bash
python3 -m unittest tests.test_public_audience_v2_checkpoint tests.test_public_audience_v2_sessions tests.test_public_audience_v2_campaign -v
```

The fixtures create and destroy temporary databases. A real Traffic database is **not** needed for these tests.

The CLI supports bounded shadow-only recovery, but **do not run it against the 18M-row VPS database** until an approved resource and provenance preflight is complete. Local fixture example:

```bash
python3 scripts/public_audience_v2_campaign.py cycle \
  --source /path/to/isolated-fixture.sqlite3 \
  --state /private/shadow-checkpoint.sqlite3 \
  --start 2026-05-22T00:00:00+00:00 \
  --end 2026-10-20T00:00:00+00:00 \
  --rows-per-step 2000 --step-budget 15 --wall-seconds 120 --max-steps 80

python3 scripts/public_audience_v2_campaign.py status \
  --state /private/shadow-checkpoint.sqlite3
```

No user-facing Traffic statistic is populated by these commands.

## Required remaining certification before live audience recovery

1. Prove a representative real input sample has **unchanged canonical visitor/session and burst classifications** and reconcile every output bucket against a separately computed trusted oracle, not merely structural equality under fixture mocks.
2. Prove snapshot source identity, source mutation/rewind behavior, late-event ingestion and host/visibility-code requalification. Different source epochs must never be merged without a documented correctness model.
3. Benchmark against at least 18 million representative events under the actual VPS's RAM, CPU, disk and SQLite contention limits, including cancellation and restarts. Establish bounded checkpoint growth and prove there is no new pressure on the concurrent 30-minute worker.
4. Review private state retention/redaction; implement and independently test **idempotent transactional publication** to the canonical public audience table, preserving previous certified rows if any phase or final verification fails.
5. Obtain explicit operator approval for a protected service deployment, and independently verify first publication, public API freshness and the new scheduler. Never re-enable the timed-out legacy timer.

Until these pass, source CI green is not equivalent to a verified production backfill.
