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
python3 -m scripts.public_audience_v2_campaign cycle \
  --source /path/to/isolated-fixture.sqlite3 \
  --state /private/shadow-checkpoint.sqlite3 \
  --start 2026-05-22T00:00:00+00:00 \
  --end 2026-10-20T00:00:00+00:00 \
  --rows-per-step 2000 --step-budget 15 --wall-seconds 120 --max-steps 80

python3 -m scripts.public_audience_v2_campaign status \
  --state /private/shadow-checkpoint.sqlite3
```

No user-facing Traffic statistic is populated by these commands.

## Read-only VPS staging preflight

After the exact merged commit is reviewed and installed on the Traffic API
production source checkout by a clean fast-forward (do **not** enable timers):

```bash
cd /var/www/Traffic/traffic-api
.venv/bin/python3 -m scripts.public_audience_v2_preflight \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3
```

This performs indexed read-only SQLite queries; `canary_ready=true` means
only that the source, required free space and held legacy timer were observed.
It is not performance or historical parity certification.

**Run the full campaign first on a separately approved copy/fixture.** The
`cycle` command is resumable and wall-bounded, but the real production source
contains millions of events, can contend with the active 30-minute worker, and
may produce substantial private checkpoint storage. No automated schedule is
currently authorized.

After a complete shadow replay, obtain a read-only cross-check:

```bash
.venv/bin/python3 -m scripts.public_audience_v2_parity \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --state /private/reviewed-traffic-v2-checkpoint.sqlite3
```

The parity check refuses changes in previously completed historical buckets,
reports the old last bucket separately, checks for new before-cutoff rows after
the frozen source watermark, and **always** returns
`publication_authorized=false`. Even `SHADOW_COMPARABLE` does not prove full
source immutability or certify a public release.

## Required remaining certification before live audience recovery

1. Prove a representative real input sample has **unchanged canonical visitor/session and burst classifications** and reconcile every output bucket against a separately computed trusted oracle, not merely structural equality under fixture mocks.
2. Prove snapshot source identity, source mutation/rewind behavior, late-event ingestion and host/visibility-code requalification. Different source epochs must never be merged without a documented correctness model.
3. Benchmark against at least 18 million representative events under the actual VPS's RAM, CPU, disk and SQLite contention limits, including cancellation and restarts. Establish bounded checkpoint growth and prove there is no new pressure on the concurrent 30-minute worker.
4. Review private state retention/redaction; implement and independently test **idempotent transactional publication** to the canonical public audience table, preserving previous certified rows if any phase or final verification fails.
5. Obtain explicit operator approval for a protected service deployment, and independently verify first publication, public API freshness and the new scheduler. Never re-enable the timed-out legacy timer.

Until these pass, source CI green is not equivalent to a verified production backfill.

## Cursor-seek performance qualification (October 20)

A production-source first-pass checkpoint reached 3,645,248 selected rows, then a later read hit the 25-second SQLite progress-handler budget. An isolated SQLite EXPLAIN showed the redundant historical `timestamp >= start` clause can make SQLite anchor the `(timestamp,line_offset)` index at the original archive start rather than at the durable keyset cursor. The candidate correction removes that redundant clause; the cursor is initialized to `(start, MIN_INT64, 0)` and is explicitly validated within the fixed window, so the strict composite cursor predicate retains exactly the same selected rows. Regression checks cover negative offsets at the start boundary, tied timestamp/offset rowids, checkpoint resume and an EXPLAIN plan requiring a cursor seek.

**No automatic VPS upgrade or publication.** An existing private checkpoint was created with the previous reader; the row-selection equivalence and checkpoint/source identity must be independently verified before resuming it after any executable code change. The `canonical_sha256` identity pins the underlying canonical classifier, but not the entire reader, so a deployment must not be mistaken for automatic cross-version equivalence certification. Keep the legacy full forge disabled.

## Explicit-source visibility policy gate

Earlier SSH shadow runs specified `--source` for raw rows but queried visibility rules via the ambient database configuration. The safe visibility helper can hide failures and return an empty rule set, and the ambient connector can write to a wrong database. The updated V2 reader now obtains active visibility policy **read-only from the exact `--source` SQLite database**, with fail-closed schema errors and the existing rules SHA-256 identity check in both passes. Before resuming the original 3,645,248-row checkpoint, compare its recorded `rules_sha256` to the real source rules in a separate read-only operator check. If hashes differ, preserve but do not use the previous checkpoint; it cannot be repaired by changing metadata. No publication or timer enablement is implied.

## Pass-two open-session memory containment (October 20, candidate)

Operator's first production 20,000-row endurance batch finished in 2.57 seconds,
raising the private replay cursor from 31,344 to 51,344 rows, but peak RSS was
133,888 KiB, above the 128 MiB **post-batch** investigation threshold. The
checkpoint remained private, mode 0600, with no public publication. Read-only
SQL identified 40 open sessions: 14,269,089 bytes total serialized JSON, with
one 12,713,573-byte session (89.1% of open JSON) and a second 1,488,008-byte
session. This confirms a repeated-inflation risk, not an OOM diagnosis.

**Candidate source-only mitigation:** add private checkpoint table
`v2_open_segments` and retain `v2_open` for per-key metadata. The first
patched replay batch migrates any old `v2_open.events_json` payload into a
single segment **inside the existing pass-two transaction** without decoding
it, then checkpoints future pending events in bounded (256-event) append-only
segments. Only when a session expires or pass two reaches EOF are the full
ordered segments rehydrated and handed unchanged to canonical
`build_single_session`. The existing canonical first-seen day, burst collapse,
classification and SHA-256 replay digest must remain unchanged. An exception
rolls back both migration and replay cursor; no public data is written.

**Important residual risk:** a genuinely massive, never-idle session must
still be materialized on close to run the canonical classifier. Disk spill
removes repeat per-batch expansion, but does not prove low memory or bounded
finalization of that session. Before installing on VPS, require CI tests for
legacy checkpoint migration, restart, failure rollback, chunked replay parity,
and independent real-source staging/performance. Preserve the original
checkpoint (and do not attempt an unreviewed reverse migration); use
exclusive shadow lock, resource/disk guards and a controlled first patched
batch with an explicit stop. Re-check all private state identities and the
legacy audience timer before activation. The 30-minute Traffic project-rollup
timer and the public audience production table remain outside scope.

Neither this patch nor successful CI authorizes publishing, timer activation,
or claiming completed historical reconstruction.

### Isolated old/new checkpoint A/B certification gate

Use the GitHub-reviewed exact PR head in a **detached staging worktree**,
never the production Traffic checkout. Take one consistent, operator-locked
SQLite backup of the current private checkpoint and copy it into two mode-0600
private sibling databases on the data volume. Run one identical bounded pass-two
step against the *original* (pinned main) source and one against the *candidate*
source, each operating solely on its disposable private clone. Check project
worker idle/success and 12 GiB reserve before each step; measure wall/RSS and
stop on failure, rather than modifying the live checkpoint to test a hypothesis.

`scripts/public_audience_v2_state_compare.py --original <private-old-copy>
--candidate <private-new-copy>` performs a **read-only**, source-identity-free
comparison of every metadata key, the complete ordered/open session payload
(reassembling private chunks), ordered closed sessions, and daily counts.
Output contains only boolean status, counts and SHA digests; private host/IP/UA
and paths remain offline. Its MATCH is necessary but **not sufficient**:
this test cannot prove general future correctness, actual memory ceilings for
all days, absent late arrivals, semantic equivalence across the entire source,
or production publication authority. Keep test copies private until the
comparison and rollback evidence have been reviewed; dispose of copies only
with an explicit review, preserving the original checkpoint.
