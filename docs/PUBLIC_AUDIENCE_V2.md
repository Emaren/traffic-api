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

## Source-controlled protected PASS2 runner (candidate)

`scripts/public_audience_v2_guarded_resume.py` is a **PASS2-only**,
checkpoint-resuming operator command. It refuses to initialize/rebuild pass one,
publish production audience data, enable any timer, or cross the frozen
2026-05-22 through 2026-10-19 UTC source epoch. Its mandatory `--require-sha`
pins the exact deployed source commit and requires a clean checkout.

Preflight checks source identity against the existing checkpoint (including
host and active visibility rules), exact 21,618,093/21,618,090 counts,
source rowid 44,247,247, first-pass SHA, private file mode 0600, independent
30-minute rollup timer enabled/active, disabled legacy timer, and root/attached
volume capacity. Exclusive `flock` uses the same private
`.canary.lock` as the exploratory replay commands. Each 20K-row pass-two
step runs in a new bounded Python process (default internal 25 seconds,
external 35 seconds) under nice 15, to reclaim large temporary allocations.
It checks worker priority before and after each step, enforces an 18-second
and 192MiB **observed post-step** soft stop, and writes mode-0600 fsynced
START/STEP/STOP/FAIL JSONL receipts containing only counters/provenance.
The default 900-second/240-step window is finite and restartable; operator
invokes another window if stopped by time. All state advances remain
transactional within the private replay checkpoint.

**Important:** an observed RSS stop is not a hard cgroup memory limit. Very
large, never-expiring sessions still have an unbounded canonical close phase.
The real operator must inspect actual peak RSS/swap, unit overlap and volume
pressure during the campaign, and stop if any threshold is hit. Do not schedule
autonomous recovery or public publication without separate reviewed unit,
operator approval and production evidence. Treat each proof as specific to
the code SHA and source epoch used.

Example **operator-approved candidate** invocation after guarded, exact-SHA
source deployment (replace SHA with reviewed merged GitHub main), with no
public database write:

```bash
.venv/bin/python3 -m scripts.public_audience_v2_guarded_resume \\
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \\
  --state /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \\
  --require-sha <exact-reviewed-main-sha> \\
  --wall-seconds 900 --max-steps 240
```

Only `PASS2_COMPLETE` together with exact full counts and equal digests can
move the incident to independent historical parity. None of these receipts
certifies the public graph or authorizes publication.

## Aggregate replay hot-path telemetry (2026-10-20 candidate)

After the first governed nine batches, pass two had safely advanced to
`231,344` selected raw rows; eight batches stayed below 94,000 KiB RSS.
Batch nine reached 234,896 KiB RSS (6.51s), triggering the 192MiB
post-batch soft stop. The checkpoint remained `PASS2_RUNNING`, original
first-pass identity preserved. Read-only checkpoint inspection showed
24 open sessions; 304 private segments with 33,840,610 serialized bytes,
including one **27,473,250-byte** open session and another 6,275,281-byte
session. Therefore the original giant session **did not close**; it
continued growing. No specific cause of batch nine's transient RSS spike
has yet been proven. The source cursor was 2026-06-13 03:45:37Z.

To distinguish causes without exposing behavior or adding source-query
work, the next operator-approved replay adds in-memory aggregate
`performance` counters to each successful 20K step: maximum event
count materialized by any closed canonical session, max seconds spent
collecting a session's private segments, max seconds in canonical
session classification, maximum session count flushed from one
distributed-burst bucket, and max seconds spent in a bucket's
classification. All counters are reset per subprocess and stored in
mode-0600 private runner receipts. Never report host, IP, path,
user agent, session IDs or detailed segment contents.

**No change** to normalizer, classification, session boundaries,
digest chain, checkpoint schema, timer or public publication.
Counters explain hot-path cost but do not themselves establish peak
allocator source or prove a giant session can close under the hard
virtual-memory limit. Any future memory threshold change requires
independent review of actual RSS and throughput. Keep the legacy
audience timer disabled, project rollup enabled, and publication held.

## Bounded foreground multi-window PASS2 supervisor

October 20 operator run with existing protected runner, pinned Traffic
SHA `37733e750a07abdb4f738f9c0a3a4c5577e8da79`, reached
`p2_raw=4,471,344` (20.68% of 21,618,093), `p2_pages=53,943`,
`p2_finalized=69,303`, cursor `2026-07-22T02:18:50Z`, using
189 successful 20K steps in ~9.7 minutes. Maximum peak RSS 302,916 KiB
at a canonical close of 191,931 events; below the operator-approved
320MiB post-step soft stop. The run stopped voluntarily with
`project_worker_priority` when the 30-minute project rollup worker
started. That is intended behavior, not an incident.

`scripts/public_audience_v2_guarded_supervisor.py` is an
**operator-started, foreground-only**, finite multi-window supervisor.
It invokes the existing locked, guarded PASS2-only runner, waits for
priority project work to finish, and continues only after a successful
worker/health status. Each child window still enforces the frozen
source epoch, digest/counts/policy, clean SHA, private lock, disabled
legacy timer, root/attached volume reserves, 25s internal/35s external
batch timeouts, 18s per-batch soft stop, 320MiB observed RSS soft
stop, and 768MiB inherited Linux process virtual-address-space
backstop. The supervisor additionally checks MemAvailable >=1GiB
before windows, validates every new mode-0600 receipt and resulting
checkpoint cursor, and never automatically retries an RSS soft-stop,
FAILED run, malformed receipt, changed cursor, or unhealthy worker.
It limits its total foreground lifespan and worker-wait duration; no
systemd unit or cron schedule is installed. On SIGINT/SSH disconnect,
the currently running guarded child must not be left unattended:
use operator SSH session discipline and inspect private receipts.

Example (only after reviewed, exact-SHA GitHub main is cleanly
fast-forwarded to the VPS):

```bash
.venv/bin/python3 -m scripts.public_audience_v2_guarded_supervisor \\
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \\
  --state /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \\
  --require-sha <exact-reviewed-main-sha> \\
  --total-seconds 7200 --window-seconds 900 --max-windows 12
```

This supervisor cannot authorize production publication, does not
replace independent source/digest and historical semantic parity,
and must not start the 06:15Z failed public forge. Keep project 30m
rollup timer enabled and stable. Inspect STOP reason and full source
digest before touching public series. Historical audience maintenance
after October 19 remains a separate engineering/publication task.

## Completed frozen replay and 132-day coverage diagnostic (2026-10-20)

Production operator completed V2 private pass two with 21,618,093 source rows,
21,618,090 accepted; phase `PASS2_COMPLETE`, exact first/second raw-stream
digest match. No publication is authorized. Read-only `campaign.audit` found
132 populated days (2026-06-10 through 2026-10-19), missing 19 calendar days
2026-05-22 through 2026-06-09; no extra dates, no zero-valued stored buckets,
no hierarchy violations. Three aggregate series summed 757,806 total sessions,
86,969 potential-human sessions, 37,405 confirmed-human sessions. These are
session counts, **not** raw request counts. Full-day October 19 present as
[10,695, 615, 283]. A missing bucket is not verified zero traffic: **do not
synthetically insert 19 zero days or imply source coverage was proven.**
Establish independently whether raw eligible traffic existed before June 10,
whether historical ingestion was operational then, and what the public graph
should disclose for an uncovered interval.

The live-vs-shadow preview failed before legacy comparison because its
post-watermark scan raised `sqlite3.OperationalError: interrupted` at the
10-second database progress-handler budget. This is an **inconclusive**
late-eligible-row check, not absence of late arrivals. The remedy forces
`FROM traffic_entries NOT INDEXED WHERE rowid > watermark` so SQLite uses
its intrinsic primary-key rowid seek, rather than picking a stale timestamp
index. The host, end-exclusive UTC window, non-firehose and canonical
normalizer still gate eligibility; 10-second and candidate budgets remain
fail-closed. Regression requires EXPLAIN of the *actual query* to indicate
`INTEGER PRIMARY KEY (rowid>?)` with competing time indexes present.
Operator must verify real VPS explain and actual preview under exclusive
private lock before interpreting its `MATCH` or `BLOCKED` result.

Never mutate source, private checkpoint, public audience table, or timer
in response to this diagnostic alone. All 151-day claims and daily maintenance
remain independently gated from frozen-source digest parity.

## Earliest retained source boundary & narrower truthful release candidate

VPS read-only evidence at Traffic SHA `750f458460fad5bb133d8a0e19fcb1a51e63b6b9`
proved the **earliest surviving event anywhere** is
`2026-06-10T13:41:50Z`, the earliest matching AoE2WAR source row is
`2026-06-10T13:43:17Z`, and 0 records remain for June 8–9.
June 10 has 3,672 retained selected requests starting after 13:43;
June 11 has 91,506 requests between 00:00:57 and 23:59:56 UTC;
June 12 has 97,501. The prior October 14 public archive has June 9
`[90,3,1]`, June 10 `[2939,21,9]`, yet the canonical private
replay returns no June9 and June10 `[987,13,6]`. All 125 legacy
**stable complete** June 11–October 13 buckets exactly match.
Late eligible source rows after original snapshot watermark were absent
under the canonical normalization policy. The prior historical loss
mechanism is not proven, and absent events cannot be reconstructed.

The safe immediate public **candidate** would include only 131 complete
UTC days **2026-06-11 through 2026-10-19**, excluding both the
pre-source May22–June9 interval and incomplete June10. This is a
narrower proposition than the originally requested May22 start and
**requires operator approval**, not a silent substitute. The Traffic
public audience API already reads ordered rows directly from the
single canonical `traffic_public_daily_audience_rollups` table,
so this proposed interval is representable without filling empty days.
The live frontend still needs separate runtime smoke tests before
assuming it correctly represents the shorter source coverage.

`scripts/public_audience_v2_release_manifest.py` is a deliberately
**read-only** candidate gate: frozen raw source/counts/digest/policy;
verified earliest retained event; bounded post-watermark late eligible
scan; exactly 132 canonical shadow buckets (including the known June10
partial); exact 131 positive, monotone full days June11–Oct19;
expected only June9/June10 legacy mismatches (125/127 matches);
legacy baseline count/range; SHA256 of the candidate day/value matrix
and of the current published matrix. No release permission implied.
It has no apply/write command. After operator approval of the
**131-day** historical window, separately design, review, test and
prove an idempotent atomic publisher preserving/restoring the previous
public rows, plus independent proof that the AoE2WAR frontend renders
the dates correctly. Daily 00:05 UTC maintenance and missed-day
handling require their own canonical-equivalence design. Keep the
failed full-forge timer disabled; never zero-fill missing source days.

## Live retention confirmation and no false immutable-source guard

After the October 20 first full-day manifest was deployed (pinned
`d21a54586e09a2de2696961d2f41ae8fcb747dae`), its exact earliest-live-row
assertion correctly fail-closed. Operator inspection confirmed source
`traffic_history.sqlite3` had same device/inode (2064/131074),
but earliest live raw timestamp advanced from
`2026-06-10T13:41:50+00:00` to `2026-06-10T13:48:00+00:00`.
The current earliest live rowid was 10,591,495, still below the frozen
watermark 44,247,247. Latest live rowid was 44,305,099, reflecting
ongoing ingestion. The deployed production source explicitly contains
`_prune_old_entries_bounded`: DELETE oldest timestamp-selected rows in
5,000-row batches, checked approximately every 300 seconds, with
`PERSIST_RETENTION_DAYS` default 120 (effective VPS env still
requires independent confirmation). Therefore a stable earliest *live*
timestamp is **not** a valid prerequisite for a persisted, separately
computed frozen 151-day source snapshot.

The correction validates the current earliest timestamp as offset-aware UTC,
monotonically **not earlier** than the independently observed frozen source
boundary and **before** the frozen end-exclusive UTC date. It records both
the original and current boundaries in the private/public-safe manifest
receipt and whether retention advanced. Any source event timestamp earlier
than the original earliest, a missing source, or a future-only source still
fails closed. This is a guard on drift direction, **not** a proof that no
interior frozen rows were mutated. That broader protection derives from the
complete, checkpointed two-pass frozen raw input digest and canonical
historical agreement, along with a separate bounded post-watermark
late-eligible scan. Do not rerun the frozen two-pass job against a
retention-pruned source, and do not blindly lift or suspend ingestion
retention. Before authorizing any public migration, create a 0600
completed-checkpoint backup using SQLite's online backup API under
the private shared lock, verify metadata and the complete shadow day SHA,
and retain receipt/digest along with rollback evidence.

The candidate is **still** June11–Oct19 only, and still explicitly
unauthorized for publication pending user acceptance, atomic/idempotent
publication design, and completed-day maintenance. The old 06:15 public
full-forge timer remains disabled. Never turn the incoming raw-log retention
policy into a guarantee of infinite replay history.

## Protected public-audience publication candidate (not authorized)

The real VPS verified a **completed independent checkpoint backup** at
`canary-oocB0WuA/completed-pass2-21618093.sqlite3` (593,838,080 bytes,
mode 0600), identical metadata and source pass-one/pass-two SHA
`6606f0277cf7c94249f73d4ffce83826068aa00fd78212014fa1422dc46c0f33`,
and identical full private daily checksum
`30701fe697faca6098cb72c82c98b8b1fed8e9effeffa9190bc104cde643b61d`.
The read-only retention-aware release manifest returned
`CANDIDATE_ONLY` for 131 full days June 11–October 19, with
Total/Potential/Confirmed sessions [756,819, 86,956, 37,399], candidate
SHA `84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4`,
legacy SHA `61de508cb57292ca006f0beb7b535ec91d6ab84f9da1a9e2f9e0251a822bd38b`,
125 full legacy comparisons, no eligible late event, legacy public timer
inactive/disabled, distinct project rollup timer active/enabled, volume
38GiB available, Git clean at `97703819c7555bdead18a18d4806860f4c255fd8`.
This is sufficient evidence to *prepare* a publisher, **not** proof of
actual publication, complete source immutability, or a maintenance plan.

`scripts/public_audience_v2_atomic_publish.py` (candidate, source-only)
defaults to `PREVIEW_ONLY`. It validates both independent completed
checkpoint files and their exact source/private/candidate hashes. Preview
checks current legacy public audience table checksum without modifying
it. Its separately operator-approved `--apply` mode additionally checks
pinned clean code SHA, original complete frozen source and active visibility
rule identity, late event exclusion and source retention floor, active
project timer/disabled old timer, idle service and exclusive on-disk
project-rollup and canary locks. Inside a short `BEGIN IMMEDIATE`
transaction it performs a compare-and-swap against the exact 128-row
legacy matrix hash; first fsyncs a mode-0600 **complete old public table
preimage JSON backup**, then deletes/replaces only AoE2WAR's public
audience rows with the 131 certified full-day rows. It verifies the
131-row post-write SHA and commits once; any DB or backup failure rolls
back. Exact repeated publication returns an explicit no-op without
changing existing `updated_at`. Changed public data fails closed.

**HOLD:** no operator has authorized publishing the **narrower**
131-day window in place of requested May 22–Oct19 151 dates. Do not run
`--apply`, supply the approval phrase, restart the API, or activate a
timer without explicit authorization and an independently reviewed
VPS dry-run, original-row backup and rollback exercise. Existing
131-day candidate ends Oct19, and needs a separate correctly bounded
UTC completed-day incremental maintenance architecture before it may
be described as live/current. This publisher does not implement that
architecture. Missing raw days must remain **unknown**, not zero.

## First protected historical cutover: operator deployment and rollback

This source branch adds a standalone `scripts/public_audience_v2_atomic_rollback.py`
to restore the exact 128 historic prepublication rows and original
`updated_at` timestamps from the output `backup_file` JSON of the initial
cutover. Rollback verifies the whole private 0600 receipt (128 dates, source
matrix SHA, rows SHA, row types and historical range); requires explicit
`--approval-phrase 'RESTORE AOE2WAR PRE-PUBLICATION 128-DAY AUDIENCE'`,
pinned clean Git release, correct live database, good timer/resource state,
exclusive locks on canary and existing project rollup lock, and atomic
`BEGIN IMMEDIATE` compare-and-swap against the 131-day published
candidate SHA before restoring 128 exact old rows. It refuses to override
a subsequently updated/mismatched archive; repeat identical rollback is
read-only. This fallback deliberately restores the **stale 128-day archive**
rather than claiming that it repairs underlying live raw history.

The separate read-only
`scripts/public_audience_v2_verify_published.py` requires consistent
**131 dates with the exact approved daily checksum across the SQLite public
table, local FastAPI endpoint and AoE2WAR public JSON endpoint**
(`https://aoe2war.com/api/traffic/public`). It refuses absent dates,
duplicates, unverified partial days, hierarchy violations, wrong count
matrices and backend rows published before midnight at UTC end-of-day.
Successful output is `VERIFIED_PUBLISHED` and is not proof of the
long-term daily maintenance. The AoE2WAR Next.js `app/traffic/page.tsx`
loads this data dynamically from `lib/publicTraffic.ts`; neither
frontend source promotion nor traffic-api service restart is required
**provided** the live endpoint remains on the same configured SQLite
source and the public network response verifies it.

Operator steps must remain a two-paste workflow:
(1) fast-forward from the previously exact clean Traffic SHA, check
exact reviewed files, full unit tests on actual VPS venv, hold the old
public timer, verify the legitimate project timer, read-only manifest
and publisher PREVIEW, and record old/current candidate hash; (2) on
the explicitly operator-approved *narrower* 131-day historical window,
call publisher `--apply --approval-phrase` once while project worker is
idle, preserve printed `backup_file` path and receipt, and validate the
real DB/FastAPI/AoE2WAR web APIs using the read-only publication verifier.
The public API's cache may retain an old response for a short interval;
do not undo an otherwise valid SQLite publication merely because an
edge cache has not refreshed yet. Operator should inspect any stale
result and re-verify after cache expiry before deciding to rollback.

Do **not** enable the 06:15 failed legacy full-forge timer, do **not**
confuse the enabled 30-minute project rollup timer with audience
maintenance, and do **not** call June11–Oct19 a continuously current
traffic series until a separate source-equivalent 00:05 UTC completed-day
incremental maintenance mechanism is implemented, benchmarked and
production proven. A full-series backfill from a pruned 120-day raw
source will not reproduce the existing certified 131-day shadow history.

## Production historical cutover completed; Cloudflare urllib false-negative verification

On October 20 the operator performed the authorized one-time 131 complete-day
historical cutover against the exact pinned Traffic production code. SQLite
reported `COMMITTED`, wrote exactly 131 June11–October19 rows, and verified
the full published matrix digest
`84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4`.
The prior 128-row matrix SHA was
`61de508cb57292ca006f0beb7b535ec91d6ab84f9da1a9e2f9e0251a822bd38b`,
and the original mode-0600 rollback preimage remains
`canary-oocB0WuA/v2-public-audience-preimage-20261020T213655198475Z.json`.
The operator independently read all live SQLite published values, verified 131
correct UTC dates and totals [756819,86956,37399], and excluded October20
partial. `/traffic` returned HTTP 200; legitimate project worker timer stayed
active/enabled, old failed public forge timer inactive/disabled. No full replay
or public service restart was required.

The original three-layer verifier failed at HTTP **403** from the Cloudflare
public edge. Follow-up operator read-only diagnostics isolated the issue:
local canonical FastAPI returned HTTP200 with **all 131 dates and pinned
checksum PASS** for Python and curl; public AoE2WAR API returned
HTTP403 specifically to Python `urllib`, with header `Server: cloudflare`,
but curl from the same server returned HTTP200. Therefore the **database and
local backend are verified**, while curl's HTTP200 alone did not certify the
edge JSON. There was no evidence supporting rollback or republish.

The read-only verifier now uses narrowly scoped, HTTPS-only native curl for
the **exact** `https://aoe2war.com/api/traffic/public` endpoint, retaining
Python for the exact loopback FastAPI endpoint. It rejects redirects,
HTTP errors, excessive body size, invalid JSON, unexpected dates/counts,
and anything lacking the precise 131-day SHA match. This changes neither
Cloudflare settings nor the site; if edge JSON is stale or rejected,
verification still fails closed. Deploy just source changes and tests, then
require live `VERIFIED_PUBLISHED` before marking three-layer cutover closed.
Future completed-day maintenance is still outstanding in issue #31.

## Forward-only audience evidence ledger — explicit private shadow stage

The one-time historic audience recovery is **fully verified in production**
(131/131 days 2026-06-11..2026-10-19, SQLite + Traffic API + AoE2WAR
public JSON, 173/173 unit tests). The original V2 sealed source snapshot
had maximum rowid **44,247,247**, and end-exclusive timestamp
`2026-10-20T00:00:00Z`. Critically the snapshot high rowid was taken
*after* October 20 had already begun: events dated October 20 with
`rowid <= 44,247,247` were **intentionally excluded from the 131-day
historic calculation**. Therefore a naive incremental scanner starting
at `rowid > 44,247,247` would irretrievably lose early October20 events!

`scripts/public_audience_v2_forward_ledger.py` is a **PRIVATE input
evidence capture** for the separate #31 daily-maintenance effort. Its
bootstrap scans just the October20 timestamp window with the canonical
`idx_traffic_entries_timestamp_line_offset` keyset, restricted to rows
with the original rowid ceiling. Only when bootstrap is complete does it
switch to rowid-ordered seek from `rowid > 44,247,247` to capture
future/late source events. It uses the original canonical host and
browser/firehose selector and normalizer, sealed active visibility rules,
and the protected source identity. Accepted raw canonical inputs are
stored as private 0600 event JSON in an isolated SQLite evidence ledger,
never emitted in terminal output; state, raw-source digest and bounded
cursor commit atomically to permit crash-safe reruns. An **eligible**
later raw event timestamp earlier than October20 is a hard STOP rather
than silently revising the verified 131 historical days. The issuer
requires the historical checkpoint still PASS2_COMPLETE, original
canonical/host/visibility-policy signatures, unchanged public 131-day
matrix SHA, private directory/lock, idle independent rollup worker,
resource-safe row cap <=10k and explicit `--approve-private-write`.
Default CLI invocation is read-only. No writes at all to the original
source DB, audience/public tables, financial tables or systemd config.

**IMPORTANT SCOPE**: This ledger is *input preservation*, NOT daily
human-session classification, complete-day eligibility certification,
or permission to publish a new day. It does not run itself on a timer.
It makes the future semantic work safer by retaining original normalized
event inputs before the live 120-day raw retention removes them.
The next steps still require exactly the original canonical global
host/IP behaviour, 30min cross-day sessionization, 60sec burst collapse,
full-day watermark and lateness proof, independent two-day shadow parity,
and a separate guarded atomic next-day publisher. The historic 131-day
hash and old 128-day rollback receipt remain untouched. **Do not enable
the failed full-history forge timer.** The consumer cannot claim daily
audience data is current until the new worker is proven and enabled.

Manual, source-only VPS preflight after a pinned code release:
`python -m scripts.public_audience_v2_forward_ledger --source <traffic-db>
--checkpoint <completed-checkpoint> --ledger <private-future-ledger>`
(default: proof only, no file creation). Each explicit 10k-row-or-smaller
`--advance --approve-private-write` captures at most one bounded page,
prints aggregate counters only, and returns `publish_authorized=false`.
Review counts/budgets/host idle before further calls. Never automatically
loop over thousands of pages or enable an untested timer.

## Optional safe automatic forward evidence capture (NOT audience publication)

The private source-preservation phase adds two opt-in systemd units:
`ops/systemd/traffic-v2-forward-ledger-aoe2hdbets.service` and `.timer`.
The service runs a **single 3,000-row / 12-second budget** step every
roughly five minutes, with hardened read-only host filesystem and only the
0600 private canary directory writable, resource limits and a shared
canary lock; the run requires original 131-day published matrix SHA,
completed historical checkpoint and original active policy identity.
The service is executed as root solely because the established private
0600 completed checkpoint and its canary directory are root-operated;
hardened systemd mount sandbox confines writes to the private canary path.
It does not touch public tables or enable/restart the failed legacy forge.
The SQL remains read-only against the source and only appends private
canonical event evidence in `future-ledger.sqlite3`. Timer unit defaults
disabled/inactive until a separate manually observed one-step success
plus source-read-only audit confirms systemd sandbox compatibility.

**This timer is NOT THE DAILY AUDIENCE MAINTENANCE WORKER**. Only private
input preservation becomes automatic; calendar/day selection, exact
global IP behaviour, cross-day sessions, 60-second distributed burst
handling, and certified incremental publication remain open #31.
Do not show the public graph as fresh because this timer ran. Preserve
old public timer disabled/inactive and independent project rollup timer
active/enabled. When `future-ledger` command catches an eligible late
source event before October20, it fails closed and requires an explicit
evidence reconciliation, never inventing data or altering certified
131-day values.

## Resolved WAL sandbox diagnosis (release gate for PRIVATE capture only)

The VPS operator reproduced the strict sandbox failure with the live
`traffic_history.sqlite3` using SQLite `mode=ro`: its first attempted
read failed with an SQLite "unable to open database file" error when
only the canary directory was writable. Private checkpoint, ledger and
canary write probes succeeded. The original source is WAL mode, and a
separate probe confirmed its `-shm` auxiliary file was **absent**. An
exception for an existing `-shm` file alone is therefore not a stable
solution (closed/unmerged draft PR #35). SQLite can create/remove
`-wal` and `-shm` when its last connection closes.

A later *actual VPS* ephemeral same-sandbox probe added
`ReadWritePaths=<private-canary> <traffic-db-dir>` and
`ReadOnlyPaths=<traffic_history.sqlite3> -<traffic_history.sqlite3-wal>`.
This **PASSED**, including an explicit `os.open(main.db, O_WRONLY)`
**DENIED**, actual `PRAGMA journal_mode=wal` and a read of **131**
published public days. It made no audience updates, changed no permanent
service settings, and confirmed the private timer remained disabled.

The production candidate service now mirrors that observed config. The
explicit scope tradeoff: source directory is writable in the *service's
private mount namespace* so SQLite can manage transient WAL sidecars;
the primary DB file is read-only, and `-wal` is read-only **only if
present when the namespace mounts are constructed**. If `-wal` is
absent or recreated later, this mount rule is NOT a continuous filename
write-protection guarantee; this is a residual risk. SQLite itself opens
the live source as `mode=ro` and `PRAGMA query_only=ON`. The service
can write only its private ledger via application SQL. A stricter future
architecture would isolate WAL coordination in a separately controlled
reader namespace or service, avoiding directory-wide write mounts.

Any operator promoting this candidate MUST pin source Git SHA,
review/verify exact service-file contents and temporary unit
`systemd-analyze verify`, replace only the installed private service
unit, explicitly confirm the timer inactive/disabled, perform
`systemctl daemon-reload`, `systemctl reset-failed`, and ONE
`systemctl start ...service` with an inspected JSON journal receipt,
then run independent three-layer public 131-day SHA verifier.
Only after a successful hardened service test and reviewed risks may
the operator explicitly enable the PRIVATE 5-minute source-capture
timer. The main 131-day audience counts and timer remain unchanged;
automatic canonical day publication is a distinct unfinished task #31.

## 2026-10-20 23:26 UTC — private timer recurs normally, forward readiness remains provisional

Production at `786664a2f6b8a3290e6b3f2f3d14fe61afb6a1a6`
confirmed private evidence capture timer `ActiveState=active`,
`SubState=waiting`, `UnitFileState=enabled`, last triggered
`23:24:15 UTC`, **next scheduled `23:29:27 UTC`**. Service was
successfully executed at `23:24:16 UTC` and retained another 3,000
source events, for 9,000 cumulative private events, mode 0600.
Original 131-day historical site/API/checksum remained
`VERIFIED_PUBLISHED` and old forge timer stays disabled. The earlier
`NextElapseUSecMonotonic=infinity` displayed immediately after
activation resolved once the first service completed; no timer fix needed.

The new `scripts/public_audience_v2_forward_readiness.py` is a
READ-ONLY audit of the protected source, full historical checkpoint,
private ledger and sealed historical public-day checksum. It verifies
ledger metadata, number of retained events, canonical source identity
and bound timestamp-index date range. While `BOOTSTRAP`, live row-ID
scan coverage is explicitly **unknown**; once phase becomes `LIVE`,
the tool reports an **unscanned row-ID span upper bound**, *not a count
of eligible events or an ingestion lateness guarantee*. It cannot
declare any full UTC day complete or authorize new-day publication.
Errors fail closed. This is a manual audit/check utility, not a new
worker, and does not modify systemd units or public SQLite tables.

Manual example once merged and deployed:
```bash
.venv/bin/python3 -m scripts.public_audience_v2_forward_readiness \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3
```

## Private canonical global-IP behaviour — future PASS1 shadow

`scripts/public_audience_v2_forward_ip_shadow.py` is the next
incremental building block of issue #31. It updates a separate private
`future-ip-shadow.sqlite3` (0600) with counts, distinct browser user
agents, distinct normalized paths and direct-referrer counts for
**canonical accepted future input events** preserved in
`future-ledger.sqlite3`. State updates are bounded (default 3,000
events), transactional, crash-resumable and guarded by the same exclusive
canary lock as the evidence collector, with the historical source
checkpoint, canonical rule/code/host hashes, and unchanged public 131-day
checksum reverified before processing. No published daily counts or
source raw entries are ever written by this tool.

**Critical ordering barrier:** the forward-ledger BOOTSTRAP scans input
in timestamp order and may append older source row IDs after newer
ones. A durable `WHERE source_rowid > cursor` checkpoint is not safe
until the future collector has completed that bootstrap. Therefore the
new program's default (read-only) status is
`BLOCKED_BOOTSTRAP`, and `--advance` **fails closed** until forward
metadata says `phase=LIVE`. Once phase=LIVE, all pre-cutoff source
row IDs have been captured and subsequent capture is exclusively in
ascending source row ID. The shadow can then use idempotent bounded
rowid pagination without skipping input events. **Never override this
gate**, including to make a new day appear on the graph sooner.

The actual canonical IP behaviour for a future shadow epoch is the
**union** of distinct historical+future user agents and paths, while
additive request/referrer counts sum. This is not the same as adding
the two epochs' unique-UA and unique-path cardinalities. The sealed
historical pass-one tables stay immutable; helper
`merged_ip_behavior(historical, future, host, ip)` implements that
union and the original framework-route-spam heuristic. The helper is
for privately validated classification code and must never output
identifiable host/IP/UA/path details in production receipts.
Global IP behaviour may reclassify historical sessions when future
inputs arrive: preserve the certified 131-day sealed contract rather
than silently revising those days. A fully retroactive canonical
counterfactual is NOT yet proven.

To inspect safely after deployment (defaults to readonly):
```bash
.venv/bin/python3 -m scripts.public_audience_v2_forward_ip_shadow \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
  --shadow /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ip-shadow.sqlite3
```

After the read-only result is `READY_PRIVATE_PASS1`, explicit
`--advance --approve-private-write --max-rows 3000` processes exactly
one private bounded batch. Do **not** schedule this tool automatically
until shadow/backlog behaviour, performance, resource reserves and
canonical parity fixtures have been independently reviewed.
This is **not** a full future-day session processor, UTC-day
completeness test, or public publisher: cross-midnight 30-minute
sessions, 60-second burst collapse, fixed-now identity semantics and
late-ingest/dedup proofs still precede any daily publication.

## 2026-10-21 — bounded manual IP shadow catch-up after first real pass-one success

Operator observed `future-ledger.sqlite3` at LIVE with 108,764
retained eligible events. The first private canonical IP pass-one
(3,000 event cap) succeeded in production at Traffic SHA
`9c0457fea7b2d31456091a57b29c03e78437002a`; private shadow
`PRAGMA integrity_check=ok`, 3,000 processed, SUM(requests)=3,000,
private file mode 0600, row-ID cursor 44,130,669 and 105,764 retained
events remaining as of the observation. Independent historical audience
verifier still returned VERIFIED_PUBLISHED, 131 days, SHA
`84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4`.
Source collector timer remained scheduled; this did NOT produce any
complete UTC daily audience bucket.

`scripts/public_audience_v2_forward_ip_supervisor.py` provides
strictly **operator-invoked** bounded private pass-one catch-up.
It launches the existing individually bounded 3,000-event shadow
command as a child for up to eight steps (operator caps ≤16), under
a 120-second default wall budget (hard max 300s) and 25-second default
child timeout (hard max 40s). Each subprocess independently enforces
the shared private canary lock, project-worker priority, frozen
historical checkpoint, canonical visibility rules and source identity
and the private ledger LIVE phase. The supervisor itself checks exact
pin SHA/clean checkout, working public/project/private timer states,
worker idle, and minimum free disk reserves before each batch. A
failure/timeout aborts immediately; previously committed private
steps remain restartable. Every step prints only aggregate JSON,
not IPs, user agents, visitor details or raw source events. It reports
caught-up, max-steps or time-budget stop, never an audience bucket,
API value or publication authorization.

Example **after the supervisor release is merged, VPS test-certified and
the operator has explicitly verified current LIVE/PRIVATE_ONLY status**:
```bash
.venv/bin/python3 -m scripts.public_audience_v2_forward_ip_supervisor \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
  --shadow /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ip-shadow.sqlite3 \
  --require-sha <PINNED_APPROVED_RELEASE_SHA> \
  --max-steps 8 --max-rows 3000 --wall-seconds 120 --step-timeout 25
```

The supervisor is **not installed as a new timer**, never modifies the
working private collector, never authorizes new public audience days
and never substitutes request totals for human sessions. Exact session
parity, cross-UTC-midnight closure, retroactive global IP effects,
60-second distributed burst collapse, and delayed ingestion watermark
certification remain required before the public daily publisher.

## Independent future pass-one IP evidence parity — read-only

The private `public_audience_v2_forward_ip_parity` inspector verifies
the exact normalized input prefix which the private IP shadow claims
to have consumed. It independently reads saved events from
`future-ledger.sqlite3`, re-applies the pinned canonical normalizer
and visibility policy, and compares **each** `(host,ip)` request and
direct-referrer count against the shadow plus all distinct user-agent
and normalized-path set members in both directions. It reports
**aggregate counts only**, never IPs, UAs, paths or visitor IDs. It
does not authorize daily visitor totals or rewrite the certified archive.

It requires LIVE input, matching original private checkpoint/source
identity and the 131-day public checksum, strict 0600 files,
a protected directory, and a stable exclusive private canary lock.
Default event cap 100k, hard limit 200k. When testing later larger
prefixes set `--max-events 200000` and apply a wall timeout at
the operator terminal. This comparison is a memory-bounded-by-cap
single-prefix audit, NOT a timer, not full session parity and not a
public publisher. The existing 5-minute private input capture timer
continues independently.

Sample read-only operator command (after reviewed source deployment):
```bash
sudo timeout -k 5s 60s .venv/bin/python3 \
  -m scripts.public_audience_v2_forward_ip_parity \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
  --shadow /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ip-shadow.sqlite3 \
  --max-events 200000
```
If the canary lock is held by an active collector, the inspector
stops safely and should be retried when no writer is active. Do not
increase the event cap just to make a failing check green; any
mismatch must be investigated before downstream sessionization.

## Next stage: read-only canonical future-session preview (NOT PUBLICATION)

October 21 independent VPS data proved the first **129,980 retained future
events** matched their private pass-one global IP evidence, actor-by-actor:
3,635 actor records, 4,402 distinct UA records, and 16,074 distinct
path records. VPS tests 221/221, private input/actor parity
`PRIVATE_CANONICAL_IP_PARITY_VERIFIED`. Original public 131 days stay
pinned through October 19 (sha
`84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4`).

`scripts.public_audience_v2_future_session_preview` is an
operator-invoked **read-only candidate-only** replay. It takes the
private IP shadow's exact durable source-row-ID prefix, matches that
prefix to the saved future evidence and reuses historical canonical
`normalize_row`, `build_single_session`,
`finalize_bucket` and `collapse_distributed_bursts` through the
unchanged canonical helpers. The replay sorts by
`(timestamp, line_offset, source_rowid)`, NOT by row-ID; maintains
`(host, IP, lower-case user agent)` sessions and the exact 30-minute
expiry inequality; collapses each 60-second burst only when all
sessions in its bucket are finalized. Global IP behavior is the
**distinct-set union** of frozen original history and processed future
pass one, with summed request/direct counts. The latter may affect
earlier classification as more inputs arrive.

The operator's current-day bucket is never included. Any previous
UTC-calendar-day values are printed as
`unverified_past_calendar_day_candidates` **solely for engineering
inspection**. The output contains only aggregates, no individual IP,
user agent, path, or visitor IDs. No SQLite writes, no new systemd
service, no change to published API, and no authorization to publish.

Safe manual example, from existing `tony` VPS terminal with `sudo`
(no `set -e`, nested SSH or interactive shell exit):
```bash
sudo nice -n 10 timeout -k 5s 65s .venv/bin/python3 \
  -m scripts.public_audience_v2_future_session_preview \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
  --shadow /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ip-shadow.sqlite3 \
  --max-events 160000 --budget-seconds 40
```

The explicit preview caps are ≤200,000 events, ≤45s wall time,
≤30,000 open sessions and ≤20,000 events per session. If it cannot
honor these limits, if the private canary lock is busy, if the project
worker needs priority, or if source/policy/checkpoint identities
diverge, it stops without modifying production.

**Still blocking public daily publication:** prove per-day independent
A/B parity with the original canonical algorithm; decide how sealed
October 19 sessions continuing into October 20 affect historical
immutability; certify late arrivals/insertion ordering, source ingestion
watermarks, and day-end 30-minute expiry; confirm exact burst-collapsed
semantics over more than one fully completed UTC day. This tool is
NOT a day certifier, session parity attestor, or automatic publisher.

## Live candidate safety stop — continuous sessions larger than 20,000 events

On 2026-10-21, production Traffic release
`cb55994af4abb37683a7350a594563d7f1791ebc` passed
all **230/230** VPS regression tests. The initial operator-only,
read-only future session preview safely stopped with
`STOP: future session exceeds bounded event limit`.
No public audience or private input data was modified.
The original sealed 131-day historical publication remained
`VERIFIED_PUBLISHED` through 2026-10-19, checksum
`84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4`.

Do NOT simply increase `MAX_SESSION_EVENTS=20_000` or split a session
arbitrarily; the historical 30-minute inactivity-gap definition
determines session boundaries. A continuous machine-origin stream can
legitimately have more than 20,000 raw canonical events for one actor,
yet must still be treated by the original classifier and burst rules.

Use the new `--inspect-session-sizes` option **before any future
classifier changes**. It runs the same sealed checkpoint/source/ledger/
private-shadow read-only preflight and original input ordering, but
tracks only one bounded-size counter and two timestamps per host/IP/UA
identity; it does not retain full event payloads, build sessions,
inspect per-IP output, or assign calendar-day visitors.
It reports the largest five **counts only**, how many sessions exceed
20,000/50,000 events, cross-midnight session chains, and input count.
No actor identifiers are printed or stored. It holds the private
canary lock for its bounded scan and yields priority to the project worker.

Existing `tony` VPS SSH shell (root-owned repo; use sudo; do not
run `set -e`, `exit`, nested SSH wrappers, or permission changes):

```bash
sudo nice -n 10 timeout -k 5s 65s .venv/bin/python3 \
  -m scripts.public_audience_v2_future_session_preview \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
  --shadow /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ip-shadow.sqlite3 \
  --max-events 160000 --budget-seconds 40 --inspect-session-sizes
```

Any >20k actor session remains UNCLASSIFIED until a reviewed streaming/
segmented canonical equivalent is proven; the size diagnostic itself
does not count real humans, authorize publication, prove midnight
completeness or substitute for the two-day canonical A/B gate.

## 2026-10-21: measured oversized canonical sessions and memory-only segmentation

The read-only production diagnostic on VPS Traffic release
`a55bd45f06facf9c398513ab016340d10a672176` completed
**237/237 tests** and inspected a pinned pass-one prefix of
**129,980 saved canonical inputs** (source captured 142,877; private
IP prefix backlog 12,897 at that sample). It identified **7,304**
exact 30-minute inactivity-gap actor sessions, **51** continuing across
UTC midnight and top-five lengths **29,016; 26,863; 13,893; 13,849;
12,472**. Exactly **two** sessions exceeded 20,000 events; none
exceeded 50,000. All data were anonymized aggregates, and the original
131-day public checksum was again VERIFIED_PUBLISHED unchanged.

The prior preview's 20,000 raw-event per-session guard was a
resource bound, not canonical visitor semantics. Rather than truncate
or pretend a long-running script is multiple visitors, the private
preview now uses **ephemeral SQLite `:memory:` only**, storing
canonical event payloads in **256-event chunks**, using the same
serializer and decoder as the sealed historical checkpoint.
Every session remains one `(host, IP, lowercase UA)` inactivity-gap
chain. On exact canonical closure, the preview reconstructs **all**
of that actor's events, calls the *unchanged*
`canonical.build_single_session` and then
`canonical.finalize_bucket` for original 60-second distributed burst
logic; it deletes the temporary in-memory chunks on close. It never
changes the original `SESSION_GAP_MINUTES`, known-bot rules,
confidence thresholds, source day ownership or recorded public
archive. The total 200,000-event source cap, 30,000 active-session
limit, full-bucket bound, time budget and private canary lock remain
hard fail-closed limits. This is a temporary classification working
space **only**; no temp files, source writes, private persistent
session-state changes or public writes.

Unit fixtures include real measured maximum **29,016** and second
largest **26,863** lengths, 30-minute equality at midnight,
UA partition isolation, no source-file writes and time-limit failure.
The live preview may still stop at a performance bound and then must
be profiled, never force-run unbounded.

This preview **does not certify** Oct20/Oct21 audience figures:
the exact October 19/20 historical boundary, independent canonical
parity, late/backdated ingestion evidence, global-IP future retroactivity
and publication atomicity remain open. Only after those barriers are
proved can the public completed-day timer be enabled.

## 2026-10-21 — independent A/B comparison to original canonical stream_sessions

Operator VPS `87e76db0623bc6f5db680db0a9bb72127d81f620`
passed **243/243** tests. The input ledger and private global-IP
pass-one caught up to **145,877** retained events; the future readonly
segmented session replay completed successfully with **8,135** logical
sessions, **6,996** page sessions, max chain **33,586** events,
**491** memory-only 256-event segments. The private Oct20 2026 UTC
candidate was `[5800,140,39]` for total page sessions / likely
humans / confirmed humans. These numbers remain **NOT certified** and
**NOT published**. The original 131-day public archive is still
VERIFIED_PUBLISHED SHA
`84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4`.

Use `--compare-historical-stream` (after reviewed/CI-tested release)
to compare the preview *against the original, unchanged*
`rebuild_public_audience_archive.stream_sessions` implementation on
the **same** exact frozen private input prefix and same pinned source
visibility policy. This is an independent session aggregation path:
it rebuilds the original behavior map using the separate original
history + verified future global-IP shadow and replays original
inactivity-gapped actor grouping and distributed burst finalizer.
A scoped test/mock context redirects *only the in-process reference*
source iterator to the readonly future event ledger; it does not
change any production file, globally installed service, database
connection or scheduler. The original code function objects are
restored before the standalone process exits.

A/B requires exact equality of full provisional daily counts
(including the incomplete current day for comparison only), accepted
event counts, total logical sessions and page sessions. A mismatch
fails closed and prints no raw identifiers. Inputs remain restricted
to 200k accepted events and the worker/canary-lock priority. This
comparison is allowed an explicitly requested <=100s application
budget because it computes two separate full classifications; run
it under lower CPU priority and a bounded process timeout:

```bash
sudo nice -n 10 timeout -k 5s 125s .venv/bin/python3 \
  -m scripts.public_audience_v2_future_session_preview \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
  --shadow /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ip-shadow.sqlite3 \
  --max-events 200000 --budget-seconds 100 \
  --compare-historical-stream
```

Success indicates **classification parity for the frozen future
prefix only**, not immutable historical Oct19-to-Oct20 session
boundary parity or day completeness. The published Oct19 release
cannot be rewritten; future source row-ID inserts may be backdated,
and the input collector continues changing global-IP behavior.
The independent ingestion-lateness certificate, two full UTC
days and atomic publisher remain explicitly blocked.

## 2026-10-21 — cross-epoch midnight actor-continuity release gate

The operator ran production commit
`1b87b7f70691310632bf8829b7fcc70eced16493`:
**248/248** VPS regression tests PASS; independent
`PRIVATE_CANONICAL_IP_PARITY_VERIFIED` on **145,877** source events
(3,873 actors / 4,796 UAs / 18,465 paths); and independent
`PRIVATE_FUTURE_SESSION_AB_PARITY_VERIFIED` against the
original unchanged canonical `stream_sessions` for the same prefix,
including **8,135 sessions**, **6,996 page sessions**, and full daily
classification triples for both represented UTC dates. October 20's
provisional triple remained `[5800,140,39]`.
The sealed public historical series, **131 days through 2026-10-19**,
was independently reverified with unchanged checksum
`84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4`.
**These proofs do not certify finality or permit publication**.

The immutable prior recovery deliberately stops at
`2026-10-20T00:00:00+00:00`. A canonical session can continue across
that midnight when the same **host, IP and lowercase user agent** has
its final historical event and first future event separated by **at
most 30 minutes**. The historic rollup's end-of-input close then
creates a potentially artificial session split at the release
boundary. This must be checked rather than silently double-counting
or altering the already published 131 days.

`scripts.public_audience_v2_forward_boundary_audit` performs a
bounded readonly scan of the final 30 minutes of the sealed raw
source **under its frozen row-ID watermark** and the first 30 minutes
of the saved future private ledger **under the shadow's processed
row-ID prefix**. It applies the same authenticated canonical
host selection, firehose source predicate, normalizer and visibility
rules. For each exact normalized actor identity it keeps only the
last historical timestamp and first future timestamp, compares the
exact 30-minute inactivity condition (including equality), and emits
only anonymous aggregate evidence. Both streams have hard
untruncated 20,000-row defaults, hard cap 100,000, <=45 seconds app
budget, exclusive private canary lock and project-worker priority.

Existing `tony` VPS shell, root-owned repo, **no `set -e` or nested SSH**:
```bash
sudo nice -n 10 timeout -k 5s 65s .venv/bin/python3 \
  -m scripts.public_audience_v2_forward_boundary_audit \
  --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
  --checkpoint /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
  --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
  --shadow /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ip-shadow.sqlite3 \
  --max-rows 20000 --budget-seconds 40
```

A result of `canonical_session_continuations: 0` means **only**
that no cross-epoch actor continued in the sampled, frozen input
prefix. A nonzero result is an explicit cross-release semantic
blocker. Either result remains `historical_cross_epoch_day_certified:
false` and `publication_authorized:false`. Later forward source
row-ID inserts with backdated timestamps may change the result;
the private shadow can temporarily trail capture. A separate
event-ingestion-lateness/finality policy and at least two consecutive
independently completed UTC days are still necessary. Do not
change any existing published date or enable any public timer.
