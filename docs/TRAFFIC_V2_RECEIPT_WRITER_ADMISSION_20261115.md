# Traffic V2 — exact protected insertion-receipt writer admission

STATUS: SOURCE-ONLY REVIEW CANDIDATE. No installer, no permit, no host mutation.

## Actual HEL1 installed preimage, independently read at 2026-11-15 22:55–23:04 UTC

- Traffic ingest service /etc/systemd/system/traffic-ingest.service: SHA256 ae9a923682906032343b96fb33c62ab61ed3a40c20e5d4755a78cddbb83dbac9; root:root 0644.
- Ingestion timer: c78379c9a44e2980ff3285d2b93785c0b949ea88efc3a28ea080e33b6b4441e0; root:root 0644; active and enabled, unchanged two-minute cadence.
- Persistence Python: 9863f6b6eae5986793d355486612b63ddf058624e627acac34d8303907e017e5; root:root 0644. It contains a guarded opt-in SQLite INSERT-time timestamp, preserving existing NULL.
- Ingestion script: 1c65870461abf1c16c6067e5b93dffde03923a5e57ac066a11b1e4d3f42a615d; UID1000/GID1000 0664, protected byte fingerprint retained without chmod.
- Steam V27: 2695a5b5fb4adf9e17afbb30c535158260608b8ba60e13fea4b2e4da29e974ca; root:root 0700.
- Steam root pinned source: 9799d8c9042dbd1875a2096ee1df6b8751347206cf8761d695aecf1e61894707; root:root 0644.
- /etc/traffic-api.env is UID1000/GID1000 0600; the read-only preflight checked that the flag is not defined. Do NOT print the environment file.
- Original effective service uses one UID/GID tony systemd oneshot and original /usr/bin/flock -n -E 75 /run/traffic-ingest/sync.lock to scripts/sync_traffic_logs.py, with PrivateNetwork=yes, NoNewPrivileges=yes, ProtectSystem=strict, no capabilities, and inaccessible PostgreSQL paths.
- Traffic ingest timer active/enabled, legacy full-history audience publisher timer disabled/inactive, no Traffic ingest service drop-ins, Steam V27 last ExecMainStatus=0 success.
- Actual source installed on HEL1 still SHA 60cf4da5962b4ba65f546d2bea68c3cdc03e8479. Existing working production service and website remain untouched.

The proposed one-file postimage is EXACTLY the UTF-8 payload (including a final newline):

    [Service]
    Environment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1

Only proposed path: /etc/systemd/system/traffic-ingest.service.d/90-traffic-v2-insertion-receipts-only.conf.
Expected SHA256 f9a50e57fad5d9f562cafc2b89dde9c7e403f48300d5833871168ab03fc879fe.
Preimage: ABSENT. This must not change ExecStart, service sandbox, timer, original source bytes, historical timestamps or financial permissions.

## Independent review and strictly authorized installation

Only WE1/C03 financial-protected service census, B/Steam V27 source-bound reviewer and the authorized Traffic data-plane root operator can admit the exact proposed delta. November 8 showed that a different Steam V7 saved protected snapshot failed after the service flag trial and was properly rolled back. Current Steam V27 code uses a different guard path and no longer directly invokes the old full-unit production_protected() scan, but independent C03 baseline compatibility is NOT implied. The reviewers must physically compare the old and proposed effective unit config/fingerprints and approve a new exact protected footprint; no signature or approval is presumed here.

Source-only script scripts/public_audience_v2_receipt_writer_admission.py has two modes: --phase review-only and --phase inspect-live. The latter reads the six exact installed file hashes, permissions, current loaded systemd command/flag/Steam/timers and old environment file without revealing secrets. Neither mode writes or activates; both intentionally return exit status 2 with install_authorized=false, even on fully matching preimage.

Post-approval operator sequence: verify unchanged preimage, independent signed scope and C03/Steam new accepted fingerprint; acquire existing Traffic root service lock and ensure no concurrent writer; atomically add only the exact root:root 0644 drop-in; daemon-reload and verify exact one-variable effective difference, original timer/flock/sandbox unchanged. Run the independently authorized Steam/C03 negative and positive guarded tests BEFORE accepting any newly instrumented writer execution. If a protection check fails, execute the reviewed inverse immediately and verify original native loaded config and Steam status.

Then allow one monitored normal ingest via original systemd single-writer flock (not a new service or competing process), require a real newly inserted record with a naturally recorded non-NULL insertion time, no interpolated/backfilled NULL, no new recent holes/negative clock, no duplicate active writer, Steam V27 refreshed success, C03 independent snapshot, 8092–8095 closed, FINANCIAL masks intact, 3030/3032/3033/9447 preserved, canonical 131-day audience digest unchanged. If no new logs arrived, this evidence is INCONCLUSIVE rather than PASS.

The tested source-only inverse gate accepts removal ONLY when the added drop-in has precisely hash f9a50e57fad5d9f562cafc2b89dde9c7e403f48300d5833871168ab03fc879fe, original preimage was ABSENT, and the original service/timer SHAs still match. Only the genuine separately permitted root executor may remove the single exact drop-in and daemon-reload, then verify Steam, original loaded unit/ports and audit receipts. No backfill, deletion of naturally inserted row receipts or user filesystem cleanup is authorized.

## Separate bounded high-volume daily-certification design — NOT a new runtime in this PR

Keep draft PR #73's 20,000 candidate source rows PER DAY ceiling and 45-second budget unchanged. It is a fail-closed negative evidence gate; a large day MUST safely stop, not be interpreted as complete or as zero visitors.

A future independent source PR needs a separately checkpointed full-day path with at most 20,000 rows PER PAGE, bounded memory/runtime and worker/canary locks. Keyset must be exact canonical event order (timestamp, line_offset, rowid), never the append-only forward-ledger rowid order. Anchor each private checkpoint to immutable source inode/epoch/policy fingerprint, pinned high rowid, first/last keyset tuple, page event digest, append-chain total and original 131-day public seal. Commit private page and source cursor atomically. On restart verify previous checksum/source prefix; reject duplicates, skipped tie rows, source rewind, changed rules, late insertions or changed protected history.

A completed day is publishable only after the entire day range and required cross-midnight carry have been scanned; upstream Nginx log delivery and insertion completeness are independently proven; original global-IP classification, 30-minute sessions, 60-second burst collapse, bot/visibility rules and retroactive effects have exact A/B parity; and a definitive late-arrival watermark closes the day. Recompute affected UNSEALED days if classification changes, but never alter immutable Jun11–Oct19 history. Require two actually consecutive fully closed UTC days with independently witnessed source and canonical audience matrix. Another separately authorized atomic publisher must preserve immutable preimage, compare-and-swap source hash, transactional append/rollback/idempotence and bounded catch-up under the existing shared worker lock. The legacy full-history timer stays disabled.

One or more historical NULLs existed on every Oct20–Nov14 date in actual source observations. A new receipt flag cannot reconstruct these historical unknowns. Their Total/Potential/Confirmed counts remain UNVERIFIED until genuine independent log delivery and provenance recovery supports certifying them. Never substitute project daily visitor rollups or fabricate historical insertion times.

No website rebuild/deployment or new Traffic backend installation is needed for this source-only review candidate.

## Real single-raw-writer API isolation witness

The live traffic-api.service is active, PID 1562 at 23:07 UTC,
with effective Environment=TRAFFIC_DISABLE_INLINE_INGEST=1,
NeedDaemonReload=no and no traffic ingestion enabled in its environment.
The original API unit fragment SHA256 is
fbb43b0d050cb3894bb7099aa71a5076f8996f59c6f3ccf7c80a28ef2d5efa40
and its approved 60-inline-ingest-handoff.conf is
257edd0bfc86039255a955297f2e51bff6144daa0c644e136dcc34dd525eca7f.
The entire effective systemctl cat traffic-api.service SHA256 is
ef5f7b2b0b64611dbb136ef2def4e0264acdb44ce0868100194792acf10b85cb.
The Python persistence.inline_log_sync_disabled() checks that exact
TRAFFIC_DISABLE_INLINE_INGEST flag. That is why the scheduled original
Traffic ingest one-shot remains the sole intended raw-log writer;
the private daily-rollup worker is separate and uses its own flock.
The read-only source-only admission preflight now pins all THREE API
artifacts and the effective flag and PID before accepting the proposed
ingest-only service diff. If API inline sync becomes reenabled or the
pinned source changes, the admission MUST refuse to proceed rather than
risk a second writer or only partially instrumenting insertions.
