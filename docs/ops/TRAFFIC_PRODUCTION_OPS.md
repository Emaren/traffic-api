# Traffic Production Ops

## Services

- traffic-api.service: FastAPI on 127.0.0.1:3345
- traffic-web.service: Next.js on 127.0.0.1:3045
- traffic-watchdog.timer: checks local/public web, API health, and archive endpoint every 2 minutes
- traffic-session-archive-aoe2hdbets.timer: rebuilds AoE2 War session archive every 30 minutes
- traffic-project-daily-rollups-aoe2hdbets.timer: incrementally refreshes bounded AoE2 War daily rollups
- traffic-public-audience-aoe2hdbets.timer: LEGACY FULL-HISTORY FORGE; intentionally DISABLED since the 2026-10-15 2-hour timeout (18M+ raw rows). Do not enable without new audited release.

## Important paths

- API repo: /var/www/Traffic/traffic-api
- Web repo: /var/www/Traffic/traffic-app
- Ops scripts: /var/www/Traffic/ops
- Traffic DB: /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3

## Canonical AoE2 War publication-age observer (read-only)

The API healthz, ingestion timer and every-30-minute project rollup **do not
certify** the separate canonical audience series. The legacy full-history
publisher is intentionally disabled. Do not mark the public chart healthy
merely because the endpoint returns HTTP 200 or recent filtered GET/IP
observations exist.

Run the source-only, loopback-only observer after a source review:

    .venv/bin/python3 -I -B scripts/public_audience_v2_publication_freshness.py --phase observe

It checks only the exact AoE2HDBets public-audience-series HTTP endpoint on
127.0.0.1:3345 and the read-only systemd state of
traffic-public-audience-aoe2hdbets.timer. It validates published UTC dates,
completed-day timestamps, monotonic gap-free daily rows, exact project
identity, nonnegative Total/Potential/Confirmed hierarchy and coverage
metadata. It flags an archive more than two UTC days old as
HOLD_CANONICAL_ARCHIVE_STALE (exit code 3), **even with a healthy HTTP 200**.
It also holds on an unreviewed legacy timer activation or corrupt data. A
non-stale observation is *not* canonical source/ingestion/financial certification.

Actual HEL1 read-only observation at Nov 8 2026 ~02:40 UTC returned:
age_utc_days=20, last_published_utc_day=2026-10-19,
reported_days=131, archive_calculated_at=2026-10-20T21:36:55.213038+00:00,
legacy_full_history_forge_timer=INACTIVE_DISABLED_INTENTIONAL_HOLD and
status=HOLD_CANONICAL_ARCHIVE_STALE, exit code 3.
This observer has **no publication, restart, timer enable, SQLite write,
raw visitor identity export or financial authorization capability**.

The unresolved corrective work remains Traffic issue #31: coherent private
offhost source backup, genuine remote log-delivery/receipt lateness bounds,
global IP/cross-midnight session equivalence, two independently certified
closed days, bounded atomic publisher with rollback, and a separate approved
America/Edmonton-local delayed-catch-up schedule. Never substitute observed
GET/IP totals for canonical three-series human sessions.

## Fast archive path

The all-time human-visible AoE2 War visit archive is served from:

- SQLite table: traffic_session_archive
- Rebuild script: scripts/rebuild_session_archive.py
- Timer: traffic-session-archive-aoe2hdbets.timer

Manual rebuild:

    cd /var/www/Traffic/traffic-api
    .venv/bin/python3 scripts/rebuild_session_archive.py --project aoe2hdbets --replace

Smoke test:

    curl -sS -m 10 https://traffic.tokentap.ca/api/healthz
    curl -sS -m 20 "https://traffic.tokentap.ca/api/visits/history?limit=25&classification=human_visible&projects=aoe2hdbets&range_key=all&offset=0"

Expected archive response:

- ok: true
- coverage_mode: session_archive

## Canonical public-audience forge — HELD since 2026-10-15

**P1 incident:** [traffic-api #10](https://github.com/Emaren/traffic-api/issues/10). The operator intentionally disabled the legacy daily timer after the full-history job exceeded two hours. The checked-in legacy timer is documentation of its prior schedule, NOT deployment authorization. Source-only fixes for UTC daily boundary and V2 shadow checkpoints do not approve restarting it.

`scripts/rebuild_public_audience_archive.py --apply` intentionally preserves the full canonical audience truth model. It scans the complete AoE2 War Traffic history twice: first to derive IP behavior and then to sessionize against that behavior before replacing the public daily audience rollups.

Because this is a full-history truth rebuild rather than request-time ingest, it is deliberately scheduled once daily instead of every six hours. The service remains serialized with the incremental daily-rollup job through `/run/traffic-rollups/aoe2hdbets.lock` and runs with explicit host-protection bounds:

- `CPUQuota=50%`
- `MemoryHigh=1G`
- `MemoryMax=1536M`
- `MemorySwapMax=256M`
- `Nice=15`
- best-effort I/O priority 7

These limits are an operating-safety boundary; they do not change classification, sessionization, historical coverage, or stored audience truth. A resource-limit failure must remain visible as a failed oneshot rather than being treated as a successful skip.

**Manual full-history dry-run/apply are HELD.** Do not start the legacy service or invoke `rebuild_public_audience_archive.py --apply`; the previous full forge consumed two hours without publishing new data.

V2 development is tracked in [draft PR #17](https://github.com/Emaren/traffic-api/pull/17). Its `public_audience_v2_checkpoint.py`, `public_audience_v2_sessions.py`, and `public_audience_v2_campaign.py` only produce private shadow checkpoint data, no public writes. Full-source parity, shadow classification equivalence, 18M+ resource benchmarks and operator-approved transactional promotion are required before production publication or scheduler re-enablement. See `docs/PUBLIC_AUDIENCE_V2.md`.

After reviewing service configuration, verify effective systemd state and preserve `traffic-public-audience-aoe2hdbets.timer` as disabled/inactive. **Do not copy/re-enable this unit as part of routine restore.** A separate reviewed cutover plan must authorize any future timer.

## Watchdog

Manual run:

    systemctl start traffic-watchdog.service
    journalctl -u traffic-watchdog.service -n 80 --no-pager -l

## API venv guard

traffic-api.service runs this before startup:

    /var/www/Traffic/ops/traffic-api-venv-guard.sh

It verifies .venv/bin/python3, uvicorn, and fastapi. If the venv is broken, it rebuilds the venv from requirements.txt.

## Restore systemd config from repo snapshot

    cd /var/www/Traffic/traffic-api

    cp ops/systemd/traffic-api.service /etc/systemd/system/
    cp ops/systemd/traffic-web.service /etc/systemd/system/
    cp ops/systemd/traffic-watchdog.service /etc/systemd/system/
    cp ops/systemd/traffic-watchdog.timer /etc/systemd/system/
    cp ops/systemd/traffic-session-archive-aoe2hdbets.service /etc/systemd/system/
    cp ops/systemd/traffic-session-archive-aoe2hdbets.timer /etc/systemd/system/
    cp ops/systemd/traffic-project-daily-rollups-aoe2hdbets.service /etc/systemd/system/
    cp ops/systemd/traffic-project-daily-rollups-aoe2hdbets.timer /etc/systemd/system/
    # Do not install/enable the held legacy public-audience full-history timer.

    mkdir -p /etc/systemd/system/traffic-api.service.d
    mkdir -p /etc/systemd/system/traffic-web.service.d
    cp ops/systemd/traffic-api.service.d/*.conf /etc/systemd/system/traffic-api.service.d/
    cp ops/systemd/traffic-web.service.d/*.conf /etc/systemd/system/traffic-web.service.d/

    mkdir -p /var/www/Traffic/ops
    cp ops/scripts/*.sh /var/www/Traffic/ops/
    chmod +x /var/www/Traffic/ops/*.sh

    systemctl daemon-reload
    systemctl enable --now \
      traffic-api.service \
      traffic-web.service \
      traffic-watchdog.timer \
      traffic-session-archive-aoe2hdbets.timer \
      traffic-project-daily-rollups-aoe2hdbets.timer

    # Separate explicit HOLD: traffic-public-audience-aoe2hdbets.timer

## Useful checks

    systemctl status traffic-api.service --no-pager -l
    systemctl status traffic-web.service --no-pager -l
    systemctl status traffic-public-audience-aoe2hdbets.timer --no-pager -l
    systemctl cat traffic-public-audience-aoe2hdbets.service
    systemctl list-timers --all | grep -E 'traffic-watchdog|traffic-session-archive|traffic-project-daily-rollups|traffic-public-audience|NEXT|LEFT'
    curl -sS -m 10 https://traffic.tokentap.ca/api/healthz
    curl -sS -m 15 -D- https://traffic.tokentap.ca/ -o /tmp/traffic-web.html
