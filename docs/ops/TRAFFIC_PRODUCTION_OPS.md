# Traffic Production Ops

## Services

- traffic-api.service: FastAPI on 127.0.0.1:3345
- traffic-web.service: Next.js on 127.0.0.1:3045
- traffic-watchdog.timer: checks local/public web, API health, and archive endpoint every 2 minutes
- traffic-session-archive-aoe2hdbets.timer: rebuilds AoE2 War session archive every 30 minutes
- traffic-project-daily-rollups-aoe2hdbets.timer: incrementally refreshes bounded AoE2 War daily rollups
- traffic-public-audience-aoe2hdbets.timer: runs the canonical full-history public-audience forge once daily at 06:15 UTC

## Important paths

- API repo: /var/www/Traffic/traffic-api
- Web repo: /var/www/Traffic/traffic-app
- Ops scripts: /var/www/Traffic/ops
- Traffic DB: /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3

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

## Canonical public-audience forge

`scripts/rebuild_public_audience_archive.py --apply` intentionally preserves the full canonical audience truth model. It scans the complete AoE2 War Traffic history twice: first to derive IP behavior and then to sessionize against that behavior before replacing the public daily audience rollups.

Because this is a full-history truth rebuild rather than request-time ingest, it is deliberately scheduled once daily instead of every six hours. The service remains serialized with the incremental daily-rollup job through `/run/traffic-rollups/aoe2hdbets.lock` and runs with explicit host-protection bounds:

- `CPUQuota=50%`
- `MemoryHigh=1G`
- `MemoryMax=1536M`
- `MemorySwapMax=256M`
- `Nice=15`
- best-effort I/O priority 7

These limits are an operating-safety boundary; they do not change classification, sessionization, historical coverage, or stored audience truth. A resource-limit failure must remain visible as a failed oneshot rather than being treated as a successful skip.

Manual dry-run:

    cd /var/www/Traffic/traffic-api
    .venv/bin/python3 scripts/rebuild_public_audience_archive.py

Manual canonical apply:

    systemctl start traffic-public-audience-aoe2hdbets.service
    journalctl -u traffic-public-audience-aoe2hdbets.service -n 100 --no-pager -l

After changing the checked-in systemd unit or timer, copy both files into `/etc/systemd/system/`, run `systemctl daemon-reload`, and verify the timer schedule before starting the service manually.

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
    cp ops/systemd/traffic-public-audience-aoe2hdbets.service /etc/systemd/system/
    cp ops/systemd/traffic-public-audience-aoe2hdbets.timer /etc/systemd/system/

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
      traffic-project-daily-rollups-aoe2hdbets.timer \
      traffic-public-audience-aoe2hdbets.timer

## Useful checks

    systemctl status traffic-api.service --no-pager -l
    systemctl status traffic-web.service --no-pager -l
    systemctl status traffic-public-audience-aoe2hdbets.timer --no-pager -l
    systemctl cat traffic-public-audience-aoe2hdbets.service
    systemctl list-timers --all | grep -E 'traffic-watchdog|traffic-session-archive|traffic-project-daily-rollups|traffic-public-audience|NEXT|LEFT'
    curl -sS -m 10 https://traffic.tokentap.ca/api/healthz
    curl -sS -m 15 -D- https://traffic.tokentap.ca/ -o /tmp/traffic-web.html
