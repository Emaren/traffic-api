#!/usr/bin/env python3
"""Read-only Traffic V2 production evidence preflight. Never publish."""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
import sys
from typing import Any

# Support both 'python -m scripts.public_audience_v2_preflight' and direct-script use.
# A direct script starts with scripts/ on sys.path, not the repository root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.traffic.config import PERSIST_DB_PATH
from scripts import rebuild_public_audience_archive as canonical

PUBLIC_TIMER = "traffic-public-audience-aoe2hdbets.timer"


def read_evidence(db_path: Path, hosts: list[str]) -> dict[str, Any]:
    if not db_path.is_file():
        raise RuntimeError("STOP: raw Traffic source database does not exist")
    if not hosts:
        raise RuntimeError("STOP: no project hosts found")
    with closing(sqlite3.connect(
        f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True, timeout=2,
    )) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=2000")
        highwater = db.execute(
            "SELECT COALESCE(MAX(rowid),0) FROM traffic_entries"
        ).fetchone()[0]
        latest = {}
        for host in hosts:
            row = db.execute(
                "SELECT timestamp FROM traffic_entries WHERE host=? "
                "ORDER BY timestamp DESC LIMIT 1", (host,),
            ).fetchone()
            latest[host] = row[0] if row else None
        ingest = db.execute(
            "SELECT MAX(updated_at) FROM traffic_ingest_state"
        ).fetchone()[0]
        last_public = db.execute(
            "SELECT bucket_day,updated_at FROM traffic_public_daily_audience_rollups "
            "WHERE project_slug=? ORDER BY bucket_day DESC LIMIT 1",
            (canonical.PROJECT_SLUG,),
        ).fetchone()
    return {
        "source_rowid_ceiling": int(highwater),
        "source_size_bytes": db_path.stat().st_size,
        "host_latest_utc": latest,
        "ingest_state_last_updated": ingest,
        "public_last_day": last_public[0] if last_public else None,
        "public_last_calculation_at": last_public[1] if last_public else None,
        "public_archive_stale_days": (
            (datetime.now(timezone.utc).date()-date.fromisoformat(last_public[0])).days
            if last_public else None
        ),
    }


def timer_is_disabled() -> tuple[bool, dict[str, str | None]]:
    """Never treat unavailable systemd truth as a disabled timer."""
    output: dict[str, str | None] = {}
    for property_ in ("UnitFileState", "ActiveState"):
        command = ["systemctl", "show", PUBLIC_TIMER, "--property", property_, "--value"]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            output[property_] = None
            continue
        output[property_] = result.stdout.strip() if result.returncode == 0 else None
    return (
        output.get("UnitFileState") == "disabled"
        and output.get("ActiveState") == "inactive",
        output,
    )


def preflight(source: Path, *, check_systemd: bool = True) -> dict[str, Any]:
    evidence = read_evidence(source, canonical.project_hosts())
    free = shutil.disk_usage(source.parent).free
    evidence["volume_free_bytes"] = free
    timer_ok, timer = timer_is_disabled() if check_systemd else (False, {})
    evidence["legacy_public_timer"] = timer
    evidence["legacy_timer_held_verified"] = timer_ok
    evidence["read_only"] = True
    evidence["no_publication"] = True
    evidence["canary_ready"] = bool(timer_ok and free >= 8*1024**3 and
                                    evidence["source_rowid_ceiling"] > 0)
    evidence["warning"] = (
        "This is a READ-ONLY operator observation, not full source parity, "
        "a performance benchmark, or authorization to publish."
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=PERSIST_DB_PATH)
    options = parser.parse_args()
    print(json.dumps(preflight(options.source), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
