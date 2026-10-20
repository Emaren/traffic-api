#!/usr/bin/env python3
"""Read-only live-vs-shadow Traffic public-audience parity report. NO PUBLISH."""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

# Support both 'python -m scripts.public_audience_v2_parity' and direct-script use.
# A direct script starts with scripts/ on sys.path, not the repository root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.traffic.config import PERSIST_DB_PATH
from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_sessions as sessions
from scripts import rebuild_public_audience_archive as canonical


def compare_history(
    shadow: dict[str, list[int]],
    existing: dict[str, list[int]],
) -> dict[str, Any]:
    if len(existing) < 10:
        return {"status": "BLOCKED", "reason": "insufficient trusted historical baseline",
                "compared": 0, "mismatch_days": [], "last_legacy_day": None}
    legacy_last = sorted(existing)[-1]
    # The old forge ran ~06:15 and may have stored an incomplete last day.
    # Never treat that last legacy bucket as a gold-standard completed day.
    stable_days = [day for day in sorted(existing) if day < legacy_last]
    mismatch = [day for day in stable_days if shadow.get(day) != existing[day]]
    non_monotone = [day for day, totals in shadow.items()
                    if len(totals) != 3 or not (totals[0] >= totals[1] >= totals[2] >= 0)]
    return {
        "status": "MATCH" if not mismatch and not non_monotone else "BLOCKED",
        "compared": len(stable_days),
        "mismatch_count": len(mismatch),
        "mismatch_days": mismatch[:25],
        "mismatch_omitted": max(0, len(mismatch)-25),
        "hierarchy_violations": non_monotone[:25],
        "last_legacy_day": legacy_last,
        "new_day_count": sum(day > legacy_last for day in shadow),
        "shadow_has_legacy_last_day": legacy_last in shadow,
    }


def read_existing(conn: sqlite3.Connection) -> dict[str, list[int]]:
    return {
        day: [int(total), int(suspected), int(confirmed)]
        for day, total, suspected, confirmed in conn.execute(
            """SELECT bucket_day,total_traffic,suspected_human,confirmed_human
               FROM traffic_public_daily_audience_rollups WHERE project_slug=?
               ORDER BY bucket_day""",
            (canonical.PROJECT_SLUG,),
        )
    }


def has_late_eligible_source_rows(
    live: sqlite3.Connection, *, start: str, end: str,
    watermark: int, hosts: list[str], rules: list[dict[str, Any]],
    max_candidates: int = 100_000, budget_seconds: float = 10,
) -> bool:
    """Find post-snapshot, in-window *canonical* events, not unrelated app logs.

    Candidate scan uses an ascending rowid seek and a strict wall/candidate cap.
    When a safety limit is reached, fail closed rather than claim no late arrivals.
    """
    if watermark < 0 or not hosts or max_candidates < 1 or budget_seconds <= 0:
        raise RuntimeError("STOP: invalid late-arrival search parameters")
    placeholders = ",".join("?" for _ in hosts)
    query = f"""
        SELECT rowid AS source_rowid, event_id, timestamp, ip, line_offset,
               raw_path, normalized_path, referrer_host, ua, host
        FROM traffic_entries
        WHERE rowid > ? AND timestamp >= ? AND timestamp < ?
          AND host IN ({placeholders})
          AND ({_non_browser_chain_firehose_sql()})
        ORDER BY rowid ASC
    """
    started = time.monotonic()
    live.set_progress_handler(
        lambda: int(time.monotonic() - started > budget_seconds), 1000,
    )
    try:
        rows = live.execute(query, (watermark, start, end, *hosts))
        for idx, row in enumerate(rows):
            if idx >= max_candidates or time.monotonic() - started > budget_seconds:
                raise RuntimeError("STOP: late-arrival scan budget exceeded")
            if canonical.normalize_row(row, rules=rules) is not None:
                return True
        return False
    finally:
        live.set_progress_handler(None, 0)


def preview(source: Path, state: Path) -> dict[str, Any]:
    if source.resolve() == state.resolve() or state.is_symlink():
        raise RuntimeError("STOP: private checkpoint source alias")
    shadow = sessions.shadow_daily(state)
    with closing(sqlite3.connect(f"file:{state.resolve().as_posix()}?mode=ro",
                                 uri=True)) as private:
        info = dict(private.execute("SELECT key,value FROM metadata"))
    verified = sessions.verified_state(source, state, info)
    if not verified[0]:
        raise RuntimeError("STOP: project host authority unavailable")

    if info["p1_digest"] != info["p2_digest"]:
        raise RuntimeError("STOP: raw source digest mismatch")
    with v2.source_connection(source) as live:
        late = has_late_eligible_source_rows(
            live, start=info["start"], end=info["end"],
            watermark=int(info["watermark"]), hosts=verified[0],
            rules=verified[1],
        )
        existing = read_existing(live)
    historical = compare_history(shadow, existing)
    completed = (
        historical["status"] == "MATCH"
        and bool(shadow)
        and not late
        and all(day < info["end"][:10] for day in shadow)
    )
    result = {
        "status": "SHADOW_COMPARABLE" if completed else "BLOCKED",
        "input_phase": info["phase"],
        "input_end_exclusive": info["end"],
        "input_snapshot_max_rowid": int(info["watermark"]),
        "raw_rows_p1": int(info["raw_scanned"]),
        "raw_rows_p2": int(info["p2_raw"]),
        "input_pass_digest_equal": info["p1_digest"] == info["p2_digest"],
        "late_source_rows_below_end_detected": late,
        "late_eligible_aoe2war_events_detected": late,
        "history": historical,
        "shadow_days": len(shadow),
        "shadow_checksum": hashlib.sha256(json.dumps(
            shadow, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest(),
        "private_shadow_only": True,
        "publication_authorized": False,
        "operator_production_parity_certified": False,
        "note": "Even SHADOW_COMPARABLE is a diagnostic, never release authority.",
    }
    return result


def main() -> int:
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=PERSIST_DB_PATH)
    cli.add_argument("--state", type=Path, required=True)
    opts=cli.parse_args()
    print(json.dumps(preview(opts.source, opts.state), sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
