#!/usr/bin/env python3
"""Read-only, fail-closed manifest for June 11–October 19 V2 full-day candidate.

NEVER publishes public rollups, enables timers, or replaces the original 151-day
request with invented zeros. Does not authorize any release by itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_sessions as sessions
from scripts import public_audience_v2_parity as parity
from scripts import public_audience_v2_guarded_resume as guard

START = date(2026, 6, 11)
END_EXCLUSIVE = date(2026, 10, 20)
FROZEN_EARLIEST = "2026-06-10T13:41:50+00:00"
EXPECTED_LEGACY_MISMATCHES = ["2026-06-09", "2026-06-10"]
EXPECTED_SOURCE_SHADOW_DAYS = 132


def days_between(start: date, end_exclusive: date) -> list[str]:
    days = []
    day = start
    while day < end_exclusive:
        days.append(day.isoformat())
        day += timedelta(days=1)
    return days


def sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode()).hexdigest()


def qualify(daily: dict[str, list[int]],
            legacy: dict[str, list[int]]) -> dict[str, Any]:
    expected = days_between(START, END_EXCLUSIVE)
    guard.require(len(expected) == 131, "invalid full-day calendar count")
    guard.require(
        len(daily) == EXPECTED_SOURCE_SHADOW_DAYS
        and set(daily) == set(expected) | {"2026-06-10"},
        "private completed shadow has unexpected dates or gaps",
    )
    for day in expected:
        values = daily[day]
        guard.require(
            isinstance(values, list) and len(values) == 3
            and all(type(x) is int for x in values)
            and values[0] > 0
            and values[0] >= values[1] >= values[2] >= 0,
            "incomplete or invalid full-day canonical audience bucket",
        )
    historical = parity.compare_history(daily, legacy)
    guard.require(
        historical["status"] == "BLOCKED"
        and historical["mismatch_days"] == EXPECTED_LEGACY_MISMATCHES
        and historical["mismatch_count"] == 2
        and historical["compared"] == 127
        and historical["last_legacy_day"] == "2026-10-14",
        "legacy discrepancy not limited to independently explained early dates",
    )
    guard.require(
        len(legacy) == 128 and min(legacy) == "2026-06-09"
        and max(legacy) == "2026-10-14",
        "legacy publication snapshot changed",
    )
    candidate = {day: daily[day] for day in expected}
    return {
        "status": "CANDIDATE_ONLY",
        "first_full_day": expected[0],
        "last_full_day": expected[-1],
        "full_day_count": len(candidate),
        "unavailable_prior_interval": ["2026-05-22", "2026-06-09"],
        "excluded_incomplete_day": "2026-06-10",
        "full_day_totals": [
            sum(values[idx] for values in candidate.values()) for idx in range(3)
        ],
        "full_day_sha256": sha(candidate),
        "legacy_day_count": len(legacy),
        "legacy_sha256": sha(legacy),
        "legacy_mismatches_excluded": historical["mismatch_days"],
        "legacy_full_day_compared": historical["compared"] - 2,
        "last_completed_utc_day": "2026-10-19",
        "candidate_daily": candidate,
    }


def inspect(source: Path, state: Path) -> dict[str, Any]:
    guard.require(state.is_file() and not state.is_symlink(),
                  "missing private shadow checkpoint")
    guard.require(state.stat().st_mode & 0o777 == 0o600,
                  "checkpoint must be mode 0600")
    guard.require(source.resolve() != state.resolve(),
                  "source aliases checkpoint")
    info = guard.checkpoint_info(state)
    guard.verify_frozen(source, state, info)
    guard.require(info["phase"] == "PASS2_COMPLETE",
                  "fully completed frozen replay required")
    daily = sessions.shadow_daily(state)
    hosts, rules = sessions.verified_state(source, state, info)
    guard.require(bool(hosts), "no source-authorized project hosts")
    with closing(v2.source_connection(source)) as db:
        first = db.execute(
            "SELECT timestamp FROM traffic_entries "
            "INDEXED BY idx_traffic_entries_timestamp_line_offset "
            "ORDER BY timestamp ASC, line_offset ASC LIMIT 1"
        ).fetchone()
        guard.require(
            bool(first) and first["timestamp"] == FROZEN_EARLIEST,
            "retained earliest source boundary changed",
        )
        late = parity.has_late_eligible_source_rows(
            db, start=info["start"], end=info["end"],
            watermark=int(info["watermark"]), hosts=hosts, rules=rules,
        )
        guard.require(not late, "late eligible source rows exist")
        legacy = parity.read_existing(db)
    result = qualify(daily, legacy)
    result.pop("candidate_daily")  # never print full source payload by default
    result.update({
        "source_sha256": info["p2_digest"],
        "source_snapshot_rowid": int(info["watermark"]),
        "source_rows": int(info["p2_raw"]),
        "source_accepted_rows": int(info["p2_accepted"]),
        "late_eligible_events_detected": False,
        "source_earliest_retained_utc": FROZEN_EARLIEST,
        "first_full_day_reason": "June 10 source starts after 13:41 UTC",
        "source_contract": "canonical page sessions with global IP behavior",
        "record_counts_not_pageviews": True,
        "preview_only": True,
        "publication_authorized": False,
        "operator_approval_required": True,
        "daily_maintenance_not_implemented": True,
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.source, args.state), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
