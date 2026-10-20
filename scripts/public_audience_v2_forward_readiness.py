#!/usr/bin/env python3
"""Read-only integrity and backlog audit for private forward Traffic inputs.

Reports source-cursor health; never decides whether a UTC day is publishable.
All audience calculation and automatic public release remain unavailable.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import public_audience_v2_checkpoint as v2


def report(meta: dict[str, str], *, retained: int, source_max_rowid: int,
           earliest_private_day: str | None, last_private_day: str | None) -> dict:
    """Independently reject impossible cursor/count relationships."""
    for key in ("captured", "accepted", "live_rowid", "original_watermark"):
        forward.require(meta.get(key, "").isdecimal(),
                        f"ledger {key} invalid")
    captured, accepted = int(meta["captured"]), int(meta["accepted"])
    cursor, base = int(meta["live_rowid"]), int(meta["original_watermark"])
    phase = meta["phase"]
    forward.require(phase in ("BOOTSTRAP", "LIVE"),
                    "unexpected private ledger phase")
    forward.require(base == forward.FROZEN_WATERMARK,
                    "historical rowid watermark mismatch")
    forward.require(0 <= accepted <= captured
                    and retained == accepted,
                    "private input retention/cursor count discrepancy")
    forward.require(source_max_rowid >= cursor >= base,
                    "source rowid ceiling retreated or cursor invalid")
    if phase == "BOOTSTRAP":
        forward.require(cursor == base,
                        "bootstrap unexpectedly advanced live source cursor")
    forward.require(
        (retained == 0 and earliest_private_day is None and last_private_day is None)
        or (retained > 0 and earliest_private_day is not None
            and last_private_day is not None
            and forward.START[:10] <= earliest_private_day <= last_private_day),
        "private retained date boundaries inconsistent"
    )

    # A difference in SQLite rowids is NOT a count of eligible events:
    # discarded, non-project, and deleted rows leave gaps.
    return {
        "result": "PRIVATE_FORWARD_INTEGRITY_VERIFIED",
        "phase": phase,
        "bootstrap_finished": phase == "LIVE",
        "raw_source_rows_examined": captured,
        "canonical_events_retained": retained,
        "earliest_retained_utc_day": earliest_private_day,
        "latest_retained_utc_day": last_private_day,
        "sealed_historical_public_sha256": forward.RELEASE_SHA,
        "source_highest_rowid": source_max_rowid,
        "forward_scan_cursor_rowid": cursor,
        "unscanned_rowid_span_upper_bound": (
            source_max_rowid - cursor if phase == "LIVE" else None
        ),
        "private_input_capture_only": True,
        "canonical_day_classification_ready": False,
        "utc_day_completeness_certified": False,
        "ready_to_publish_days": [],
        "publication_authorized": False,
    }


def audit(source: Path, checkpoint: Path, ledger_path: Path) -> dict:
    forward.require(source.is_file() and not source.is_symlink(),
                    "source missing or symlink")
    forward.require(checkpoint.is_file() and not checkpoint.is_symlink(),
                    "checkpoint missing or symlink")
    forward.require(ledger_path.is_file() and not ledger_path.is_symlink(),
                    "private ledger missing or symlink")
    forward.require(ledger_path.parent == checkpoint.parent,
                    "private ledger/checkpoint directory mismatch")
    forward.require((ledger_path.stat().st_mode & 0o777) == 0o600,
                    "private ledger not 0600")

    historical = guard.checkpoint_info(checkpoint)
    guard.verify_frozen(source, checkpoint, historical)
    forward.require(historical["phase"] == "PASS2_COMPLETE",
                    "historical source checkpoint incomplete")
    sessions.verified_state(source, checkpoint, historical)
    with closing(v2.source_connection(source)) as src:
        forward.assert_published_history(src)
        source_max = int(src.execute(
            "SELECT COALESCE(MAX(rowid),0) FROM traffic_entries"
        ).fetchone()[0])
    with closing(sqlite3.connect(
        f"file:{ledger_path.resolve().as_posix()}?mode=ro",
        uri=True, timeout=2,
    )) as db:
        db.execute("PRAGMA query_only=ON")
        meta = forward.read_metadata(db)
        forward.validate_ledger(meta, historical)
        retained = int(db.execute(
            "SELECT COUNT(*) FROM future_events"
        ).fetchone()[0])
        limits = db.execute(
            "SELECT MIN(substr(timestamp,1,10)),"
            "MAX(substr(timestamp,1,10)) FROM future_events"
        ).fetchone()
    return report(
        meta, retained=retained, source_max_rowid=source_max,
        earliest_private_day=limits[0], last_private_day=limits[1],
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--ledger", type=Path, required=True)
    args = p.parse_args()
    try:
        result = audit(args.source, args.checkpoint, args.ledger)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RuntimeError, ValueError, KeyError, sqlite3.Error, OSError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
