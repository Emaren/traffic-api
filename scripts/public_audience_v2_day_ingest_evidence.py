#!/usr/bin/env python3
"""Fail-closed, bounded, read-only source-row insertion evidence for one UTC day.

This is a PRE-CERTIFICATION witness, never a publication permit. An upstream
delivery authority, source-equivalent canonical sessions/global-IP classifier,
cross-day carry and late-change proof are independently required. No public
SQLite writes, timers or insertion-time backfills are implemented here.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import date, datetime, time as dt_time, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from app.services.traffic.persistence import _non_browser_chain_firehose_sql

FIRST_DAY = date(2026, 10, 20)
MAX_DAY_ROWS = 20_000
MAX_SECONDS = 45
REQUIRED_INDEX = "idx_traffic_entries_timestamp_line_offset"


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ValueError(why)


def completed_day(day: str, *, now: datetime) -> tuple[datetime, datetime]:
    require(type(day) is str and len(day) == 10
            and day == date.fromisoformat(day).isoformat(),
            "invalid canonical UTC day")
    require(now.tzinfo is not None, "observation clock lacks UTC offset")
    today = now.astimezone(timezone.utc).date()
    target = date.fromisoformat(day)
    require(FIRST_DAY <= target < today,
            "only completed future-epoch UTC days may be inspected")
    start = datetime.combine(target, dt_time.min, tzinfo=timezone.utc)
    return start, start + timedelta(days=1)


def parse_utc_clock(value: str) -> datetime:
    require(type(value) is str and 10 < len(value) <= 40,
            "missing or malformed insertion UTC clock")
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None
            and result.utcoffset() == timedelta(0),
            "insertion receipt lacks UTC offset")
    return result.astimezone(timezone.utc)


def evaluate_rows(rows: list[tuple[int, str, str | None]], *,
                  day: str, now: datetime, cursor: int,
                  max_rowid: int, retroactive_frozen_history: bool) -> dict:
    """Bounded evidence report; a good sample never becomes a certificate."""
    start, end = completed_day(day, now=now)
    require(type(cursor) is int and cursor >= forward.FROZEN_WATERMARK,
            "forward prefix cursor invalid")
    require(type(max_rowid) is int and max_rowid >= cursor,
            "canonical source rowid rewind")
    require(0 <= len(rows) <= MAX_DAY_ROWS,
            "completed day exceeds bounded row ceiling")
    digest = hashlib.sha256()
    seen: set[int] = set()
    missing = 0
    beyond_cursor = 0
    clocks_bad = 0
    clock_by_rowid: list[tuple[int, datetime]] = []
    for rowid, event_time, received_time in rows:
        require(type(rowid) is int and 0 < rowid <= max_rowid
                and rowid not in seen, "invalid or duplicate source rowid")
        seen.add(rowid)
        require(type(event_time) is str, "malformed event-time evidence")
        event = datetime.fromisoformat(event_time)
        require(event.tzinfo is not None and
                start <= event.astimezone(timezone.utc) < end,
                "source row timestamp outside requested UTC day")
        if rowid > cursor:
            beyond_cursor += 1
        if received_time is None:
            missing += 1
            receipt = None
        else:
            receipt = parse_utc_clock(received_time)
            if receipt < event.astimezone(timezone.utc) or receipt > now + timedelta(minutes=5):
                clocks_bad += 1
            clock_by_rowid.append((rowid, receipt))
        digest.update(json.dumps(
            [rowid, event_time, received_time],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8") + b"\n")
    reversals = sum(
        current[1] < previous[1]
        for previous, current in zip(
            sorted(clock_by_rowid), sorted(clock_by_rowid)[1:]
        )
    )
    # These tests are necessary, NOT sufficient. Only a separately authenticated
    # upstream log-delivery receipt can show the day was actually delivered.
    if retroactive_frozen_history:
        status = "HOLD_FROZEN_HISTORY_RETROACTIVE_INPUT"
    elif not rows:
        status = "HOLD_DAY_SOURCE_EVIDENCE_ABSENT"
    elif beyond_cursor:
        status = "HOLD_DAY_SOURCE_PREFIX_NOT_CAPTURED"
    elif missing:
        status = "HOLD_INSERTION_CLOCK_UNKNOWN"
    elif clocks_bad or reversals:
        status = "HOLD_INSERTION_CLOCK_INCONSISTENT"
    else:
        status = "HOLD_INDEPENDENT_DELIVERY_AND_CLASSIFIER_FINALITY_ABSENT"
    return {
        "schema": "traffic.public-audience.day-ingest-evidence.v1",
        "day": day,
        "status": status,
        "source_rowid_upper_bound": max_rowid,
        "forward_prefix_rowid": cursor,
        "source_rows_examined": len(rows),
        "rows_not_captured_at_prefix": beyond_cursor,
        "rows_with_missing_insertion_receipt": missing,
        "rows_with_invalid_insertion_clock": clocks_bad,
        "insertion_clock_rowid_reversals": reversals,
        "late_input_targets_frozen_history": retroactive_frozen_history,
        "observed_day_source_rows_digest_sha256": digest.hexdigest(),
        "source_read_only": True,
        "source_window_bounded": True,
        "unproven_global_ip_classification": True,
        "upstream_log_delivery_complete": False,
        "source_equivalent_sessions_certified": False,
        "cross_midnight_carry_certified": False,
        "late_arrival_finality_certified": False,
        "two_consecutive_days_certified": False,
        "publication_authorized": False,
        "public_audience_writes": False,
        "certified_days": [],
        "ready_to_publish_days": [],
        "unknown_days_not_filled_with_zero": True,
    }


def regular(path: Path, *, mode: int | None = None) -> None:
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
            "source/private evidence not a single regular file")
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode,
                "private evidence mode mismatch")


def audit(source: Path, checkpoint: Path, ledger: Path, lock: Path, *, day: str,
          max_rows: int = MAX_DAY_ROWS, budget_seconds: int = 30,
          now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    start, end = completed_day(day, now=now)
    require(1 <= max_rows <= MAX_DAY_ROWS, "day row cap outside allowed bounds")
    require(5 <= budget_seconds <= MAX_SECONDS,
            "day scan time budget outside allowed bounds")
    # Calendar refusal happens BEFORE worker or private-file access.
    guard.require_worker_priority()
    require(guard.worker_idle(), "project daily worker has priority")
    for path in (source, checkpoint, ledger, lock):
        regular(path)
    require(checkpoint.parent == ledger.parent == lock.parent,
            "private evidence directories do not match")
    require((ledger.parent.stat().st_mode & 0o077) == 0,
            "private forward ledger directory not owner-private")
    require((ledger.stat().st_mode & 0o777) == 0o600
            and (checkpoint.stat().st_mode & 0o777) == 0o600,
            "private checkpoint/ledger must be 0600")
    deadline = time.monotonic() + budget_seconds
    fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "lock inode invalid")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with closing(sqlite3.connect(
            f"file:{source.resolve().as_posix()}?mode=ro", uri=True, timeout=3
        )) as src, closing(sqlite3.connect(
            f"file:{ledger.resolve().as_posix()}?mode=ro", uri=True, timeout=3
        )) as private:
            for db in (src, private):
                db.execute("PRAGMA query_only=ON")
                db.execute("PRAGMA busy_timeout=3000")
                db.execute("BEGIN")
                db.set_progress_handler(
                    lambda: int(time.monotonic() >= deadline), 1000
                )
            historical = guard.checkpoint_info(checkpoint)
            guard.verify_frozen(source, checkpoint, historical)
            hosts, _rules = sessions.verified_state(source, checkpoint, historical)
            require(bool(hosts) and all(type(h) is str and h for h in hosts),
                    "verified canonical project host set empty")
            require(historical.get("phase") == "PASS2_COMPLETE",
                    "sealed historical checkpoint not complete")
            meta = forward.read_metadata(private)
            forward.validate_ledger(meta, historical)
            forward.assert_published_history(src)
            require(meta.get("phase") == "LIVE",
                    "private forward capture not LIVE")
            require(meta.get("original_watermark") ==
                    str(forward.FROZEN_WATERMARK)
                    and meta.get("historical_public_digest") ==
                    forward.RELEASE_SHA,
                    "private forward source epoch/release hash drift")
            s = source.stat()
            require(meta.get("device") == str(s.st_dev) and
                    meta.get("inode") == str(s.st_ino),
                    "private forward source inode mismatch")
            cursor = int(meta["live_rowid"])
            max_rowid = int(src.execute(
                "SELECT COALESCE(MAX(rowid),0) FROM traffic_entries"
            ).fetchone()[0])
            cols = {x[1] for x in src.execute(
                "PRAGMA table_info(traffic_entries)"
            )}
            require({"timestamp", "line_offset", "ingested_at_utc",
                     "host", "normalized_path", "ua"}.issubset(cols),
                    "canonical source insertion-time/host schema incomplete")
            indexes = {x[1] for x in src.execute(
                "PRAGMA index_list(traffic_entries)"
            )}
            require(REQUIRED_INDEX in indexes, "approved day index absent")
            begin, finish = start.isoformat(), end.isoformat()
            # Exact candidate-host/filter semantics from canonical source.
            # Read only a bounded indexed UTC-day slice, including unclassified
            # bots; do NOT substitute raw per-day visitor counts for audience.
            host_placeholders = ",".join("?" for _ in hosts)
            canonical_filter = _non_browser_chain_firehose_sql()
            rows = src.execute(f"""
                SELECT rowid,timestamp,ingested_at_utc
                FROM traffic_entries INDEXED BY {REQUIRED_INDEX}
                WHERE timestamp >= ? AND timestamp < ?
                  AND host IN ({host_placeholders})
                  AND ({canonical_filter})
                ORDER BY timestamp,line_offset,rowid LIMIT ?
            """, (begin, finish, *hosts, max_rows + 1)).fetchall()
            require(len(rows) <= max_rows,
                    "day has more events than bounded source scan")
            retroactive = src.execute(f"""
                SELECT 1 FROM traffic_entries INDEXED BY {REQUIRED_INDEX}
                WHERE timestamp < ? AND rowid > ?
                  AND host IN ({host_placeholders})
                  AND ({canonical_filter})
                LIMIT 1
            """, (FIRST_DAY.isoformat() + "T00:00:00+00:00",
                  forward.FROZEN_WATERMARK, *hosts)).fetchone() is not None
            require(time.monotonic() < deadline, "day read-only scan timed out")
            result = evaluate_rows(
                rows, day=day, now=now, cursor=cursor,
                max_rowid=max_rowid, retroactive_frozen_history=retroactive,
            )
            for db in (src, private):
                db.execute("ROLLBACK")
            result["private_forward_epoch_hash_checked"] = True
            result["sealed_historical_source_checkpoint_checked"] = True
            result["original_131_published_days_immutable_checked"] = True
            result["worker_priority_verified"] = True
            result["source_inode_matches_forward_prefix"] = True
            result["canonical_host_and_non_browser_filter_checked"] = True
            result["shared_canary_lock_acquired"] = True
            return result
    finally:
        os.close(fd)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--checkpoint", required=True, type=Path)
    p.add_argument("--ledger", required=True, type=Path)
    p.add_argument("--lock", required=True, type=Path)
    p.add_argument("--day", required=True)
    p.add_argument("--max-rows", type=int, default=MAX_DAY_ROWS)
    p.add_argument("--budget-seconds", type=int, default=30)
    args = p.parse_args()
    try:
        result = audit(
            args.source, args.checkpoint, args.ledger, args.lock, day=args.day,
            max_rows=args.max_rows, budget_seconds=args.budget_seconds,
        )
        print(json.dumps(result, sort_keys=True))
        # Every emitted report still lacks independently verified upstream
        # log delivery/classifier/finality. Explicit nonzero HOLD exit makes
        # it impossible to mistake a readable JSON result for authorization.
        return 2
    except (OSError, sqlite3.Error, ValueError, KeyError, RuntimeError, OverflowError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
