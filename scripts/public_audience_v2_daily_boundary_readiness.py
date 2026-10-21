#!/usr/bin/env python3
"""Private, bounded, per-UTC-day cross-midnight source evidence diagnostic.

Does not rebuild audience rollups or classify human sessions. Independently
checks whether sessions with events in the LAST 30 minutes of a completed
UTC day have observable continuations and expiry in a timestamp-indexed
future window. This is NOT an ingestion completeness or publication proof.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sqlite3
import stat
import sys
import time
from contextlib import closing
from datetime import date, datetime, time as dt_time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from app.services.traffic.config import SESSION_GAP_MINUTES
from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ledger as ledger_mod
from scripts import public_audience_v2_forward_ip_shadow as shadow_mod
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import rebuild_public_audience_archive as canonical

MAX_WINDOW_EVENTS = 120_000
MAX_SECONDS = 80
MAX_LOOKAHEAD_HOURS = 48
FIRST_DAY = date(2026, 10, 20)


def require(ok: bool, message: str) -> None:
    guard.require(ok, message)


def actor_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (item["host"], item["ip"], (item.get("ua") or "").lower())


def examine_trailing_sessions(
    tail: list[dict[str, Any]], lookahead: Iterator[dict[str, Any]],
    *, boundary: datetime, scanned_through: datetime,
    deadline: float,
) -> dict[str, int | bool]:
    """Conservative event-clock evidence; does not claim ingestion finality.

    If the last-seen event is separated from a later global event by >30m
    with no same-actor continuation inside the fully scanned range, the
    actor is observationally inactive. Late delivery could reverse this;
    the result NEVER represents a final certified session.
    """
    require(boundary.tzinfo is not None and scanned_through.tzinfo is not None,
            "event window requires UTC-aware boundaries")
    gap = timedelta(minutes=SESSION_GAP_MINUTES)
    latest: dict[tuple[str, str, str], datetime] = {}
    for item in tail:
        stamp = item["timestamp"]
        require(boundary-gap <= stamp < boundary,
                "last-half-hour source evidence out of range")
        key = actor_key(item)
        if key not in latest or stamp > latest[key]:
            latest[key] = stamp
    tail_actors = len(latest)
    advanced: set[tuple[str, str, str]] = set()
    expired: set[tuple[str, str, str]] = set()
    for item in lookahead:
        require(time.monotonic() < deadline, "lookahead analysis timed out")
        stamp = item["timestamp"]
        require(boundary <= stamp <= scanned_through,
                "forward event outside fully scanned range")
        key = actor_key(item)
        if key not in latest or key in expired:
            continue
        require(stamp >= latest[key], "forward event clock regressed")
        if stamp - latest[key] > gap:
            expired.add(key)
        else:
            latest[key] = stamp
            advanced.add(key)
    # Canonical expiry is strictly >30 minutes, not >=30 minutes.
    observed_inactive = sum(
        key in expired or stamp + gap < scanned_through
        for key, stamp in latest.items()
    )
    return {
        "day_edge_actor_keys": tail_actors,
        "actor_keys_observed_continuing_across_midnight": len(advanced),
        "actor_keys_observationally_inactive_after_gap": observed_inactive,
        "actor_keys_without_observed_expiry": tail_actors-observed_inactive,
        "final_ingestion_watermark_proven": False,
        "joint_historical_cross_epoch_sessions_certified": False,
        "day_publication_authorized": False,
    }


def canonical_window_inputs(
    db: sqlite3.Connection, *, begin: datetime, end: datetime,
    max_source_rowid: int, rules: list[dict[str, Any]], max_events: int,
    deadline: float,
) -> Iterator[dict[str, Any]]:
    """Timestamp index seek, strict prefix, ordered tie handling and cap."""
    require(0 < max_events <= MAX_WINDOW_EVENTS, "invalid window scan cap")
    if begin >= end:
        return
    rows = db.execute(
        """SELECT source_rowid,timestamp,event_json
           FROM future_events INDEXED BY idx_future_events_timestamp
           WHERE timestamp>=? AND timestamp<? AND source_rowid<=?
           ORDER BY timestamp ASC LIMIT ?""",
        (begin.isoformat(), end.isoformat(), max_source_rowid, max_events+1),
    )
    examined = 0
    for rowid, stamp, payload in rows:
        examined += 1
        require(examined <= max_events,
                "bounded event window cap exceeded: SAFE STOP")
        require(time.monotonic() < deadline, "window seek/scan timed out")
        raw = json.loads(payload)
        require(isinstance(raw, dict) and type(raw.get("source_rowid")) is int
                and raw["source_rowid"] == rowid
                and raw.get("timestamp") == stamp,
                "future evidence row identity mismatch")
        item = canonical.normalize_row(raw, rules=rules)
        require(item is not None, "canonical visibility normalization changed")
        require(begin <= item["timestamp"] < end,
                "normalized UTC timestamp drift")
        yield item


def inspect(
    source: Path, checkpoint: Path, ledger: Path, shadow: Path, *,
    day: str, max_window_events: int, lookahead_hours: int,
    budget_seconds: int,
) -> dict[str, Any]:
    require(1 <= max_window_events <= MAX_WINDOW_EVENTS,
            "event window scan cap outside bounds")
    require(1 <= lookahead_hours <= MAX_LOOKAHEAD_HOURS,
            "lookahead outside approved bounds")
    require(5 <= budget_seconds <= MAX_SECONDS,
            "day diagnostic time budget outside bounds")
    requested = date.fromisoformat(day)
    now = datetime.now(timezone.utc)
    require(FIRST_DAY <= requested < now.date(),
            "target must be a completed forward UTC calendar day")
    start = datetime.combine(requested, dt_time.min, tzinfo=timezone.utc)
    boundary = start + timedelta(days=1)
    horizon = min(now, boundary + timedelta(hours=lookahead_hours))
    for file in (source, checkpoint, ledger, shadow):
        require(file.is_file() and not file.is_symlink(),
                "source or immutable private evidence absent/symlink")
    require(checkpoint.parent == ledger.parent == shadow.parent
            and checkpoint.parent.stat().st_mode & 0o077 == 0,
            "untrusted private canary directory")
    for file in (checkpoint, ledger, shadow):
        require(file.stat().st_mode & 0o777 == 0o600,
                "private canary evidence must be 0600")
    guard.require_worker_priority()
    require(guard.worker_idle(), "independent project worker busy")
    deadline = time.monotonic() + budget_seconds
    fd = os.open(checkpoint.parent / ".canary.lock",
                 os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode),
                "private canary lock not regular")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        historical = guard.checkpoint_info(checkpoint)
        guard.verify_frozen(source, checkpoint, historical)
        require(historical["phase"] == "PASS2_COMPLETE",
                "historical two-pass evidence not sealed")
        _, rules = sessions.verified_state(source, checkpoint, historical)
        with closing(v2.source_connection(source)) as src, closing(
            sqlite3.connect(
                f"file:{ledger.resolve().as_posix()}?mode=ro", uri=True,
            )
        ) as inputs, closing(
            sqlite3.connect(
                f"file:{shadow.resolve().as_posix()}?mode=ro", uri=True,
            )
        ) as ip:
            for db in (src, inputs, ip):
                db.execute("PRAGMA query_only=ON")
            ledger_mod.assert_published_history(src)
            forward_meta = ledger_mod.read_metadata(inputs)
            ledger_mod.validate_ledger(forward_meta, historical)
            require(forward_meta["phase"] == "LIVE",
                    "future evidence capture not LIVE")
            ip_meta = dict(ip.execute("SELECT key,value FROM shadow_metadata"))
            shadow_mod.validate_metadata(
                ip_meta, shadow_mod.fresh_metadata(historical, ledger),
            )
            cursor = int(ip_meta["last_source_rowid"])
            processed = int(ip_meta["processed_inputs"])
            require(0 < processed <= int(forward_meta["accepted"]),
                    "IP processed snapshot count invalid")
            frozen_count = int(inputs.execute(
                "SELECT COUNT(*) FROM future_events WHERE source_rowid<=?",
                (cursor,),
            ).fetchone()[0])
            require(frozen_count == processed,
                    "ledger/IP frozen event prefix count mismatch")
            inputs.set_progress_handler(
                lambda: int(time.monotonic() >= deadline), 1000,
            )
            try:
                day_count = int(inputs.execute(
                    """SELECT COUNT(*) FROM future_events
                       INDEXED BY idx_future_events_timestamp
                       WHERE timestamp>=? AND timestamp<? AND source_rowid<=?""",
                    (start.isoformat(), boundary.isoformat(), cursor),
                ).fetchone()[0])
                require(day_count > 0, "no future events for requested full day")
                newest = inputs.execute(
                    """SELECT timestamp FROM future_events
                       INDEXED BY idx_future_events_timestamp
                       WHERE source_rowid<=?
                       ORDER BY timestamp DESC LIMIT 1""",
                    (cursor,),
                ).fetchone()
                require(newest is not None, "no future snapshot event watermark")
                max_event_time = datetime.fromisoformat(newest[0])
                require(max_event_time.tzinfo is not None, "event clock missing UTC")
                scanned_through = min(horizon, max_event_time)
                # This check is about observable canonical event time only.
                # No late-delivery or remote log rotation guarantee exists.
                require(scanned_through >= boundary,
                        "future event stream does not reach day boundary")
                tail = list(canonical_window_inputs(
                    inputs, begin=boundary-timedelta(minutes=SESSION_GAP_MINUTES),
                    end=boundary, max_source_rowid=cursor,
                    rules=rules, max_events=max_window_events, deadline=deadline,
                ))
                following = canonical_window_inputs(
                    inputs, begin=boundary,
                    end=scanned_through + timedelta(microseconds=1),
                    max_source_rowid=cursor, rules=rules,
                    max_events=max_window_events, deadline=deadline,
                )
                continuity = examine_trailing_sessions(
                    tail, following, boundary=boundary,
                    scanned_through=scanned_through, deadline=deadline,
                )
            finally:
                inputs.set_progress_handler(None, 0)
            require(time.monotonic() < deadline,
                    "day boundary scan exceeded wall time")
            return {
                "result": "PRIVATE_DAY_BOUNDARY_READINESS_ONLY",
                "day": day,
                "frozen_input_events_total": processed,
                "day_events_at_frozen_prefix": day_count,
                "source_ip_prefix_rowid": cursor,
                "day_edge_events_examined": len(tail),
                "lookahead_hours_cap": lookahead_hours,
                "last_observed_event_utc": max_event_time.isoformat(),
                "scanned_through_event_clock_utc": scanned_through.isoformat(),
                "ledger_events_after_frozen_prefix":
                    int(forward_meta["accepted"]) - processed,
                "all_future_event_scan_required": False,
                "event_window_index_seeks_only": True,
                "late_ingestion_watermark_certified": False,
                "future_global_ip_classification_stable": False,
                "historical_stitched_canonical_parity_certified": False,
                "public_audience_writes": False,
                "private_read_only": True,
                "publication_authorized": False,
                **continuity,
            }
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "checkpoint", "ledger", "shadow"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--day", required=True)
    parser.add_argument("--max-window-events", type=int, default=90000)
    parser.add_argument("--lookahead-hours", type=int, default=24)
    parser.add_argument("--budget-seconds", type=int, default=60)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(
            args.source, args.checkpoint, args.ledger, args.shadow,
            day=args.day, max_window_events=args.max_window_events,
            lookahead_hours=args.lookahead_hours,
            budget_seconds=args.budget_seconds,
        ), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, TypeError, KeyError, OSError,
            sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
