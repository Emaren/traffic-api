#!/usr/bin/env python3
"""Bounded PRIVATE audit of source-rowid vs event-time ordering; never publish.

Traffic entries do NOT contain authoritative per-event ingestion timestamps.
Source rowid order can reveal relative backdating but cannot certify
absolute delivery latency or that late arrivals will never recur.
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
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_forward_ip_shadow as ip_shadow
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import rebuild_public_audience_archive as canonical

MAX_EVENTS = 200_000
MAX_UNPROCESSED_ROWS = 20_000
MAX_SECONDS = 45


def require(ok: bool, reason: str) -> None:
    guard.require(ok, reason)


def ordered_event_diagnostic(rows: Iterable[tuple[int, str]], *,
                             now_utc: datetime, cap: int) -> dict[str, Any]:
    """Record insertion-order disorder, NOT an invented ingestion timestamp."""
    require(now_utc.tzinfo is not None, "observation clock must be aware")
    require(1 <= cap <= MAX_EVENTS, "source-rowid observation cap exceeded")
    latest: datetime | None = None
    last_rowid = -1
    total = 0
    backward = Counter()
    events_per_day: Counter[str] = Counter()
    preceding_day_seen: str | None = None
    earlier_day_after_later_day = 0
    furthest_back_seconds = 0
    future_timestamp_events = 0
    for rowid, stamp_text in rows:
        total += 1
        require(total <= cap, "retained event scan cap exceeded")
        require(type(rowid) is int and rowid > last_rowid,
                "future retained event source rowids not strictly ascending")
        last_rowid = rowid
        stamp = datetime.fromisoformat(stamp_text)
        require(stamp.tzinfo is not None,
                "saved event time lacks timezone")
        stamp = stamp.astimezone(timezone.utc)
        day = stamp.date().isoformat()
        events_per_day[day] += 1
        if preceding_day_seen is not None and day < preceding_day_seen:
            earlier_day_after_later_day += 1
        if preceding_day_seen is None or day > preceding_day_seen:
            preceding_day_seen = day
        if stamp > now_utc:
            future_timestamp_events += 1
        if latest is not None and stamp < latest:
            seconds = int((latest - stamp).total_seconds())
            furthest_back_seconds = max(furthest_back_seconds, seconds)
            backward["any"] += 1
            if seconds > 1800:
                backward["over_30_minutes"] += 1
            if seconds > 6 * 3600:
                backward["over_6_hours"] += 1
            if seconds > 24 * 3600:
                backward["over_24_hours"] += 1
        if latest is None or stamp > latest:
            latest = stamp
    require(total > 0, "no retained private future events")
    require(len(events_per_day) <= 31,
            "too many event dates for one bounded diagnostic")
    return {
        "events_ordered_by_insert_rowid": total,
        "event_dates_retained_counts": dict(sorted(events_per_day.items())),
        "events_earlier_than_previously_seen_event_time":
            backward["any"],
        "events_over_30_minutes_behind_seen_event_time":
            backward["over_30_minutes"],
        "events_over_6_hours_behind_seen_event_time":
            backward["over_6_hours"],
        "events_over_24_hours_behind_seen_event_time":
            backward["over_24_hours"],
        "events_for_prior_utc_day_after_later_day_already_seen":
            earlier_day_after_later_day,
        "largest_event_time_inversion_seconds": furthest_back_seconds,
        "events_timestamped_in_future": future_timestamp_events,
        "relative_order_only_no_per_event_ingestion_time": True,
    }


def audit(source: Path, checkpoint: Path, ledger: Path, shadow: Path,
          *, max_events: int, max_unprocessed_rows: int,
          budget_seconds: int) -> dict[str, Any]:
    require(1 <= max_events <= MAX_EVENTS, "invalid future audit event cap")
    require(1 <= max_unprocessed_rows <= MAX_UNPROCESSED_ROWS,
            "invalid source backlog scan cap")
    require(5 <= budget_seconds <= MAX_SECONDS,
            "invalid source audit time budget")
    for path in (source, checkpoint, ledger, shadow):
        require(path.is_file() and not path.is_symlink(),
                "canonical source or private proof unavailable")
    require(checkpoint.parent == ledger.parent == shadow.parent,
            "private audit evidence paths differ")
    require(checkpoint.parent.stat().st_mode & 0o077 == 0,
            "private audit directory permissions drift")
    for path in (checkpoint, ledger, shadow):
        require(path.stat().st_mode & 0o777 == 0o600,
                "private audit evidence must be 0600")
    guard.require_worker_priority()
    require(guard.worker_idle(), "project worker has priority")
    deadline = time.monotonic() + budget_seconds
    lockfd = os.open(checkpoint.parent / ".canary.lock",
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(lockfd).st_mode),
                "private audit canary lock invalid")
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = guard.checkpoint_info(checkpoint)
        guard.verify_frozen(source, checkpoint, info)
        require(info["phase"] == "PASS2_COMPLETE",
                "historical source checkpoint not complete")
        hosts, rules = sessions.verified_state(source, checkpoint, info)
        now = datetime.now(timezone.utc)
        with closing(v2.source_connection(source)) as src, closing(
            sqlite3.connect(
                f"file:{ledger.resolve().as_posix()}?mode=ro", uri=True
            )
        ) as events, closing(
            sqlite3.connect(
                f"file:{shadow.resolve().as_posix()}?mode=ro", uri=True
            )
        ) as private_ip:
            for db in (src, events, private_ip):
                db.execute("PRAGMA query_only=ON")
            forward.assert_published_history(src)
            meta = forward.read_metadata(events)
            forward.validate_ledger(meta, info)
            require(meta["phase"] == "LIVE", "future capture not in LIVE mode")
            ip_meta = dict(private_ip.execute(
                "SELECT key,value FROM shadow_metadata"
            ))
            ip_shadow.validate_metadata(
                ip_meta, ip_shadow.fresh_metadata(info, ledger),
            )
            processed = int(ip_meta["processed_inputs"])
            source_cursor = int(meta["live_rowid"])
            require(source_cursor >= forward.FROZEN_WATERMARK,
                    "forward source cursor before frozen release watermark")

            def ledger_rows():
                for rowid, timestamp in events.execute(
                    "SELECT source_rowid,timestamp FROM future_events "
                    "ORDER BY source_rowid ASC"
                ):
                    require(time.monotonic() < deadline,
                            "future ingestion-order scan exceeded time budget")
                    yield int(rowid), str(timestamp)

            relative = ordered_event_diagnostic(
                ledger_rows(), now_utc=now, cap=max_events,
            )
            require(relative["events_ordered_by_insert_rowid"]
                    == int(meta["accepted"]),
                    "future ledger retained count and metadata disagree")
            require(0 <= processed <= int(meta["accepted"]),
                    "future private-IP processed count drift")
            raw_max = int(src.execute(
                "SELECT COALESCE(MAX(rowid),0) FROM traffic_entries"
            ).fetchone()[0])
            require(raw_max >= source_cursor,
                    "source high rowid behind captured cursor")
            backlog_rows = src.execute(
                """SELECT rowid AS source_rowid,event_id,timestamp,ip,
                          line_offset,raw_path,normalized_path,referrer_host,
                          ua,host
                   FROM traffic_entries
                   WHERE rowid>? ORDER BY rowid
                   LIMIT ?""",
                (source_cursor, max_unprocessed_rows + 1),
            )
            scanned = 0
            eligible_pending = 0
            eligible_old_release = 0
            eligible_closed_day = 0
            current_day = now.date().isoformat()
            for row in backlog_rows:
                scanned += 1
                require(scanned <= max_unprocessed_rows,
                        "unprocessed source backlog exceeds bounded scan")
                require(time.monotonic() < deadline,
                        "source backlog inspection exceeded time budget")
                # The forward collector uses this exact same normalizer.
                value = canonical.normalize_row(row, rules=rules)
                if value is None:
                    continue
                eligible_pending += 1
                if value["timestamp_iso"] < forward.START:
                    eligible_old_release += 1
                elif value["timestamp"].astimezone(timezone.utc).date().isoformat() < current_day:
                    eligible_closed_day += 1
            newest_ingest_update = src.execute(
                "SELECT MAX(updated_at),COUNT(*) FROM traffic_ingest_state"
            ).fetchone()
            require(time.monotonic() < deadline,
                    "source audit wall clock exceeded")
            return {
                "result": "PRIVATE_SOURCE_ORDER_AND_BACKLOG_AUDITED",
                "observed_at_utc": now.isoformat(),
                "published_history_through": "2026-10-19",
                "published_history_sha256": forward.RELEASE_SHA,
                "source_max_rowid": raw_max,
                "collector_source_cursor_rowid": source_cursor,
                "raw_rowid_distance_from_collector": raw_max-source_cursor,
                "raw_rows_inspected_since_collector_cursor": scanned,
                "canonical_eligible_rows_pending_capture": eligible_pending,
                "eligible_pending_rows_targeting_sealed_history":
                    eligible_old_release,
                "eligible_pending_rows_targeting_prior_calendar_days":
                    eligible_closed_day,
                "private_future_ledger_events": int(meta["accepted"]),
                "private_ip_events_processed": processed,
                "private_ip_events_pending": int(meta["accepted"])-processed,
                "source_ingest_state_records": int(newest_ingest_update[1]),
                "last_source_ingest_state_updated_at_utc":
                    newest_ingest_update[0],
                "historical_source_ingestion_policy_proven": False,
                "absolute_ingestion_lag_proven": False,
                "late_ingestion_watermark_certified": False,
                "global_ip_classification_stable": False,
                "two_closed_utc_days_certified": False,
                "publication_authorized": False,
                "read_only": True,
                **relative,
            }
    finally:
        os.close(lockfd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "checkpoint", "ledger", "shadow"):
        parser.add_argument("--"+key, type=Path, required=True)
    parser.add_argument("--max-events", type=int, default=200000)
    parser.add_argument("--max-unprocessed-rows", type=int, default=10000)
    parser.add_argument("--budget-seconds", type=int, default=30)
    args = parser.parse_args()
    try:
        print(json.dumps(audit(
            args.source, args.checkpoint, args.ledger, args.shadow,
            max_events=args.max_events,
            max_unprocessed_rows=args.max_unprocessed_rows,
            budget_seconds=args.budget_seconds,
        ), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, TypeError, KeyError, OSError,
            sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
