#!/usr/bin/env python3
"""Private forward canonical pass-two candidate. NO public writes or permits.

The immutable historical canonical implementation is called as-is in an
isolated, one-shot process. Its SHA-256 is pinned by the original checkpoint;
changing that historical source would invalidate production recovery proofs.

This operation can compute candidate values only. Upstream NGINX delivery EOF,
source-page completion, canonical cross-epoch carry and late-arrival finality
remain independent signed admission gates.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import date, datetime, time as dt_time, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from typing import Iterator

from scripts import rebuild_public_audience_archive as canonical
from scripts import public_audience_v2_checkpoint as checkpoint
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_forward_ip_shadow as ip_shadow
from scripts import public_audience_v2_sessions as sessions

CANONICAL_EPOCH = date(2026, 10, 20)
MAX_REQUESTED_EVENTS = 6_000_000
MAX_EQUAL_TIME_GROUP = 10_000
MAX_BUDGET_SECONDS = 600
FIELDS = frozenset(checkpoint.RAW_FIELDS)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError("TRAFFIC_V2_FORWARD_HOLD_" + reason)


def regular_private(path: Path) -> None:
    require(not path.is_symlink() and path.is_file(), "PRIVATE_FILE_MISSING_OR_SYMLINK")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            (info.st_mode & 0o777) == 0o600, "PRIVATE_FILE_INTEGRITY")


def open_ro(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro",
                         uri=True, timeout=1)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def raw_forward_rows(db: sqlite3.Connection, *, start: str, end: str,
                     source_prefix_rowid: int, max_events: int,
                     deadline: float) -> Iterator[dict]:
    """Reconstruct exact canonical timestamp/line_offset/rowid order.

    The forward ledger indexes timestamp, but cannot assume rowid breaks
    timestamp ties in the same way as the old archive; sort each bounded
    equal-timestamp cohort by its original raw line offset and rowid.
    """
    require(start < end and source_prefix_rowid > forward.FROZEN_WATERMARK,
            "SOURCE_WINDOW_OR_PREFIX")
    require(1 <= max_events <= MAX_REQUESTED_EVENTS, "EVENT_CEILING")
    cursor = db.execute(
        """SELECT source_rowid,event_json,timestamp FROM future_events
           INDEXED BY idx_future_events_timestamp
           WHERE timestamp>=? AND timestamp<?
             AND source_rowid<=? ORDER BY timestamp ASC,source_rowid ASC""",
        (start, end, source_prefix_rowid),
    )
    counted = 0
    group: list[dict] = []
    previous: str | None = None

    def yield_group() -> Iterator[dict]:
        for item in sorted(group, key=lambda x: (
                int(x["line_offset"]), int(x["source_rowid"]))):
            yield item

    for record in cursor:
        if time.monotonic() >= deadline:
            raise RuntimeError("TRAFFIC_V2_FORWARD_HOLD_BUDGET_SECONDS")
        timestamp = str(record["timestamp"])
        if previous is not None and timestamp != previous:
            yield from yield_group()
            group.clear()
        previous = timestamp
        try:
            item = json.loads(record["event_json"])
        except (ValueError, TypeError) as exc:
            raise RuntimeError("TRAFFIC_V2_FORWARD_HOLD_EVENT_JSON") from exc
        require(type(item) is dict and set(item) == FIELDS,
                "RAW_FIELDS_DRIFT")
        require(type(item["source_rowid"]) is int and
                item["source_rowid"] == record["source_rowid"] and
                type(item["timestamp"]) is str and
                item["timestamp"] == timestamp and
                type(item["line_offset"]) is int,
                "SOURCE_ROW_ID_OR_TIMESTAMP_DRIFT")
        group.append(item)
        require(len(group) <= MAX_EQUAL_TIME_GROUP, "TIMESTAMP_TIE_LIMIT")
        counted += 1
        require(counted <= max_events, "EVENT_COUNT_LIMIT")
    if group:
        yield from yield_group()


class VerifiedMergedIPBehavior:
    """Original historical and private-forward IP model, lazy and bounded."""
    def __init__(self, historical: sqlite3.Connection,
                 private: sqlite3.Connection):
        self.historical = historical
        self.private = private
        self.cache: dict[tuple[str, str], dict] = {}

    def get(self, key: tuple[str, str], default: dict | None = None) -> dict:
        if key in self.cache:
            return self.cache[key]
        host, ip = key
        value = ip_shadow.merged_ip_behavior(
            self.historical, self.private, host, ip)
        if len(self.cache) >= 2048:
            self.cache.clear()
        self.cache[key] = value
        return value


def canonical_private_replay(*, raw_rows: Iterator[dict], behavior: object,
                             from_utc: datetime, until_utc: datetime,
                             source_prefix_rowid: int,
                             observed_at_utc: datetime) -> tuple[dict, dict]:
    """Call the ORIGINAL canonical engine, without modifying its source.

    Only one isolated command-line process may invoke this substitution.
    Restore the original function even on a timeout/exception; a web process
    must never import or invoke this adapter.
    """
    require(from_utc.tzinfo is not None and until_utc.tzinfo is not None and
            from_utc < until_utc, "INVALID_REPLAY_WINDOW")
    require(canonical.__name__ == "scripts.rebuild_public_audience_archive",
            "CANONICAL_SOURCE_IMPORT_DRIFT")
    original = canonical.source_rows
    called = False

    def private_source_rows(*, start: datetime, end: datetime,
                            snapshot_max_rowid: int) -> Iterator[dict]:
        nonlocal called
        require(not called, "CANONICAL_SOURCE_ITERATOR_REUSED")
        require(start == from_utc and end == until_utc and
                snapshot_max_rowid == source_prefix_rowid,
                "CANONICAL_ARGUMENT_DRIFT")
        called = True
        return raw_rows

    # The private adapter is a one-shot read-only CLI, not part of any web
    # worker. All original canonical session/bucket/classifier code is reused.
    canonical.source_rows = private_source_rows
    try:
        daily, metrics = canonical.stream_sessions(
            start=from_utc, end=until_utc,
            behavior=behavior, snapshot_max_rowid=source_prefix_rowid)
    finally:
        canonical.source_rows = original
    require(called, "CANONICAL_PASS_TWO_DID_NOT_READ_PRIVATE_SOURCE")
    return daily, metrics


def inspect(source: Path, historical: Path, ledger: Path, shadow: Path, *,
            day: str, max_events: int, budget_seconds: float) -> dict:
    require(1 <= max_events <= MAX_REQUESTED_EVENTS and
            1 <= budget_seconds <= MAX_BUDGET_SECONDS,
            "RESOURCE_LIMIT")
    today = datetime.now(timezone.utc).date()
    try:
        requested = date.fromisoformat(day)
    except ValueError as exc:
        raise RuntimeError("TRAFFIC_V2_FORWARD_HOLD_DAY_FORMAT") from exc
    require(requested.isoformat() == day and
            CANONICAL_EPOCH <= requested < today,
            "DAY_NOT_ELIGIBLE")
    require(source.is_file() and not source.is_symlink(),
            "ORIGINAL_SOURCE_MISSING")
    for path in (historical, ledger, shadow):
        regular_private(path)
    require(historical.parent == ledger.parent == shadow.parent and
            (historical.parent.stat().st_mode & 0o077) == 0,
            "PRIVATE_COHORT_MISMATCH")

    began = time.monotonic()
    deadline = began + budget_seconds
    info = guard.checkpoint_info(historical)
    guard.verify_frozen(source, historical, info)
    require(info.get("phase") == "PASS2_COMPLETE",
            "HISTORIC_PASS_TWO_INCOMPLETE")
    sessions.verified_state(source, historical, info)
    with closing(checkpoint.source_connection(source)) as db:
        forward.assert_published_history(db)
        max_at_start = int(db.execute(
            "SELECT COALESCE(MAX(rowid),0) FROM traffic_entries"
        ).fetchone()[0])
    with (closing(open_ro(historical)) as history,
          closing(open_ro(ledger)) as future,
          closing(open_ro(shadow)) as ip_data):
        metadata = forward.read_metadata(future)
        forward.validate_ledger(metadata, info)
        require(metadata["phase"] == "LIVE", "PRIVATE_BOOTSTRAP_INCOMPLETE")
        scanned_prefix = int(metadata["live_rowid"])
        # Fail closed on a live ingestion tail not yet covered by the
        # private ledger. Do not pretend a high-water rowid is a day EOF.
        require(scanned_prefix >= max_at_start, "FORWARD_SOURCE_TAIL_UNSCANNED")
        expected = ip_shadow.fresh_metadata(info, ledger)
        observed = dict(ip_data.execute(
            "SELECT key,value FROM shadow_metadata"))
        ip_shadow.validate_metadata(observed, expected)
        require(int(observed["processed_inputs"]) ==
                int(metadata["accepted"]),
                "GLOBAL_IP_PASS_ONE_NOT_CAUGHT_UP")
        last_private = future.execute(
            "SELECT COALESCE(MAX(source_rowid),0) FROM future_events"
        ).fetchone()[0]
        require(int(observed["last_source_rowid"]) == last_private,
                "IP_SHADOW_CURSOR_MISMATCH")
        # Historical pass-one source input also binds the original source
        # rules; never query a different ambient history database.
        start_dt = datetime.combine(CANONICAL_EPOCH, dt_time.min,
                                    tzinfo=timezone.utc)
        end_dt = datetime.combine(requested + timedelta(days=1),
                                  dt_time.min, tzinfo=timezone.utc)
        margin = timedelta(minutes=31)
        # All retained events since the protected epoch are replayed in
        # timestamp order, including the next-day expiry margin.
        private_rows = raw_forward_rows(
            future, start=start_dt.isoformat(),
            end=(end_dt + margin).isoformat(),
            source_prefix_rowid=scanned_prefix, max_events=max_events,
            deadline=deadline)
        behavior = VerifiedMergedIPBehavior(history, ip_data)
        daily, metrics = canonical_private_replay(
            raw_rows=private_rows, behavior=behavior,
            from_utc=start_dt, until_utc=end_dt + margin,
            source_prefix_rowid=scanned_prefix,
            observed_at_utc=datetime.now(timezone.utc))
        require(time.monotonic() <= deadline, "FULL_REPLAY_BUDGET_EXCEEDED")
        values = daily.get(day, [0, 0, 0])
        require(0 <= values[2] <= values[1] <= values[0],
                "CANONICAL_METRIC_HIERARCHY")
        # Crucially these are PRIVATE CANDIDATE values, not certifiable
        # source-day counts: the Oct19→Oct20 historical carry, independent
        # NGINX EOF/writer closure, late arrivals, and true day paging
        # require separate original signed certificates.
        model_pin = hashlib.sha256(json.dumps({
            "historical_pass_digest": info["p1_digest"],
            "forward_live_digest": metadata["live_digest"],
            "shadow_cursor": observed["last_source_rowid"],
            "shadow_processed": observed["processed_inputs"],
            "source_prefix": scanned_prefix,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {
            "result": "PRIVATE_CANONICAL_PASS_TWO_CANDIDATE_ONLY",
            "day": day,
            "candidate_total": values[0],
            "candidate_potential": values[1],
            "candidate_confirmed": values[2],
            "source_prefix_rowid": scanned_prefix,
            "raw_pass_two_rows": metrics["raw_rows"],
            "accepted_pass_two_rows": metrics["accepted_rows"],
            "finalized_sessions": metrics["finalized_sessions"],
            "model_input_pin_sha256": model_pin,
            "original_history_unchanged": True,
            "private_classification_only": True,
            "historical_epoch_carry_certified": False,
            "nginx_delivery_eof_certified": False,
            "late_arrival_stability_certified": False,
            "full_day_source_paging_certified": False,
            "upstream_signature_present": False,
            "classifier_signature_present": False,
            "daily_classification_ready": False,
            "publication_authorized": False,
            "public_writes": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "historical", "ledger", "shadow"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--day", required=True)
    parser.add_argument("--max-events", type=int, default=600_000)
    parser.add_argument("--budget-seconds", type=float, default=120.0)
    args = parser.parse_args()
    try:
        report = inspect(args.source, args.historical, args.ledger,
                         args.shadow, day=args.day,
                         max_events=args.max_events,
                         budget_seconds=args.budget_seconds)
        print(json.dumps(report, sort_keys=True))
        # No CLI codepath authorizes public publication, including complete
        # classification candidates. Only independent original signed-day
        # and root-owned publisher admission can authorize that.
        return 2
    except (RuntimeError, ValueError, TypeError, KeyError,
            OSError, sqlite3.Error) as exc:
        print("PRIVATE_CANONICAL_HOLD:", type(exc).__name__, str(exc),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
