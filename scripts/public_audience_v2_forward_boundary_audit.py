#!/usr/bin/env python3
"""Read-only Oct 19/20 canonical actor session-boundary diagnostic.

Compares the last 30 minutes of the original sealed historical source
with the first 30 minutes of its private forward evidence ledger.
Never certifies a day, publishes counts, or prints actor identities.
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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from app.services.traffic.config import SESSION_GAP_MINUTES
from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import public_audience_v2_forward_ip_shadow as future_shadow
from scripts import rebuild_public_audience_archive as canonical

MAX_ROWS = 100_000
MAX_SECONDS = 45


def require(condition: bool, message: str) -> None:
    guard.require(condition, message)


def actor_key(event: dict[str, Any]) -> tuple[str, str, str]:
    return (event["host"], event["ip"], (event.get("ua") or "").lower())


def analyze_boundary(historical: Iterable[dict], future: Iterable[dict], *,
                     boundary: datetime, max_rows: int) -> dict[str, Any]:
    """Compute closest possible continuity; no raw actor data in receipt."""
    require(boundary.tzinfo is not None, "UTC boundary must be timezone aware")
    require(1 <= max_rows <= MAX_ROWS, "invalid boundary scan row bound")
    gap = timedelta(minutes=SESSION_GAP_MINUTES)
    old_last: dict[tuple[str, str, str], datetime] = {}
    new_first: dict[tuple[str, str, str], datetime] = {}
    history_events = 0
    future_events = 0
    for event in historical:
        history_events += 1
        require(history_events <= max_rows, "historical boundary event cap exceeded")
        stamp = event["timestamp"]
        require(boundary-gap <= stamp < boundary,
                "historical event outside sealed boundary window")
        key = actor_key(event)
        if key not in old_last or stamp > old_last[key]:
            old_last[key] = stamp
    for event in future:
        future_events += 1
        require(future_events <= max_rows, "future boundary event cap exceeded")
        stamp = event["timestamp"]
        require(boundary <= stamp < boundary+gap,
                "future event outside boundary window")
        key = actor_key(event)
        if key not in new_first or stamp < new_first[key]:
            new_first[key] = stamp
    bridging = 0
    exact_30min = 0
    nearest_gap_seconds: int | None = None
    for key in old_last.keys() & new_first.keys():
        delta = new_first[key] - old_last[key]
        require(delta.total_seconds() > 0, "non-positive cross-epoch time gap")
        seconds = int(delta.total_seconds())
        nearest_gap_seconds = (
            seconds if nearest_gap_seconds is None
            else min(nearest_gap_seconds, seconds)
        )
        if delta <= gap:
            bridging += 1
            if delta == gap:
                exact_30min += 1
    return {
        "historical_boundary_events_examined": history_events,
        "future_boundary_events_examined": future_events,
        "historical_active_actor_keys": len(old_last),
        "future_active_actor_keys": len(new_first),
        "cross_epoch_actor_overlap": len(old_last.keys() & new_first.keys()),
        "canonical_session_continuations": bridging,
        "exact_30_minute_continuations": exact_30min,
        "closest_cross_epoch_gap_seconds": nearest_gap_seconds,
        "release_boundary_isolation_observed": bridging == 0,
        "global_ip_behavior_stable": False,
        "late_ingestion_watermark_certified": False,
        "historical_cross_epoch_day_certified": False,
        "publication_authorized": False,
        "read_only": True,
    }


def verify(source: Path, checkpoint: Path, ledger: Path, shadow: Path,
           *, max_rows: int, budget_seconds: int) -> dict[str, Any]:
    require(1 <= max_rows <= MAX_ROWS, "invalid boundary scan cap")
    require(5 <= budget_seconds <= MAX_SECONDS, "invalid boundary time limit")
    for path in (source, checkpoint, ledger, shadow):
        require(path.is_file() and not path.is_symlink(),
                "source or sealed private evidence unavailable")
    require(checkpoint.parent == ledger.parent == shadow.parent,
            "private evidence location mismatched")
    require(checkpoint.parent.stat().st_mode & 0o077 == 0,
            "private directory insecure")
    for path in (checkpoint, ledger, shadow):
        require(path.stat().st_mode & 0o777 == 0o600,
                "private evidence file mode drift")
    guard.require_worker_priority()
    require(guard.worker_idle(), "project rollup worker has priority")
    deadline = time.monotonic() + budget_seconds
    lockfd = os.open(checkpoint.parent / ".canary.lock",
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(lockfd).st_mode),
                "private lock file invalid")
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = guard.checkpoint_info(checkpoint)
        guard.verify_frozen(source, checkpoint, info)
        require(info["phase"] == "PASS2_COMPLETE",
                "historical checkpoint not sealed")
        hosts, rules = sessions.verified_state(source, checkpoint, info)
        boundary = datetime.fromisoformat(forward.START)
        require(info["end"] == forward.START,
                "frozen historical boundary differs from forward start")
        gap = timedelta(minutes=SESSION_GAP_MINUTES)
        with closing(v2.source_connection(source)) as raw, closing(
            sqlite3.connect(
                f"file:{ledger.resolve().as_posix()}?mode=ro", uri=True
            )
        ) as future_db, closing(
            sqlite3.connect(
                f"file:{shadow.resolve().as_posix()}?mode=ro", uri=True
            )
        ) as shadow_db:
            raw.execute("PRAGMA query_only=ON")
            future_db.execute("PRAGMA query_only=ON")
            shadow_db.execute("PRAGMA query_only=ON")
            forward.assert_published_history(raw)
            meta = forward.read_metadata(future_db)
            forward.validate_ledger(meta, info)
            require(meta["phase"] == "LIVE",
                    "future evidence capture not LIVE")
            shadow_meta = dict(shadow_db.execute(
                "SELECT key,value FROM shadow_metadata"
            ))
            future_shadow.validate_metadata(
                shadow_meta, future_shadow.fresh_metadata(info, ledger),
            )
            cursor = int(shadow_meta["last_source_rowid"])
            processed = int(shadow_meta["processed_inputs"])
            require(processed >= 0 and
                    processed <= int(meta["accepted"]),
                    "invalid shadow processed prefix")

            placeholder = ",".join("?" for _ in hosts)
            sql = f"""
            SELECT rowid AS source_rowid,event_id,timestamp,ip,line_offset,
                   raw_path,normalized_path,referrer_host,ua,host
            FROM traffic_entries INDEXED BY idx_traffic_entries_timestamp_line_offset
            WHERE timestamp >= ? AND timestamp < ?
              AND rowid <= ? AND host IN ({placeholder})
              AND ({_non_browser_chain_firehose_sql()})
            ORDER BY timestamp ASC,line_offset ASC,rowid ASC LIMIT ?
            """
            old_rows = raw.execute(sql, (
                (boundary-gap).isoformat(), boundary.isoformat(),
                int(info["watermark"]), *hosts, max_rows+1,
            ))
            def historical():
                for row in old_rows:
                    require(time.monotonic() < deadline,
                            "boundary source scan timed out")
                    value = canonical.normalize_row(row, rules=rules)
                    if value is not None:
                        yield value

            new_rows = future_db.execute(
                """SELECT source_rowid,event_json FROM future_events
                   INDEXED BY idx_future_events_timestamp
                   WHERE timestamp>=? AND timestamp<? AND source_rowid<=?
                   ORDER BY timestamp ASC LIMIT ?""",
                (boundary.isoformat(), (boundary+gap).isoformat(),
                 cursor, max_rows+1),
            )
            def future():
                for rowid, payload in new_rows:
                    require(time.monotonic() < deadline,
                            "future boundary scan timed out")
                    fields = json.loads(payload)
                    require(isinstance(fields, dict)
                            and type(fields.get("source_rowid")) is int
                            and fields["source_rowid"] == rowid,
                            "future boundary evidence corrupt")
                    value = canonical.normalize_row(fields, rules=rules)
                    require(value is not None,
                            "retained future boundary input changed")
                    yield value

            result = analyze_boundary(
                historical(), future(), boundary=boundary, max_rows=max_rows,
            )
            require(time.monotonic() < deadline,
                    "boundary comparison exceeded time budget")
            return {
                "result": "PRIVATE_CROSS_EPOCH_BOUNDARY_OBSERVED",
                "sealed_history_last_day": "2026-10-19",
                "sealed_history_sha256": forward.RELEASE_SHA,
                "future_prefix_processed_events": processed,
                "future_prefix_rowid": cursor,
                "future_source_captured": int(meta["accepted"]),
                "future_prefix_backlog_events": int(meta["accepted"])-processed,
                **result,
            }
    finally:
        os.close(lockfd)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("source", "checkpoint", "ledger", "shadow"):
        p.add_argument("--"+arg, required=True, type=Path)
    p.add_argument("--max-rows", type=int, default=20000)
    p.add_argument("--budget-seconds", type=int, default=30)
    a = p.parse_args()
    try:
        print(json.dumps(verify(
            a.source, a.checkpoint, a.ledger, a.shadow,
            max_rows=a.max_rows, budget_seconds=a.budget_seconds,
        ), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, TypeError, KeyError, OSError,
            sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
