#!/usr/bin/env python3
"""READ-ONLY future canonical-session PREVIEW from a frozen private input prefix.

The result is deliberately UNVERIFIED: source ingestion/late events and
cross-epoch retroactive IP semantics are not certified. No public writes,
no certified-day token, no systemd integration or background scheduler.
"""
from __future__ import annotations

import argparse
import fcntl
import heapq
import itertools
import json
import os
import sqlite3
import stat
import sys
import time
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from app.services.traffic.config import SESSION_GAP_MINUTES
from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ip_shadow as shadow_mod
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as historical_sessions
from scripts import rebuild_public_audience_archive as canonical

MAX_EVENTS = 200_000
MAX_SECONDS = 45
MAX_OPEN = 30_000
MAX_SESSION_EVENTS = 20_000
MAX_BUCKET_SESSIONS = 30_000


def require(ok: bool, message: str) -> None:
    guard.require(ok, message)


def read_canonical_inputs(db: sqlite3.Connection, *, rules: list,
                          max_rowid: int, max_events: int,
                          deadline: float) -> Iterator[dict]:
    """Use timestamp INDEX seek, then original line-offset/rowid tie order.

    Historical source uses (timestamp,line_offset,rowid) ordering.
    Never use future source_rowid ordering for sessionization: BOOTSTRAP
    inserted by timestamp and sessions can span UTC-day boundaries.
    """
    require(0 <= max_rowid, "invalid frozen forward IP cursor")
    statement = db.execute(
        "SELECT timestamp,source_rowid,event_json "
        "FROM future_events INDEXED BY idx_future_events_timestamp "
        "WHERE source_rowid<=? ORDER BY timestamp ASC", (max_rowid,),
    )
    count = 0
    for timestamp, group in itertools.groupby(statement, key=lambda row: row[0]):
        if time.monotonic() >= deadline:
            raise RuntimeError("STOP: session-preview time budget exceeded")
        candidates = []
        for _, rowid, payload in group:
            count += 1
            require(count <= max_events, "future input event cap exceeded")
            record = json.loads(payload)
            require(isinstance(record, dict)
                    and type(record.get("source_rowid")) is int
                    and record["source_rowid"] == rowid
                    and record["timestamp"] == timestamp,
                    "private input evidence mismatch")
            candidates.append(record)
            require(len(candidates) <= MAX_BUCKET_SESSIONS,
                    "too many events share one timestamp")
        for record in sorted(candidates, key=lambda x: (
            int(x["line_offset"] or 0), x["source_rowid"],
        )):
            item = canonical.normalize_row(record, rules=rules)
            require(item is not None, "forward accepted event normalization drift")
            require(item["timestamp_iso"] >= forward.START,
                    "future input targets certified historical epoch")
            yield item


def replay(
    items: Iterable[dict], *,
    behavior: Callable[[str, str], dict],
    reference_now: datetime,
    deadline: float,
) -> tuple[dict[str, list[int]], dict[str, int]]:
    """Match canonical expire/close/bucket/finalize sequence without writes."""
    require(reference_now.tzinfo is not None, "preview now must have timezone")
    gap = timedelta(minutes=SESSION_GAP_MINUTES)
    opened: dict[tuple[str, str, str], dict] = {}
    expiries: list[tuple[float, int, tuple[str, str, str]]] = []
    open_counts: Counter[int] = Counter()
    closed: dict[int, list[dict]] = defaultdict(list)
    ready: list[int] = []
    daily: dict[str, list[int]] = {}
    behavior_cache: dict[tuple[str, str], dict] = {}
    version = 0
    accepted = 0
    finalized = 0
    page_sessions = 0

    def close(key: tuple[str, str, str], state: dict) -> None:
        nonlocal finalized
        events = state["events"]
        require(bool(events), "empty future session")
        actor = (events[0]["host"], events[0]["ip"])
        if actor not in behavior_cache:
            if len(behavior_cache) >= 4096:
                behavior_cache.clear()
            behavior_cache[actor] = behavior(*actor)
        session = canonical.build_single_session(
            events, now=reference_now, ip_behavior=behavior_cache[actor],
        )
        bid = state["bucket"]
        closed[bid].append(session)
        require(len(closed[bid]) <= MAX_BUCKET_SESSIONS,
                "too many closed sessions in burst bucket")
        open_counts[bid] -= 1
        if open_counts[bid] == 0:
            heapq.heappush(ready, bid)
        finalized += 1

    def expire(stamp: datetime) -> None:
        threshold = stamp.timestamp()
        while expiries and expiries[0][0] < threshold:
            _, old_ver, key = heapq.heappop(expiries)
            state = opened.get(key)
            if state is None or state["version"] != old_ver:
                continue
            close(key, state)
            del opened[key]

    def flush(stamp: datetime) -> None:
        nonlocal page_sessions
        upper = canonical.bucket_id(stamp)
        while ready and ready[0] < upper:
            bid = heapq.heappop(ready)
            if open_counts.get(bid, 0):
                continue
            batch = closed.pop(bid, [])
            if batch:
                page_sessions += canonical.finalize_bucket(batch, daily)
            open_counts.pop(bid, None)

    for item in items:
        accepted += 1
        if accepted % 128 == 0:
            require(time.monotonic() < deadline,
                    "session-preview time budget exceeded")
        stamp = item["timestamp"]
        require(stamp.tzinfo is not None, "naive event timestamp forbidden")
        expire(stamp)
        flush(stamp)
        key = (item["host"], item["ip"], (item.get("ua") or "").lower())
        state = opened.get(key)
        version += 1
        if state is None:
            bucket = canonical.bucket_id(stamp)
            state = {
                "events": [item], "last_time": stamp,
                "version": version, "bucket": bucket,
            }
            opened[key] = state
            open_counts[bucket] += 1
        else:
            require(len(state["events"]) < MAX_SESSION_EVENTS,
                    "future session exceeds bounded event limit")
            state["events"].append(item)
            state["last_time"] = stamp
            state["version"] = version
        heapq.heappush(expiries, (
            (stamp + gap).timestamp(), version, key,
        ))
        require(len(opened) <= MAX_OPEN,
                "too many future open sessions")

    # Exactly canonical EOF preview behavior: close all, flush buckets
    # in ascending order. This EOF close is NOT proof of time/day finality.
    for key, state in list(opened.items()):
        close(key, state)
    for bucket in sorted(closed):
        page_sessions += canonical.finalize_bucket(closed[bucket], daily)
    return daily, {
        "accepted_future_events": accepted,
        "finalized_sessions": finalized,
        "page_sessions": page_sessions,
    }


def preview(source: Path, checkpoint: Path, ledger: Path,
            shadow: Path, *, max_events: int, budget_seconds: int) -> dict:
    require(1 <= max_events <= MAX_EVENTS, "invalid private preview event bound")
    require(5 <= budget_seconds <= MAX_SECONDS,
            "invalid private preview time bound")
    for path in (source, checkpoint, ledger, shadow):
        require(path.is_file() and not path.is_symlink(),
                "input or private evidence missing/symlink")
    require(checkpoint.parent == ledger.parent == shadow.parent,
            "private input directories differ")
    require((checkpoint.parent.stat().st_mode & 0o077) == 0,
            "private directory not protected")
    for path in (checkpoint, ledger, shadow):
        require((path.stat().st_mode & 0o777) == 0o600,
                "private evidence permissions drift")
    guard.require_worker_priority()
    require(guard.worker_idle(), "project rollup worker has priority")

    start_clock = time.monotonic()
    deadline = start_clock + budget_seconds
    lock_fd = os.open(checkpoint.parent / ".canary.lock",
                      os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(lock_fd).st_mode),
                "private canary lock invalid")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        historical = guard.checkpoint_info(checkpoint)
        guard.verify_frozen(source, checkpoint, historical)
        require(historical["phase"] == "PASS2_COMPLETE",
                "historical checkpoint not complete")
        _, rules = historical_sessions.verified_state(
            source, checkpoint, historical,
        )
        with closing(v2.source_connection(source)) as db:
            forward.assert_published_history(db)
        with closing(sqlite3.connect(
            f"file:{ledger.resolve().as_posix()}?mode=ro", uri=True,
        )) as inputs, closing(sqlite3.connect(
            f"file:{shadow.resolve().as_posix()}?mode=ro", uri=True,
        )) as pass1, closing(sqlite3.connect(
            f"file:{checkpoint.resolve().as_posix()}?mode=ro", uri=True,
        )) as history:
            for db in (inputs, pass1, history):
                db.execute("PRAGMA query_only=ON")
            meta = forward.read_metadata(inputs)
            forward.validate_ledger(meta, historical)
            require(meta["phase"] == "LIVE", "forward source not LIVE")
            pass1_meta = dict(pass1.execute(
                "SELECT key,value FROM shadow_metadata"
            ))
            shadow_mod.validate_metadata(
                pass1_meta, shadow_mod.fresh_metadata(historical, ledger),
            )
            processed = int(pass1_meta["processed_inputs"])
            rowid = int(pass1_meta["last_source_rowid"])
            prefix = inputs.execute(
                "SELECT COUNT(*) FROM future_events WHERE source_rowid <= ?",
                (rowid,),
            ).fetchone()[0]
            require(prefix == processed and processed > 0,
                    "private pass1 not complete for frozen input prefix")
            require(processed <= max_events,
                    "future input exceeds preview max-events cap")
            now = datetime.now(timezone.utc)
            daily, stats = replay(
                read_canonical_inputs(
                    inputs, rules=rules, max_rowid=rowid,
                    max_events=max_events, deadline=deadline,
                ),
                behavior=lambda host, actor: shadow_mod.merged_ip_behavior(
                    history, pass1, host, actor,
                ),
                reference_now=now, deadline=deadline,
            )
            require(stats["accepted_future_events"] == processed,
                    "canonical preview missed private prefix input")
            require(time.monotonic() <= deadline,
                    "preview exceeded allowed wall time")
            today = now.date().isoformat()
            provisional = {
                day: daily[day] for day in sorted(daily)
                if forward.START[:10] <= day < today
            }
            for values in provisional.values():
                require(len(values) == 3
                        and all(type(x) is int for x in values)
                        and values[0] >= values[1] >= values[2] >= 0,
                        "preview session hierarchy broken")
            return {
                "result": "PRIVATE_CANONICAL_SESSION_PREVIEW_ONLY",
                "pinned_public_through": "2026-10-19",
                "pinned_public_sha256": forward.RELEASE_SHA,
                "frozen_prefix_events": processed,
                "prefix_source_rowid": rowid,
                "forward_total_captured": int(meta["accepted"]),
                "source_prefix_backlog_events": int(meta["accepted"]) - processed,
                "preview_now_utc": now.isoformat(),
                "unverified_past_calendar_day_candidates": provisional,
                "historical_cross_epoch_session_parity_certified": False,
                "late_ingestion_watermark_certified": False,
                "future_global_ip_behavior_stable": False,
                "session_parity_certified": False,
                "no_current_utc_day_published": True,
                "publication_authorized": False,
                "private_read_only": True,
                **stats,
            }
    finally:
        os.close(lock_fd)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "checkpoint", "ledger", "shadow"):
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("--max-events", type=int, default=160_000)
    p.add_argument("--budget-seconds", type=int, default=30)
    a = p.parse_args()
    try:
        print(json.dumps(preview(
            a.source, a.checkpoint, a.ledger, a.shadow,
            max_events=a.max_events, budget_seconds=a.budget_seconds,
        ), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, TypeError, KeyError,
            OSError, sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
