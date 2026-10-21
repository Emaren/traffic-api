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
from unittest.mock import patch

from app.services.traffic.config import SESSION_GAP_MINUTES
from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ip_shadow as shadow_mod
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as historical_sessions
from scripts import rebuild_public_audience_archive as canonical

MAX_EVENTS = 200_000
MAX_SECONDS = 45
MAX_AB_SECONDS = 100
MAX_OPEN = 30_000
EVENT_SEGMENT_ROWS = historical_sessions.EVENT_SEGMENT_ROWS
MAX_BUCKET_SESSIONS = 30_000


def require(ok: bool, message: str) -> None:
    guard.require(ok, message)


def read_canonical_inputs(db: sqlite3.Connection, *, rules: list,
                          max_rowid: int, max_events: int,
                          deadline: float,
                          raw_records: bool = False) -> Iterator[dict]:
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
            yield record if raw_records else item


def replay(
    items: Iterable[dict], *,
    behavior: Callable[[str, str], dict],
    reference_now: datetime,
    deadline: float,
) -> tuple[dict[str, list[int]], dict[str, int]]:
    """Run canonical session replay with ephemeral memory-only event chunks.

    The SQLite :memory: database is never written to disk or attached to
    persistent production databases. Chunking never splits canonical sessions.
    """
    with closing(sqlite3.connect(":memory:")) as temporary:
        temporary.execute(
            "CREATE TABLE chunks (token INTEGER NOT NULL,"
            " seq INTEGER NOT NULL, events_json TEXT NOT NULL,"
            " PRIMARY KEY(token,seq)) WITHOUT ROWID"
        )
        return _replay_bounded(
            items, behavior=behavior, reference_now=reference_now,
            deadline=deadline, spool=temporary,
        )


def _replay_bounded(
    items: Iterable[dict], *,
    behavior: Callable[[str, str], dict],
    reference_now: datetime,
    deadline: float,
    spool: sqlite3.Connection,
) -> tuple[dict[str, list[int]], dict[str, int]]:
    """Match the original 30-minute expiry and complete-bucket finalizer."""
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
    token_counter = 0
    max_session_length = 0
    segments_written = 0

    def append_event(state: dict, item: dict) -> None:
        nonlocal segments_written, max_session_length
        # Global event budget and deadline guard RAM/CPU; never split an
        # exact canonical session because it exceeds a guessed row count.
        state["pending"].append(item)
        state["size"] += 1
        max_session_length = max(max_session_length, state["size"])
        if len(state["pending"]) >= EVENT_SEGMENT_ROWS:
            spool.execute(
                "INSERT INTO chunks(token,seq,events_json) VALUES (?,?,?)",
                (state["token"], state["chunk_seq"],
                 historical_sessions.serialize(state["pending"])),
            )
            state["chunk_seq"] += 1
            state["pending"] = []
            segments_written += 1

    def materialize_events(state: dict) -> list[dict]:
        events: list[dict] = []
        for (blob,) in spool.execute(
            "SELECT events_json FROM chunks WHERE token=? ORDER BY seq",
            (state["token"],),
        ):
            part = historical_sessions.deserialize(blob)
            require(isinstance(part, list)
                    and 0 < len(part) <= EVENT_SEGMENT_ROWS,
                    "invalid ephemeral session segment")
            events.extend(part)
        events.extend(state["pending"])
        require(len(events) == state["size"] and bool(events),
                "incomplete ephemeral canonical session")
        spool.execute("DELETE FROM chunks WHERE token=?", (state["token"],))
        return events

    def close(key: tuple[str, str, str], state: dict) -> None:
        nonlocal finalized
        events = materialize_events(state)
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
            token_counter += 1
            state = {
                "pending": [], "size": 0, "chunk_seq": 0,
                "token": token_counter, "last_time": stamp,
                "version": version, "bucket": bucket,
            }
            opened[key] = state
            open_counts[bucket] += 1
        else:
            state["last_time"] = stamp
            state["version"] = version
        append_event(state, item)
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
        "longest_session_events": max_session_length,
        "ephemeral_event_segments_written": segments_written,
        "ephemeral_database_only": True,
    }



def diagnose_session_sizes(
    items: Iterable[dict], *, deadline: float,
) -> dict[str, Any]:
    """Count 30-minute host/IP/UA session lengths without classification.

    Keeps one counter per active actor rather than retaining event payloads;
    identifying actor keys are never included in the result.
    """
    gap = timedelta(minutes=SESSION_GAP_MINUTES)
    active: dict[tuple[str, str, str], tuple[datetime, datetime, int]] = {}
    sizes: list[int] = []
    events = 0
    crossing_midnight = 0
    largest = 0

    def finish(state: tuple[datetime, datetime, int]) -> None:
        nonlocal crossing_midnight, largest
        first, last, length = state
        sizes.append(length)
        largest = max(largest, length)
        if first.date() != last.date():
            crossing_midnight += 1

    for item in items:
        events += 1
        if events % 128 == 0:
            require(time.monotonic() < deadline,
                    "session-size diagnostic time budget exceeded")
        stamp = item["timestamp"]
        require(stamp.tzinfo is not None,
                "session-size diagnostic requires aware timestamps")
        key = (item["host"], item["ip"], (item.get("ua") or "").lower())
        old = active.get(key)
        if old is None:
            active[key] = (stamp, stamp, 1)
            continue
        first, last, length = old
        require(stamp >= last, "session-size input time order regressed")
        if stamp - last > gap:
            finish(old)
            active[key] = (stamp, stamp, 1)
        else:
            active[key] = (first, stamp, length + 1)

    for state in active.values():
        finish(state)
    require(time.monotonic() < deadline,
            "session-size diagnostic time budget exceeded")
    return {
        "result": "PRIVATE_SESSION_SIZE_DIAGNOSTIC_ONLY",
        "source_events_examined": events,
        "sessions_by_exact_30min_gap": len(sizes),
        "largest_session_event_count": largest,
        "largest_five_session_event_counts": sorted(sizes, reverse=True)[:5],
        "sessions_over_20000_events": sum(x > 20000 for x in sizes),
        "sessions_over_50000_events": sum(x > 50000 for x in sizes),
        "cross_midnight_session_chains": crossing_midnight,
        "private_read_only": True,
        "individual_identifiers_in_receipt": False,
        "classification_performed": False,
        "certified_utc_days": [],
        "publication_authorized": False,
    }



def compare_original_stream(
    inputs: sqlite3.Connection,
    historical: sqlite3.Connection,
    ip_evidence: sqlite3.Connection,
    *, rules: list, prefix_cursor: int,
    max_events: int, deadline: float,
    snapshot_now: datetime,
    expected_daily: dict[str, list[int]],
    expected_stats: dict[str, int],
) -> dict[str, Any]:
    """Independent original stream_sessions versus segmented future replay.

    Historical canonical stream_sessions is used UNMODIFIED: only its
    source_rows and visibility-rule provider are temporarily redirected to
    the previously verified read-only future ledger and source policy.
    No source, checkpoint, ledger, shadow or publication writes.
    """
    require(snapshot_now.tzinfo is not None, "snapshot time must be aware")
    actor_behavior = {}
    for host, ip in ip_evidence.execute(
        "SELECT host,ip FROM ip_counts ORDER BY host,ip"
    ):
        require(time.monotonic() < deadline,
                "original A/B behavior preload time budget exceeded")
        actor_behavior[(host, ip)] = shadow_mod.merged_ip_behavior(
            historical, ip_evidence, host, ip,
        )
        require(len(actor_behavior) <= 100_000, "too many IP actors for A/B")

    def readonly_rows(*, start: datetime, end: datetime,
                      snapshot_max_rowid: int) -> Iterator[dict]:
        require(snapshot_max_rowid == prefix_cursor,
                "original stream input snapshot drift")
        require(start == datetime.fromisoformat(forward.START),
                "original stream wrong forward start")
        for raw in read_canonical_inputs(
            inputs, rules=rules, max_rowid=prefix_cursor,
            max_events=max_events, deadline=deadline, raw_records=True,
        ):
            require(time.monotonic() < deadline,
                    "original canonical streaming budget exceeded")
            stamp = datetime.fromisoformat(raw["timestamp"])
            require(start <= stamp < end,
                    "reference raw event outside UTC window")
            yield raw

    # This process is a single CLI worker; scoped mocks cannot touch any
    # live production service and restore original function objects on exit.
    with patch.object(canonical, "source_rows", side_effect=readonly_rows), \
         patch.object(canonical, "safe_list_visibility_rules",
                      return_value=rules):
        original_daily, original_stats = canonical.stream_sessions(
            start=datetime.fromisoformat(forward.START),
            end=snapshot_now,
            behavior=actor_behavior,
            snapshot_max_rowid=prefix_cursor,
        )
    require(original_stats["raw_rows"] == expected_stats["accepted_future_events"],
            "A/B original raw input count differs")
    require(original_stats["accepted_rows"] == expected_stats["accepted_future_events"],
            "A/B original accepted input count differs")
    require(original_stats["finalized_sessions"] == expected_stats["finalized_sessions"],
            "A/B canonical session count disagrees")
    require(original_stats["page_sessions"] == expected_stats["page_sessions"],
            "A/B canonical page session count disagrees")
    require(original_daily == expected_daily,
            "A/B complete canonical daily distributions disagree")
    require(time.monotonic() < deadline, "A/B comparison exceeded time budget")
    return {
        "result": "PRIVATE_FUTURE_SESSION_AB_PARITY_VERIFIED",
        "input_events_compared": original_stats["accepted_rows"],
        "finalized_sessions_compared": original_stats["finalized_sessions"],
        "page_sessions_compared": original_stats["page_sessions"],
        "calendar_days_compared": len(original_daily),
        "original_canonical_stream_sessions_used": True,
        "historical_cross_epoch_parity_certified": False,
        "late_ingestion_watermark_certified": False,
        "future_global_ip_behavior_stable": False,
        "publication_authorized": False,
        "private_read_only": True,
    }


def preview(source: Path, checkpoint: Path, ledger: Path,
            shadow: Path, *, max_events: int, budget_seconds: int,
            inspect_sizes: bool = False,
            compare_original: bool = False) -> dict:
    require(1 <= max_events <= MAX_EVENTS, "invalid private preview event bound")
    require(5 <= budget_seconds <=
            (MAX_AB_SECONDS if compare_original else MAX_SECONDS),
            "invalid private preview time bound")
    require(not (inspect_sizes and compare_original),
            "cannot combine session-size diagnosis with canonical A/B")
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
            if inspect_sizes:
                metrics = diagnose_session_sizes(
                    read_canonical_inputs(
                        inputs, rules=rules, max_rowid=rowid,
                        max_events=max_events, deadline=deadline,
                    ), deadline=deadline,
                )
                require(metrics["source_events_examined"] == processed,
                        "session-size diagnostic did not examine full prefix")
                return {
                    **metrics,
                    "frozen_prefix_events": processed,
                    "prefix_source_rowid": rowid,
                    "forward_total_captured": int(meta["accepted"]),
                    "source_prefix_backlog_events": int(meta["accepted"]) - processed,
                    "pinned_public_through": "2026-10-19",
                    "pinned_public_sha256": forward.RELEASE_SHA,
                }
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
            comparison = {}
            if compare_original:
                comparison = compare_original_stream(
                    inputs, history, pass1, rules=rules,
                    prefix_cursor=rowid, max_events=max_events,
                    deadline=deadline, snapshot_now=now,
                    expected_daily=daily, expected_stats=stats,
                )
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
                "independent_stream_ab": comparison,
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
    p.add_argument("--compare-historical-stream", action="store_true",
                   help="Compare original canonical stream_sessions, no publishing")
    p.add_argument("--inspect-session-sizes", action="store_true",
                   help="Read-only aggregate size diagnostic; never build sessions")
    a = p.parse_args()
    try:
        print(json.dumps(preview(
            a.source, a.checkpoint, a.ledger, a.shadow,
            max_events=a.max_events, budget_seconds=a.budget_seconds,
            inspect_sizes=a.inspect_session_sizes,
            compare_original=a.compare_historical_stream,
        ), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, TypeError, KeyError,
            OSError, sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
