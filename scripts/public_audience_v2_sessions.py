#!/usr/bin/env python3
"""Bounded canonical session pass TWO. PRIVATE SHADOW OUTPUT ONLY."""
from __future__ import annotations

import argparse
import heapq
import json
import sqlite3
import time
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Any

# Support both 'python -m scripts.public_audience_v2_sessions' and direct-script use.
# A direct script starts with scripts/ on sys.path, not the repository root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.traffic.config import SESSION_GAP_MINUTES, PERSIST_DB_PATH
from scripts import public_audience_v2_checkpoint as v2
from scripts import rebuild_public_audience_archive as canonical

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_open (
  host TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL,
  events_json TEXT NOT NULL, last_time TEXT NOT NULL,
  version INTEGER NOT NULL, bucket INTEGER NOT NULL,
  PRIMARY KEY(host, ip, ua)
);
CREATE TABLE IF NOT EXISTS v2_closed (
  bucket INTEGER NOT NULL,
  session_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_v2_closed_bucket ON v2_closed(bucket);
CREATE TABLE IF NOT EXISTS v2_daily (
  day TEXT PRIMARY KEY,
  total INTEGER NOT NULL, suspected INTEGER NOT NULL, confirmed INTEGER NOT NULL
);
-- Private append-only chunks avoid decoding and rewriting large open sessions
-- for every resumed batch. Existing v2_open JSON is migrated transactionally.
CREATE TABLE IF NOT EXISTS v2_open_segments (
  host TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL,
  seq INTEGER NOT NULL, events_json TEXT NOT NULL,
  PRIMARY KEY(host, ip, ua, seq)
) WITHOUT ROWID;
"""
ACTIVE_SESSION_LIMIT = 50_000
EVENT_SEGMENT_ROWS = 256


def serialize(value: Any) -> str:
    def encode(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return {"__utc_datetime__": obj.isoformat()}
        raise TypeError("STOP: unexpected canonical session state type")
    return json.dumps(value, default=encode, sort_keys=True, separators=(",", ":"))


def deserialize(blob: str) -> Any:
    def decode(obj: dict[str, Any]) -> Any:
        if len(obj) == 1 and "__utc_datetime__" in obj:
            return datetime.fromisoformat(obj["__utc_datetime__"])
        return obj
    return json.loads(blob, object_hook=decode)


def ip_behavior(db: sqlite3.Connection, host: str, ip: str) -> dict[str, Any]:
    counts = db.execute(
        "SELECT requests,direct_referrers FROM ip_counts WHERE host=? AND ip=?",
        (host, ip),
    ).fetchone()
    if counts is None:
        raise RuntimeError("STOP: pass-two IP missing from complete pass-one evidence")
    requests, direct = (int(v) for v in counts)
    ua_count = int(db.execute(
        "SELECT COUNT(*) FROM ip_uas WHERE host=? AND ip=?", (host, ip),
    ).fetchone()[0])
    paths = [r[0] for r in db.execute(
        "SELECT path FROM ip_paths WHERE host=? AND ip=? ORDER BY path",
        (host, ip),
    )]
    spam = (
        requests >= canonical.ROTATING_UA_ROUTE_SPAM_MIN_REQUESTS
        and ua_count >= canonical.ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_UAS
        and canonical.ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_PATHS <= len(paths)
        <= canonical.ROTATING_UA_ROUTE_SPAM_MAX_UNIQUE_PATHS
        and all(canonical._is_framework_route_bundle_path(p) for p in paths)
        and direct / requests >= canonical.ROTATING_UA_ROUTE_SPAM_DIRECT_RATIO
    )
    return {
        "request_count": requests,
        "unique_uas": ua_count,
        "unique_paths": len(paths),
        "route_bundle_paths": paths,
        "route_bundle_spam": bool(spam),
    }


def verified_state(raw: Path, checkpoint: Path, info: dict[str, str]) -> tuple[list[str], list[dict[str, Any]]]:
    if info.get("phase") not in {"PASS1_COMPLETE", "PASS2_RUNNING", "PASS2_COMPLETE"}:
        raise RuntimeError("STOP: full pass-one required before session pass")
    hosts = canonical.project_hosts()
    rules = v2.source_visibility_rules(raw)
    expected = v2.source_identity(
        raw, info["start"], info["end"], int(info["watermark"]), hosts, rules,
    )
    for key, val in expected.items():
        if info.get(key) != val:
            raise RuntimeError(f"STOP: source policy mismatch ({key})")
    return hosts, rules



def spill_legacy_open_state(db: sqlite3.Connection) -> int:
    """Convert the original v2_open JSON format without decoding private events.

    Must run *inside* the same checkpoint transaction as the new replay step.
    An interrupted step rolls back this migration and its source cursor together.
    """
    migrated = 0
    for host, ip, ua, blob in db.execute(
        "SELECT host,ip,ua,events_json FROM v2_open WHERE events_json != '[]'"
    ):
        key = (host, ip, ua)
        if db.execute(
            "SELECT 1 FROM v2_open_segments WHERE host=? AND ip=? AND ua=? LIMIT 1",
            key,
        ).fetchone():
            raise RuntimeError("STOP: ambiguous mixed-format private open session")
        if not blob or not blob.startswith("[") or not blob.endswith("]"):
            raise RuntimeError("STOP: invalid legacy open-session JSON envelope")
        db.execute(
            """INSERT INTO v2_open_segments
               (host,ip,ua,seq,events_json) VALUES(?,?,?,0,?)""",
            (*key, blob),
        )
        db.execute(
            "UPDATE v2_open SET events_json='[]' WHERE host=? AND ip=? AND ua=?",
            key,
        )
        migrated += 1
    return migrated


def collect_session_events(
    db: sqlite3.Connection, key: tuple[str, str, str],
    pending: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Materialize the full canonical event sequence *only at session close*."""
    events: list[dict[str, Any]] = []
    for (blob,) in db.execute(
        """SELECT events_json FROM v2_open_segments
           WHERE host=? AND ip=? AND ua=? ORDER BY seq""", key,
    ):
        chunk = deserialize(blob)
        if not isinstance(chunk, list) or not chunk:
            raise RuntimeError("STOP: corrupt private session segment")
        events.extend(chunk)
    events.extend(pending)
    return events


def save_pending_segments(
    db: sqlite3.Connection, key: tuple[str, str, str],
    pending: list[dict[str, Any]],
) -> None:
    if not pending:
        return
    first_seq = int(db.execute(
        """SELECT COALESCE(MAX(seq), -1) + 1 FROM v2_open_segments
           WHERE host=? AND ip=? AND ua=?""", key,
    ).fetchone()[0])
    for offset in range(0, len(pending), EVENT_SEGMENT_ROWS):
        db.execute(
            """INSERT INTO v2_open_segments
               (host,ip,ua,seq,events_json) VALUES(?,?,?,?,?)""",
            (*key, first_seq + offset // EVENT_SEGMENT_ROWS,
             serialize(pending[offset:offset + EVENT_SEGMENT_ROWS])),
        )


def pass2_step(raw: Path, checkpoint: Path, *, max_rows: int = 2000,
               budget_seconds: float = 15) -> dict[str, Any]:
    if not 1 <= max_rows <= 20_000 or not 1 <= budget_seconds <= 120:
        raise RuntimeError("STOP: bounded page/time budget required")
    if checkpoint.is_symlink() or not checkpoint.is_file():
        raise RuntimeError("STOP: private pass-one checkpoint required")
    if raw.resolve() == checkpoint.resolve():
        raise RuntimeError("STOP: cannot use raw source as checkpoint")

    tick = time.monotonic()
    with closing(v2.source_connection(raw)) as src, closing(sqlite3.connect(checkpoint, timeout=0.25)) as db:
        src.set_progress_handler(lambda: int(time.monotonic()-tick > budget_seconds), 1000)
        db.row_factory = sqlite3.Row
        info = v2._metadata(db)
        hosts, rules = verified_state(raw, checkpoint, info)
        if info["phase"] == "PASS2_COMPLETE":
            raise RuntimeError("STOP: pass-two already complete")
        # Create only private local tables, never the published Traffic rollup.
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        spill_legacy_open_state(db)
        if info["phase"] == "PASS1_COMPLETE":
            additions = {
                "phase": "PASS2_RUNNING",
                "p2_cursor_time": info["start"],
                "p2_cursor_offset": "-9223372036854775808",
                "p2_cursor_rowid": "0",
                "p2_raw": "0", "p2_accepted": "0", "p2_finalized": "0",
                "p2_pages": "0", "p2_version": "0",
                "p2_digest": v2.EMPTY_DIGEST,
                "p2_now": datetime.now(timezone.utc).isoformat(),
            }
            db.executemany(
                "INSERT INTO metadata VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                additions.items(),
            )
            info.update(additions)
        cursor_info = {
            **info,
            "cursor_time": info["p2_cursor_time"],
            "cursor_offset": info["p2_cursor_offset"],
            "cursor_rowid": info["p2_cursor_rowid"],
        }
        rows = v2.select_page(src, cursor_info, hosts, max_rows)
        open_map: dict[tuple[str, str, str], dict[str, Any]] = {}
        expiry: list[tuple[float, int, tuple[str, str, str]]] = []
        open_count: Counter[int] = Counter()
        for row in db.execute(
            "SELECT host,ip,ua,last_time,version,bucket FROM v2_open"
        ):
            key = (row["host"], row["ip"], row["ua"])
            state = {
                "events": [],
                "last_time": datetime.fromisoformat(row["last_time"]),
                "version": int(row["version"]),
                "bucket_id": int(row["bucket"]),
            }
            open_map[key] = state
            open_count[state["bucket_id"]] += 1
            heapq.heappush(expiry, (
                (state["last_time"]+timedelta(minutes=SESSION_GAP_MINUTES)).timestamp(),
                state["version"], key,
            ))
        if len(open_map) > ACTIVE_SESSION_LIMIT:
            raise RuntimeError("STOP: too many cross-batch open sessions")
        zero: list[int] = [
            row[0] for row in db.execute("SELECT DISTINCT bucket FROM v2_closed")
            if open_count.get(int(row[0]), 0) == 0
        ]
        heapq.heapify(zero)
        version = int(info["p2_version"])
        finalized = 0
        pages = 0
        accepted = 0
        # Metrics never contain IPs, UAs, paths, or serialized events.
        metrics = {
            "max_closed_session_events": 0,
            "max_close_collect_seconds": 0.0,
            "max_close_classify_seconds": 0.0,
            "max_flushed_bucket_sessions": 0,
            "max_bucket_classify_seconds": 0.0,
        }
        now = datetime.fromisoformat(info["p2_now"])
        gap = timedelta(minutes=SESSION_GAP_MINUTES)
        cache: dict[tuple[str, str], dict[str, Any]] = {}

        def close(key: tuple[str, str, str], state: dict[str, Any]) -> None:
            nonlocal finalized
            collecting = time.monotonic()
            events = collect_session_events(db, key, state["events"])
            metrics["max_close_collect_seconds"] = max(
                metrics["max_close_collect_seconds"],
                round(time.monotonic() - collecting, 4),
            )
            metrics["max_closed_session_events"] = max(
                metrics["max_closed_session_events"], len(events),
            )
            if not events:
                raise RuntimeError("STOP: open session has no canonical events")
            host_ip = (events[0]["host"], events[0]["ip"])
            if host_ip not in cache:
                if len(cache) >= 4096:
                    cache.clear()
                cache[host_ip] = ip_behavior(db, *host_ip)
            classifying = time.monotonic()
            session = canonical.build_single_session(
                events, now=now, ip_behavior=cache[host_ip],
            )
            metrics["max_close_classify_seconds"] = max(
                metrics["max_close_classify_seconds"],
                round(time.monotonic() - classifying, 4),
            )
            bucket = state["bucket_id"]
            db.execute(
                "INSERT INTO v2_closed(bucket,session_json) VALUES(?,?)",
                (bucket, serialize(session)),
            )
            db.execute(
                "DELETE FROM v2_open_segments WHERE host=? AND ip=? AND ua=?",
                key,
            )
            open_count[bucket] -= 1
            if open_count[bucket] == 0:
                heapq.heappush(zero, bucket)
            finalized += 1

        def expire(current: datetime) -> None:
            threshold = current.timestamp()
            while expiry and expiry[0][0] < threshold:
                _, ver, key = heapq.heappop(expiry)
                state = open_map.get(key)
                if state is None or state["version"] != ver:
                    continue
                close(key, state)
                del open_map[key]

        def flush(current: datetime) -> None:
            nonlocal pages
            bucket_limit = canonical.bucket_id(current)
            while zero and zero[0] < bucket_limit:
                bucket = heapq.heappop(zero)
                if open_count.get(bucket, 0) != 0:
                    continue
                sessions = [deserialize(row[0]) for row in db.execute(
                    "SELECT session_json FROM v2_closed WHERE bucket=? ORDER BY rowid",
                    (bucket,),
                )]
                if not sessions:
                    continue
                daily: dict[str, list[int]] = {}
                metrics["max_flushed_bucket_sessions"] = max(
                    metrics["max_flushed_bucket_sessions"], len(sessions),
                )
                classifying_bucket = time.monotonic()
                pages += canonical.finalize_bucket(sessions, daily)
                metrics["max_bucket_classify_seconds"] = max(
                    metrics["max_bucket_classify_seconds"],
                    round(time.monotonic() - classifying_bucket, 4),
                )
                for day, (total, suspected, confirmed) in daily.items():
                    db.execute(
                        """INSERT INTO v2_daily VALUES(?,?,?,?)
                           ON CONFLICT(day) DO UPDATE SET
                           total=total+excluded.total,
                           suspected=suspected+excluded.suspected,
                           confirmed=confirmed+excluded.confirmed""",
                        (day, total, suspected, confirmed),
                    )
                db.execute("DELETE FROM v2_closed WHERE bucket=?", (bucket,))
                open_count.pop(bucket, None)

        for idx, row in enumerate(rows):
            if idx % 128 == 0 and time.monotonic() - tick > budget_seconds:
                raise RuntimeError("STOP: pass-two CPU time budget exhausted")
            item = canonical.normalize_row(row, rules=rules)
            if item is None:
                continue
            accepted += 1
            stamp = item["timestamp"]
            expire(stamp)
            flush(stamp)
            key = (item["host"], item["ip"], (item.get("ua") or "").lower())
            state = open_map.get(key)
            version += 1
            if state is None:
                bucket = canonical.bucket_id(stamp)
                state = {
                    "events": [item], "last_time": stamp,
                    "version": version, "bucket_id": bucket,
                }
                open_map[key] = state
                open_count[bucket] += 1
            else:
                state["events"].append(item)
                state["last_time"] = stamp
                state["version"] = version
            heapq.heappush(expiry, (
                (stamp+gap).timestamp(), version, key,
            ))
            if len(open_map) > ACTIVE_SESSION_LIMIT:
                raise RuntimeError("STOP: bounded open-session limit exceeded")
        complete = len(rows) < max_rows
        if complete:
            for key, state in list(open_map.items()):
                close(key, state)
                del open_map[key]
            # canonical stream_sessions closes open sessions at EOF, then
            # flushes all buckets in ascending order.
            flush(datetime.fromisoformat(info["end"]) + timedelta(days=1))
            rest = db.execute("SELECT COUNT(*) FROM v2_closed").fetchone()[0]
            if rest:
                raise RuntimeError("STOP: unfinished burst buckets at end-of-input")
        db.execute("DELETE FROM v2_open")
        for (host, ip, ua), state in open_map.items():
            key = (host, ip, ua)
            save_pending_segments(db, key, state["events"])
            db.execute(
                "INSERT INTO v2_open VALUES(?,?,?,?,?,?,?)",
                (host, ip, ua, "[]",
                 state["last_time"].isoformat(), state["version"], state["bucket_id"]),
            )
        updates = {
            "phase": "PASS2_COMPLETE" if complete else "PASS2_RUNNING",
            "p2_raw": str(int(info["p2_raw"])+len(rows)),
            "p2_accepted": str(int(info["p2_accepted"])+accepted),
            "p2_finalized": str(int(info["p2_finalized"])+finalized),
            "p2_pages": str(int(info["p2_pages"])+pages),
            "p2_version": str(version),
            "p2_digest": v2.chain_source_digest(info["p2_digest"], rows),
        }
        if rows:
            updates.update({
                "p2_cursor_time": str(rows[-1]["timestamp"]),
                "p2_cursor_offset": str(rows[-1]["line_offset"]),
                "p2_cursor_rowid": str(rows[-1]["source_rowid"]),
            })
        if complete and (
            int(updates["p2_raw"]) != int(info["raw_scanned"])
            or int(updates["p2_accepted"]) != int(info["accepted"])
            or updates["p2_digest"] != info["p1_digest"]
        ):
            raise RuntimeError(
                "STOP: first and second source passes differ; shadow classification denied"
            )
        db.executemany(
            "UPDATE metadata SET value=? WHERE key=?",
            [(v, k) for k, v in updates.items()],
        )
        db.commit()
    return {
        "phase": updates["phase"], "step_rows": len(rows),
        "step_accepted": accepted,
        "total_raw": int(updates["p2_raw"]),
        "total_finalized": int(updates["p2_finalized"]),
        "total_page_sessions": int(updates["p2_pages"]),
        "open_sessions": len(open_map),
        "raw_source_parity": bool(complete and updates["p2_digest"] == info["p1_digest"]),
        "publication_authorized": False,
        "semantic_equivalence_certified": False,
        "performance": metrics,
    }


def shadow_daily(checkpoint: Path) -> dict[str, list[int]]:
    if checkpoint.is_symlink() or not checkpoint.is_file():
        raise RuntimeError("STOP: no private checkpoint")
    with closing(sqlite3.connect(f"file:{checkpoint.resolve().as_posix()}?mode=ro",
                                 uri=True)) as db:
        info = dict(db.execute("SELECT key,value FROM metadata"))
        if info.get("phase") != "PASS2_COMPLETE":
            raise RuntimeError("STOP: daily shadow report requires complete pass two")
        if info.get("p1_digest") != info.get("p2_digest"):
            raise RuntimeError("STOP: raw source digest mismatch")
        return {day: [t, s, c] for day, t, s, c in db.execute(
            "SELECT day,total,suspected,confirmed FROM v2_daily ORDER BY day",
        )}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("advance", "shadow"))
    parser.add_argument("--source", type=Path, default=PERSIST_DB_PATH)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=2000)
    parser.add_argument("--budget-seconds", type=float, default=15)
    args = parser.parse_args()
    result = (shadow_daily(args.state) if args.command == "shadow" else pass2_step(
        args.source, args.state, max_rows=args.max_rows,
        budget_seconds=args.budget_seconds,
    ))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
