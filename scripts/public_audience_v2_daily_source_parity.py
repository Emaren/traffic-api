#!/usr/bin/env python3
"""Read-only independent Oct20 source/ledger event-identity reconciliation.

Compares retained canonical source events against the frozen forward input
ledger, event for event, using an ephemeral SQLite identity index. It
cannot certify future log delivery or authorize an audience publication.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts import public_audience_v2_checkpoint as checkpoint_mod
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_forward_ip_shadow as future_shadow
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import rebuild_public_audience_archive as canonical

MAX_ROWS = 200_000
MAX_SECONDS = 100
START = date(2026, 10, 20)


def require(condition: bool, reason: str) -> None:
    guard.require(condition, reason)


def event_fingerprint(fields: Any) -> tuple[int, str]:
    """Compare exact canonical raw identities, without emitting PII."""
    require(all(k in fields for k in checkpoint_mod.RAW_FIELDS),
            "canonical event identity missing field")
    rowid = fields["source_rowid"]
    require(type(rowid) is int and rowid > 0, "invalid event rowid")
    payload = json.dumps(
        [fields[k] for k in checkpoint_mod.RAW_FIELDS],
        ensure_ascii=False, separators=(",", ":"), default=str,
    ).encode("utf-8")
    return rowid, hashlib.sha256(payload).hexdigest()


def compare_event_rows(source: Iterable[Any], ledger: Iterable[Any],
                       *, limit: int, deadline: float) -> dict[str, Any]:
    """Independent exact multiset parity with bounded RAM, no disk writes."""
    require(1 <= limit <= MAX_ROWS, "event comparison cap invalid")
    with closing(sqlite3.connect(":memory:")) as scratch:
        scratch.executescript("""
            CREATE TABLE original (source_rowid INTEGER PRIMARY KEY, digest TEXT NOT NULL);
            CREATE TABLE captured (source_rowid INTEGER PRIMARY KEY, digest TEXT NOT NULL);
        """)
        counts: dict[str, int] = {}
        for label, rows in (("original", source), ("captured", ledger)):
            count = 0
            for fields in rows:
                require(time.monotonic() < deadline,
                        "source/ledger parity time budget exceeded")
                count += 1
                require(count <= limit, "source/ledger day exceeds max row cap")
                rowid, digest = event_fingerprint(fields)
                scratch.execute(
                    f"INSERT INTO {label}(source_rowid,digest) VALUES(?,?)",
                    (rowid, digest),
                )
            counts[label] = count
        require(counts["original"] == counts["captured"],
                "source/ledger day canonical row count mismatch")
        discrepancy = scratch.execute("""
            SELECT 1 FROM original AS a
            LEFT JOIN captured AS b ON b.source_rowid=a.source_rowid
            WHERE b.source_rowid IS NULL OR a.digest<>b.digest
            LIMIT 1
        """).fetchone()
        require(discrepancy is None,
                "source/ledger source event identity mismatch")
        missing = scratch.execute("""
            SELECT 1 FROM captured AS b
            LEFT JOIN original AS a ON b.source_rowid=a.source_rowid
            WHERE a.source_rowid IS NULL LIMIT 1
        """).fetchone()
        require(missing is None,
                "ledger contains event not in verified canonical source")
        # Stable digest in SOURCE rowid order, not event timestamp order.
        digest = hashlib.sha256()
        for rowid, event_hash in scratch.execute(
            "SELECT source_rowid,digest FROM original ORDER BY source_rowid"
        ):
            digest.update(f"{rowid}:{event_hash}\n".encode("ascii"))
        return {
            "rows_compared": counts["original"],
            "source_ledger_event_identities_equal": True,
            "source_event_identity_sha256": digest.hexdigest(),
            "comparison_database_memory_only": True,
        }


def run(source: Path, checkpoint: Path, ledger: Path, shadow: Path,
        *, day: str, max_rows: int, budget_seconds: int) -> dict[str, Any]:
    require(1 <= max_rows <= MAX_ROWS, "row cap out of bounds")
    require(5 <= budget_seconds <= MAX_SECONDS, "wall clock cap out of bounds")
    day_value = date.fromisoformat(day)
    require(day_value >= START and day_value < datetime.now(timezone.utc).date(),
            "only past future-epoch completed UTC days may be inspected")
    begin = datetime.combine(day_value, datetime.min.time(), tzinfo=timezone.utc)
    end = begin + timedelta(days=1)
    for path in (source, checkpoint, ledger, shadow):
        require(path.is_file() and not path.is_symlink(),
                "source or private evidence unavailable")
    require(checkpoint.parent == ledger.parent == shadow.parent,
            "private proof directories mismatched")
    require(checkpoint.parent.stat().st_mode & 0o077 == 0,
            "private canary directory mode drift")
    for path in (checkpoint, ledger, shadow):
        require(path.stat().st_mode & 0o777 == 0o600,
                "private proof file permissions drift")
    guard.require_worker_priority()
    require(guard.worker_idle(), "project rollup worker has priority")
    deadline = time.monotonic() + budget_seconds
    lockfd = os.open(checkpoint.parent / ".canary.lock",
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(lockfd).st_mode),
                "private canary lock not regular file")
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = guard.checkpoint_info(checkpoint)
        guard.verify_frozen(source, checkpoint, state)
        require(state["phase"] == "PASS2_COMPLETE",
                "historical canonical snapshot incomplete")
        hosts, rules = sessions.verified_state(source, checkpoint, state)
        with closing(checkpoint_mod.source_connection(source)) as raw, closing(
            sqlite3.connect(
                f"file:{ledger.resolve().as_posix()}?mode=ro", uri=True,
            )
        ) as retained, closing(
            sqlite3.connect(
                f"file:{shadow.resolve().as_posix()}?mode=ro", uri=True,
            )
        ) as ip:
            for db in (raw, retained, ip):
                db.execute("PRAGMA query_only=ON")
            forward.assert_published_history(raw)
            meta = forward.read_metadata(retained)
            forward.validate_ledger(meta, state)
            require(meta["phase"] == "LIVE", "forward evidence not LIVE")
            shadow_meta = dict(ip.execute(
                "SELECT key,value FROM shadow_metadata"
            ))
            future_shadow.validate_metadata(
                shadow_meta, future_shadow.fresh_metadata(state, ledger),
            )
            cursor = int(shadow_meta["last_source_rowid"])
            processed = int(shadow_meta["processed_inputs"])
            require(processed > 0 and processed <= int(meta["accepted"]),
                    "shadow processed cursor incoherent")
            expected_prefix = int(retained.execute(
                "SELECT COUNT(*) FROM future_events WHERE source_rowid<=?",
                (cursor,),
            ).fetchone()[0])
            require(expected_prefix == processed, "private prefix not coherent")
            source_max = int(raw.execute(
                "SELECT COALESCE(MAX(rowid),0) FROM traffic_entries"
            ).fetchone()[0])
            require(source_max >= cursor, "source rowid rewind")
            placeholders = ",".join("?" for _ in hosts)
            sql = f"""
                SELECT rowid AS source_rowid,event_id,timestamp,ip,line_offset,
                       raw_path,normalized_path,referrer_host,ua,host
                FROM traffic_entries
                    INDEXED BY idx_traffic_entries_timestamp_line_offset
                WHERE timestamp>=? AND timestamp<? AND rowid<=?
                    AND host IN ({placeholders})
                    AND ({_non_browser_chain_firehose_sql()})
                ORDER BY timestamp ASC,line_offset ASC,rowid ASC LIMIT ?
            """
            source_query = raw.execute(sql, (
                begin.isoformat(), end.isoformat(), cursor,
                *hosts, max_rows + 1,
            ))
            def canonical_rows():
                scanned = 0
                for row in source_query:
                    scanned += 1
                    require(scanned <= max_rows, "day source scan cap exceeded")
                    require(time.monotonic() < deadline,
                            "canonical source day scan timed out")
                    if canonical.normalize_row(row, rules=rules) is not None:
                        yield row

            ledger_query = retained.execute(
                """SELECT source_rowid,event_json FROM future_events
                   INDEXED BY idx_future_events_timestamp
                   WHERE timestamp>=? AND timestamp<?
                     AND source_rowid<=?
                   ORDER BY timestamp ASC LIMIT ?""",
                (begin.isoformat(), end.isoformat(), cursor, max_rows + 1),
            )
            def ledger_rows():
                count = 0
                for rowid, payload in ledger_query:
                    count += 1
                    require(count <= max_rows, "future ledger day cap exceeded")
                    require(time.monotonic() < deadline,
                            "private ledger day scan timed out")
                    record = json.loads(payload)
                    require(type(record) is dict
                            and record.get("source_rowid") == rowid,
                            "private ledger event identity corrupt")
                    require(canonical.normalize_row(record, rules=rules)
                            is not None, "private ledger contains newly hidden input")
                    yield record

            parity = compare_event_rows(
                canonical_rows(), ledger_rows(), limit=max_rows,
                deadline=deadline,
            )
            require(time.monotonic() < deadline,
                    "day-source parity exceeded wall budget")
            return {
                "result": "PRIVATE_CLOSED_DAY_SOURCE_LEDGER_PARITY_VERIFIED",
                "day": day,
                "historical_release_through": "2026-10-19",
                "historical_release_sha256": forward.RELEASE_SHA,
                "frozen_private_ip_prefix_rowid": cursor,
                "private_ip_events_processed": processed,
                "captured_events_after_private_ip_prefix":
                    int(meta["accepted"])-processed,
                "source_rows_after_private_ip_prefix": source_max-cursor,
                "source_fully_captured_at_snapshot": source_max == cursor,
                "future_log_delivery_complete": False,
                "absolute_late_ingestion_bound_proven": False,
                "global_ip_classification_stable": False,
                "joint_historical_boundary_parity_certified": False,
                "publication_authorized": False,
                "private_read_only": True,
                **parity,
            }
    finally:
        os.close(lockfd)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "checkpoint", "ledger", "shadow"):
        p.add_argument("--"+name, required=True, type=Path)
    p.add_argument("--day", required=True)
    p.add_argument("--max-rows", type=int, default=180000)
    p.add_argument("--budget-seconds", type=int, default=70)
    args = p.parse_args()
    try:
        print(json.dumps(run(
            args.source, args.checkpoint, args.ledger, args.shadow,
            day=args.day, max_rows=args.max_rows,
            budget_seconds=args.budget_seconds,
        ), sort_keys=True))
        return 0
    except (ValueError, RuntimeError, KeyError, OSError,
            sqlite3.Error, BlockingIOError, TypeError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
