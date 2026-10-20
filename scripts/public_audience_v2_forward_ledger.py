#!/usr/bin/env python3
"""Bounded PRIVATE forward source ledger after the certified 2026-10-19 archive.

This tool captures future canonical INPUT EVIDENCE, not audience classifications.
Its historical snapshot captured some October 20 entries before the original
rowid watermark; bootstrap those by the original timestamp index first.
Only then scan rowid > frozen watermark. No public writes, no timer activation.
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
from datetime import datetime, timezone
from pathlib import Path

from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import rebuild_public_audience_archive as canonical

RELEASE_SHA = "84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4"
START = "2026-10-20T00:00:00+00:00"
BOOT_END = "2026-10-21T00:00:00+00:00"
FROZEN_WATERMARK = 44_247_247
PRIVATE_SCHEMA = """
CREATE TABLE ledger_metadata (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE future_events (
    source_rowid INTEGER PRIMARY KEY,
    event_json TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX idx_future_events_timestamp
    ON future_events(timestamp);
"""


def require(ok: bool, msg: str) -> None:
    guard.require(ok, msg)


def digest_append(previous: str, rows: list[sqlite3.Row]) -> str:
    return v2.chain_source_digest(previous, rows)


def live_seek_sql(hosts: list[str]) -> str:
    require(bool(hosts), "canonical host set empty")
    placeholder = ",".join("?" for _ in hosts)
    return f"""
      SELECT rowid AS source_rowid,event_id,timestamp,ip,line_offset,
             raw_path,normalized_path,referrer_host,ua,host
      FROM traffic_entries NOT INDEXED
      WHERE rowid > ? AND rowid <= ?
        AND host IN ({placeholder})
        AND ({_non_browser_chain_firehose_sql()})
      ORDER BY rowid ASC LIMIT ?
    """


def read_metadata(db: sqlite3.Connection) -> dict[str, str]:
    return dict(db.execute("SELECT key,value FROM ledger_metadata"))


def validate_ledger(meta: dict[str, str], snapshot: dict[str, str]) -> None:
    for key in ("device", "inode", "hosts_sha256", "rules_sha256",
                "canonical_sha256", "source"):
        require(meta.get(key) == snapshot[key], f"forward ledger {key} drift")
    require(meta.get("original_pass_digest") == guard.FROZEN_DIGEST,
            "forward ledger historical digest drift")
    require(meta.get("historical_public_digest") == RELEASE_SHA,
            "forward ledger published release digest drift")
    require(meta.get("start") == START
            and meta.get("original_watermark") == str(FROZEN_WATERMARK),
            "forward ledger epoch/watermark drift")
    require(meta.get("phase") in ("BOOTSTRAP", "LIVE"),
            "invalid forward ledger phase")


def assert_published_history(source: sqlite3.Connection) -> None:
    rows = source.execute(
        """SELECT bucket_day,total_traffic,suspected_human,confirmed_human
           FROM traffic_public_daily_audience_rollups
           WHERE project_slug='aoe2hdbets' ORDER BY bucket_day"""
    ).fetchall()
    from scripts import public_audience_v2_release_manifest as manifest
    matrix = {r[0]: list(r[1:]) for r in rows}
    require(len(rows) == 131 and len(matrix) == 131
            and min(matrix) == "2026-06-11" and max(matrix) == "2026-10-19"
            and manifest.sha(matrix) == RELEASE_SHA,
            "original 131-day certified public history changed")


def initial_metadata(info: dict[str, str]) -> dict[str, str]:
    return {
        **{key: info[key] for key in (
            "source", "device", "inode", "hosts_sha256", "rules_sha256",
            "canonical_sha256")},
        "original_pass_digest": guard.FROZEN_DIGEST,
        "historical_public_digest": RELEASE_SHA,
        "original_watermark": str(FROZEN_WATERMARK),
        "start": START,
        "phase": "BOOTSTRAP",
        "bootstrap_end": BOOT_END,
        "boot_cursor_time": START,
        "boot_cursor_offset": str(-(2**63)),
        "boot_cursor_rowid": "0",
        "live_rowid": str(FROZEN_WATERMARK),
        "captured": "0",
        "accepted": "0",
        "late_rejected": "0",
        "bootstrap_digest": v2.EMPTY_DIGEST,
        "live_digest": v2.EMPTY_DIGEST,
    }


def safe_initialize(db: sqlite3.Connection, snapshot: dict[str, str]) -> dict[str, str]:
    names = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    if not names:
        db.executescript(PRIVATE_SCHEMA)
        meta = initial_metadata(snapshot)
        db.executemany(
            "INSERT INTO ledger_metadata(key,value) VALUES (?,?)", meta.items()
        )
        db.commit()
        return meta
    meta = read_metadata(db)
    validate_ledger(meta, snapshot)
    return meta


def advance_one(src: sqlite3.Connection, db: sqlite3.Connection,
                meta: dict[str, str], hosts: list[str],
                rules: list[dict], *, cap: int = 3000,
                snapshot_watermark: int | None = None) -> dict:
    """Only the private DB is writable. Commit events and cursor together."""
    require(1 <= cap <= 10_000, "row cap outside approved bounds")
    phase = meta["phase"]
    if phase == "BOOTSTRAP":
        info = {
            "start": START, "end": BOOT_END,
            "watermark": str(FROZEN_WATERMARK),
            "cursor_time": meta["boot_cursor_time"],
            "cursor_offset": meta["boot_cursor_offset"],
            "cursor_rowid": meta["boot_cursor_rowid"],
        }
        rows = v2.select_page(src, info, hosts, cap)
        ceiling = FROZEN_WATERMARK
    elif phase == "LIVE":
        ceiling = int(snapshot_watermark) if snapshot_watermark is not None else int(
            src.execute("SELECT COALESCE(MAX(rowid),0) FROM traffic_entries").fetchone()[0]
        )
        require(ceiling >= int(meta["live_rowid"]),
                "live Traffic source rowid ceiling moved backward")
        rows = src.execute(
            live_seek_sql(hosts),
            (int(meta["live_rowid"]), ceiling, *hosts, cap),
        ).fetchall()
    else:
        raise RuntimeError("STOP: unknown forward-ledger phase")
    updates = {}
    if rows:
        digest_key = "bootstrap_digest" if phase == "BOOTSTRAP" else "live_digest"
        updates[digest_key] = digest_append(meta[digest_key], rows)
    db.execute("BEGIN IMMEDIATE")
    try:
        accepted = 0
        for row in rows:
            item = canonical.normalize_row(row, rules=rules)
            if item is None:
                continue
            # Any late eligible row targeting the recovered history changes
            # its potential meaning: never silently discard it or republish.
            require(item["timestamp_iso"] >= START,
                    "eligible late event targets frozen historical release")
            fields = {key: row[key] for key in v2.RAW_FIELDS}
            db.execute(
                """INSERT INTO future_events(source_rowid,event_json,timestamp)
                   VALUES(?,?,?)""",
                (int(row["source_rowid"]),
                 json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                 str(row["timestamp"])),
            )
            accepted += 1
        if phase == "BOOTSTRAP":
            if rows:
                updates.update({
                    "boot_cursor_time": str(rows[-1]["timestamp"]),
                    "boot_cursor_offset": str(rows[-1]["line_offset"]),
                    "boot_cursor_rowid": str(rows[-1]["source_rowid"]),
                })
            if len(rows) < cap:
                updates["phase"] = "LIVE"
        else:
            updates["live_rowid"] = str(
                ceiling if len(rows) < cap
                else rows[-1]["source_rowid"]
            )
        updates["captured"] = str(int(meta["captured"]) + len(rows))
        updates["accepted"] = str(int(meta["accepted"]) + accepted)
        db.executemany(
            "UPDATE ledger_metadata SET value=? WHERE key=?",
            [(value, key) for key, value in updates.items()],
        )
        db.commit()
    except BaseException:
        db.rollback()
        raise
    meta.update(updates)
    return {
        "phase": meta["phase"],
        "step_source_rows": len(rows),
        "step_retained_events": accepted,
        "total_source_rows": int(meta["captured"]),
        "total_retained_events": int(meta["accepted"]),
        "original_history_unchanged": True,
        "public_audience_writes": False,
        "daily_classification_ready": False,
        "publish_authorized": False,
        "bootstrap_finished": meta["phase"] == "LIVE",
        "source_max_rowid_at_step": ceiling,
    }


def execute(args: argparse.Namespace) -> dict:
    require(args.checkpoint.is_file() and not args.checkpoint.is_symlink(),
            "verified historical checkpoint missing")
    require(args.checkpoint.stat().st_mode & 0o777 == 0o600,
            "historical checkpoint must be 0600")
    require(args.source.is_file() and not args.source.is_symlink(),
            "Traffic source missing or symlink")
    require(args.ledger.parent == args.checkpoint.parent
            and args.ledger != args.checkpoint and
            args.ledger.resolve() != args.source.resolve(),
            "ledger and historical checkpoint must share private directory")
    require(args.ledger.parent.is_dir()
            and args.ledger.parent.stat().st_mode & 0o077 == 0,
            "private canary directory permissions unacceptable")
    require(args.max_rows in range(1, 10001),
            "forward ledger max rows outside bounds")
    require(args.advance is False or args.approve_private_write,
            "private-ledger write requires explicit confirmation")
    require(not args.ledger.is_symlink(), "ledger symlink refused")
    guard.require_worker_priority()
    require(guard.worker_idle(), "project rollup worker active")
    info = guard.checkpoint_info(args.checkpoint)
    guard.verify_frozen(args.source, args.checkpoint, info)
    require(info["phase"] == "PASS2_COMPLETE",
            "full historical replay must stay complete")

    lock = args.checkpoint.parent / ".canary.lock"
    fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode),
                "canary lock not regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        hosts, rules = sessions.verified_state(args.source, args.checkpoint, info)
        with closing(v2.source_connection(args.source)) as src:
            assert_published_history(src)
            require(bool(hosts), "AoE2WAR host selector empty")
            if not args.advance:
                if args.ledger.exists():
                    require(args.ledger.is_file()
                            and args.ledger.stat().st_mode & 0o777 == 0o600,
                            "insecure private forward ledger")
                    with closing(sqlite3.connect(
                        f"file:{args.ledger.resolve().as_posix()}?mode=ro", uri=True
                    )) as db:
                        meta = read_metadata(db)
                    validate_ledger(meta, info)
                    return {
                        "mode": "READ_ONLY", "phase": meta["phase"],
                        "captured": int(meta["captured"]),
                        "accepted": int(meta["accepted"]),
                        "source_verified": True,
                        "historical_public_checksum_unchanged": True,
                        "public_audience_writes": False,
                        "publish_authorized": False,
                    }
                return {
                    "mode": "READ_ONLY", "phase": "NOT_INITIALIZED",
                    "source_verified": True,
                    "historical_public_checksum_unchanged": True,
                    "public_audience_writes": False,
                    "publish_authorized": False,
                }
            fresh = not args.ledger.exists()
            if fresh:
                new_fd = os.open(
                    args.ledger,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY
                    | getattr(os, "O_NOFOLLOW", 0), 0o600,
                )
                os.close(new_fd)
            require(args.ledger.stat().st_mode & 0o777 == 0o600,
                    "forward ledger must be private 0600")
            with closing(sqlite3.connect(args.ledger, timeout=1)) as db:
                db.execute("PRAGMA synchronous=FULL")
                meta = safe_initialize(db, info)
                src.set_progress_handler(
                    lambda: int(time.monotonic() - started > args.budget_seconds),
                    1000,
                )
                started = time.monotonic()
                try:
                    result = advance_one(
                        src, db, meta, hosts, rules, cap=args.max_rows,
                    )
                finally:
                    src.set_progress_handler(None, 0)
                result["mode"] = "PRIVATE_LEDGER_ONLY"
                result["ledger_mode"] = oct(args.ledger.stat().st_mode & 0o777)
                return result
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=3000)
    parser.add_argument("--budget-seconds", type=int, default=12)
    parser.add_argument("--advance", action="store_true")
    parser.add_argument("--approve-private-write", action="store_true")
    a = parser.parse_args()
    try:
        print(json.dumps(execute(a), sort_keys=True), flush=True)
        return 0
    except (ValueError, RuntimeError, sqlite3.Error, OSError, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
