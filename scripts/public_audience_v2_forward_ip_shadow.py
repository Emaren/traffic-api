#!/usr/bin/env python3
"""PRIVATE bounded future-pass-one IP behaviour shadow; NEVER publishes audience.

The forward evidence ledger is non-monotonic by source_rowid during BOOTSTRAP:
its timestamp-keyset inserts may add smaller IDs later. A durable rowid
cursor is safe ONLY after the forward collector reports LIVE. This tool
refuses any pass-one writes before that transition.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sqlite3
import stat
import sys
from collections import defaultdict
from contextlib import closing
from pathlib import Path
from typing import Any

from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ledger as ledger
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import rebuild_public_audience_archive as canonical

SHADOW_VERSION = "forward-ip-behavior.shadow.pass1.v1"
SCHEMA = """
CREATE TABLE shadow_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE ip_counts (
  host TEXT NOT NULL, ip TEXT NOT NULL,
  requests INTEGER NOT NULL, direct_referrers INTEGER NOT NULL,
  PRIMARY KEY(host,ip)
);
CREATE TABLE ip_uas (
  host TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL,
  PRIMARY KEY(host,ip,ua)
);
CREATE TABLE ip_paths (
  host TEXT NOT NULL, ip TEXT NOT NULL, path TEXT NOT NULL,
  PRIMARY KEY(host,ip,path)
);
"""


def require(ok: bool, reason: str) -> None:
    guard.require(ok, reason)


def fresh_metadata(historical: dict[str, str], future_file: Path) -> dict[str, str]:
    return {
        "schema": SHADOW_VERSION,
        "source": historical["source"],
        "device": historical["device"],
        "inode": historical["inode"],
        "hosts_sha256": historical["hosts_sha256"],
        "rules_sha256": historical["rules_sha256"],
        "canonical_sha256": historical["canonical_sha256"],
        "historical_source_sha": guard.FROZEN_DIGEST,
        "historical_public_sha": ledger.RELEASE_SHA,
        "forward_ledger_file": str(future_file.resolve()),
        "original_watermark": str(ledger.FROZEN_WATERMARK),
        "last_source_rowid": "0",
        "processed_inputs": "0",
    }


def validate_metadata(meta: dict[str, str], expected: dict[str, str]) -> None:
    for key, value in expected.items():
        if key in ("last_source_rowid", "processed_inputs"):
            continue
        require(meta.get(key) == value, f"IP shadow identity mismatch: {key}")
    require(str(meta.get("last_source_rowid", "")).isdecimal(),
            "IP shadow cursor invalid")
    require(str(meta.get("processed_inputs", "")).isdecimal(),
            "IP shadow processed count invalid")


def initialize(shadow: sqlite3.Connection, expected: dict[str, str]) -> dict[str, str]:
    existing = shadow.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    if not existing:
        shadow.executescript(SCHEMA)
        shadow.executemany(
            "INSERT INTO shadow_metadata VALUES(?,?)", expected.items()
        )
        shadow.commit()
        return dict(expected)
    metadata = dict(shadow.execute("SELECT key,value FROM shadow_metadata"))
    validate_metadata(metadata, expected)
    return metadata


def future_step(
    source: sqlite3.Connection, shadow: sqlite3.Connection,
    meta: dict[str, str], rules: list[dict[str, Any]], *,
    source_phase: str, max_rows: int = 3000,
) -> dict[str, Any]:
    require(source_phase == "LIVE",
            "forward ledger BOOTSTRAP incomplete; rowid pass1 unsafe")
    require(1 <= max_rows <= 10000, "invalid bounded IP shadow page size")
    require(str(meta["last_source_rowid"]).isdecimal(), "invalid cursor")

    rows = source.execute(
        "SELECT source_rowid,event_json FROM future_events "
        "WHERE source_rowid > ? ORDER BY source_rowid LIMIT ?",
        (int(meta["last_source_rowid"]), max_rows),
    ).fetchall()
    # All canonical accepted inputs were captured in future_events.
    # Do not silently allow changes of normalization or visibility semantics.
    grouped: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "direct": 0, "uas": set(), "paths": set()}
    )
    for row in rows:
        raw = json.loads(row["event_json"])
        require(isinstance(raw, dict), "ledger input is not a JSON object")
        require(int(raw["source_rowid"]) == int(row["source_rowid"]),
                "ledger input source rowid mismatch")
        event = canonical.normalize_row(raw, rules=rules)
        require(event is not None, "canonical input normalization drift")
        require(str(event["timestamp_iso"]) >= ledger.START,
                "eligible future input belongs to sealed historical epoch")
        stat = grouped[(event["host"], event["ip"])]
        stat["count"] += 1
        ua = str(event.get("ua") or "").strip().lower()
        if ua:
            stat["uas"].add(ua)
        stat["paths"].add(event["normalized_path"])
        if (event.get("referrer_host") or canonical.UNKNOWN_REFERRER) in {
            canonical.UNKNOWN_REFERRER, "", canonical.UNKNOWN_HOST,
        }:
            stat["direct"] += 1

    shadow.execute("BEGIN IMMEDIATE")
    try:
        shadow.executemany(
            """INSERT INTO ip_counts(host,ip,requests,direct_referrers)
               VALUES (?,?,?,?)
               ON CONFLICT(host,ip) DO UPDATE SET
               requests=requests+excluded.requests,
               direct_referrers=direct_referrers+excluded.direct_referrers""",
            [(host, ip, data["count"], data["direct"])
             for (host, ip), data in grouped.items()],
        )
        shadow.executemany(
            "INSERT OR IGNORE INTO ip_uas VALUES (?,?,?)",
            [(host, ip, ua) for (host, ip), data in grouped.items()
             for ua in data["uas"]],
        )
        shadow.executemany(
            "INSERT OR IGNORE INTO ip_paths VALUES (?,?,?)",
            [(host, ip, path) for (host, ip), data in grouped.items()
             for path in data["paths"]],
        )
        new_cursor = int(rows[-1]["source_rowid"]) if rows else int(
            meta["last_source_rowid"]
        )
        new_count = int(meta["processed_inputs"]) + len(rows)
        shadow.executemany(
            "UPDATE shadow_metadata SET value=? WHERE key=?",
            [(str(new_cursor), "last_source_rowid"),
             (str(new_count), "processed_inputs")],
        )
        shadow.commit()
    except BaseException:
        shadow.rollback()
        raise
    meta.update({
        "last_source_rowid": str(new_cursor),
        "processed_inputs": str(new_count),
    })
    return {
        "step_input_events": len(rows),
        "total_input_events_processed": new_count,
        "last_source_rowid": new_cursor,
        "private_ip_shadow_writes_only": True,
        "daily_classification_ready": False,
        "publication_authorized": False,
    }


def merged_ip_behavior(historical: sqlite3.Connection, future: sqlite3.Connection,
                       host: str, ip: str) -> dict[str, Any]:
    """Equivalent baseline+future IP behaviour (no output of identifiers)."""
    def counts(db: sqlite3.Connection) -> tuple[int, int]:
        row = db.execute(
            "SELECT requests,direct_referrers FROM ip_counts "
            "WHERE host=? AND ip=?", (host, ip),
        ).fetchone()
        return tuple(map(int, row)) if row else (0, 0)

    old_count, old_direct = counts(historical)
    new_count, new_direct = counts(future)
    uas = set()
    paths = set()
    for db in (historical, future):
        uas.update(row[0] for row in db.execute(
            "SELECT ua FROM ip_uas WHERE host=? AND ip=?", (host, ip),
        ))
        paths.update(row[0] for row in db.execute(
            "SELECT path FROM ip_paths WHERE host=? AND ip=?", (host, ip),
        ))
    requests = old_count + new_count
    direct = old_direct + new_direct
    spam = bool(
        requests >= canonical.ROTATING_UA_ROUTE_SPAM_MIN_REQUESTS
        and len(uas) >= canonical.ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_UAS
        and canonical.ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_PATHS
        <= len(paths) <= canonical.ROTATING_UA_ROUTE_SPAM_MAX_UNIQUE_PATHS
        and all(canonical._is_framework_route_bundle_path(p) for p in paths)
        and direct / requests >= canonical.ROTATING_UA_ROUTE_SPAM_DIRECT_RATIO
    )
    return {
        "request_count": requests,
        "unique_uas": len(uas),
        "unique_paths": len(paths),
        "route_bundle_paths": sorted(paths),
        "route_bundle_spam": spam,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    raw = args.source
    baseline = args.checkpoint
    forward_file = args.ledger
    shadow_file = args.shadow
    for path in (raw, baseline, forward_file):
        require(path.is_file() and not path.is_symlink(),
                "required SQLite evidence absent or symlink")
    require((baseline.stat().st_mode & 0o777) == 0o600
            and (forward_file.stat().st_mode & 0o777) == 0o600,
            "private evidence files must be mode 0600")
    require(forward_file.parent == baseline.parent == shadow_file.parent,
            "all private evidence must use same protected directory")
    require((baseline.parent.stat().st_mode & 0o077) == 0,
            "canary directory must be private")
    require(shadow_file not in (baseline, forward_file, raw),
            "shadow file aliases sealed evidence")
    require(not shadow_file.is_symlink(), "shadow symlink refused")
    require(1 <= args.max_rows <= 10000, "invalid max rows")
    require(not args.advance or args.approve_private_write,
            "advance requires explicit private write approval")
    if args.advance:
        guard.require_worker_priority()
        require(guard.worker_idle(), "project rollup worker busy")

    lock_path = baseline.parent / ".canary.lock"
    lock_fd = os.open(lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(lock_fd).st_mode),
                "canary lock path not regular")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = guard.checkpoint_info(baseline)
        guard.verify_frozen(raw, baseline, info)
        require(info["phase"] == "PASS2_COMPLETE",
                "certified historic checkpoint incomplete")
        hosts, rules = sessions.verified_state(raw, baseline, info)
        require(bool(hosts), "canonical project hosts missing")
        expected = fresh_metadata(info, forward_file)
        with closing(v2.source_connection(raw)) as src:
            ledger.assert_published_history(src)
        with closing(sqlite3.connect(
            f"file:{forward_file.resolve().as_posix()}?mode=ro", uri=True,
        )) as future:
            future.row_factory = sqlite3.Row
            future.execute("PRAGMA query_only=ON")
            forward_meta = ledger.read_metadata(future)
            ledger.validate_ledger(forward_meta, info)
            phase = forward_meta["phase"]
            require(phase in ("BOOTSTRAP", "LIVE"),
                    "forward ledger phase invalid")

            if not args.advance:
                if shadow_file.exists():
                    require(shadow_file.is_file()
                            and (shadow_file.stat().st_mode & 0o777) == 0o600,
                            "IP shadow file not private")
                    with closing(sqlite3.connect(
                        f"file:{shadow_file.resolve().as_posix()}?mode=ro", uri=True,
                    )) as shadow:
                        meta = dict(shadow.execute(
                            "SELECT key,value FROM shadow_metadata"
                        ))
                    validate_metadata(meta, expected)
                else:
                    meta = expected
                processed = int(meta["processed_inputs"])
                require(processed <= int(forward_meta["accepted"]),
                        "shadow processed more events than forward ledger")
                return {
                    "result": ("READY_PRIVATE_PASS1" if phase == "LIVE"
                               else "BLOCKED_BOOTSTRAP"),
                    "forward_phase": phase,
                    "forward_retained_events": int(forward_meta["accepted"]),
                    "shadow_processed_events": processed,
                    "remaining_retained_events": int(forward_meta["accepted"]) - processed,
                    "private_ip_shadow_writes_only": True,
                    "daily_classification_ready": False,
                    "publication_authorized": False,
                }

            require(phase == "LIVE",
                    "bootstrap unfinished; refuse rowid shadow cursor")
            new = not shadow_file.exists()
            if new:
                fd = os.open(shadow_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            require(shadow_file.is_file()
                    and (shadow_file.stat().st_mode & 0o777) == 0o600,
                    "IP shadow file not regular 0600 file")
            with closing(sqlite3.connect(shadow_file, timeout=1)) as shadow:
                shadow.execute("PRAGMA synchronous=FULL")
                meta = initialize(shadow, expected)
                require(int(meta["processed_inputs"]) <= int(forward_meta["accepted"]),
                        "IP shadow count exceeds input count")
                result = future_step(
                    future, shadow, meta, rules,
                    source_phase=phase, max_rows=args.max_rows,
                )
                require(result["total_input_events_processed"]
                        <= int(forward_meta["accepted"]),
                        "shadow overprocessed forward inputs")
                result.update({"result": "PRIVATE_PASS1_STEP",
                               "remaining_retained_events":
                               int(forward_meta["accepted"])
                               - result["total_input_events_processed"]})
                return result
    finally:
        os.close(lock_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--shadow", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=3000)
    parser.add_argument("--advance", action="store_true")
    parser.add_argument("--approve-private-write", action="store_true")
    a = parser.parse_args()
    try:
        print(json.dumps(run(a), sort_keys=True))
        return 0
    except (RuntimeError, OSError, ValueError, KeyError,
            TypeError, sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
