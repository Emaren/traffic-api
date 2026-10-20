#!/usr/bin/env python3
"""Checkpoint the FIRST canonical public-audience pass; shadow-only, no publish."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.services.traffic.config import PERSIST_DB_PATH
from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts import rebuild_public_audience_archive as canonical

SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE ip_counts (
  host TEXT NOT NULL, ip TEXT NOT NULL,
  requests INTEGER NOT NULL, direct_referrers INTEGER NOT NULL,
  PRIMARY KEY (host, ip)
);
CREATE TABLE ip_uas (
  host TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL,
  PRIMARY KEY (host, ip, ua)
);
CREATE TABLE ip_paths (
  host TEXT NOT NULL, ip TEXT NOT NULL, path TEXT NOT NULL,
  PRIMARY KEY (host, ip, path)
);
"""
VERSION = "public-audience.pass1.shadow.v1"


def source_connection(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise RuntimeError("STOP: raw Traffic database does not exist")
    conn = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro",
                           uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def source_identity(path: Path, start: str, end: str, watermark: int,
                    hosts: list[str], rules: list[dict[str, Any]]) -> dict[str, str]:
    stat = path.stat()
    return {
        "schema": VERSION,
        "source": str(path.resolve()),
        "device": str(stat.st_dev),
        "inode": str(stat.st_ino),
        "start": start,
        "end": end,
        "watermark": str(watermark),
        "hosts_sha256": hashlib.sha256(json.dumps(hosts).encode()).hexdigest(),
        "rules_sha256": hashlib.sha256(
            json.dumps(rules, sort_keys=True, default=str).encode()
        ).hexdigest(),
        "canonical_sha256": hashlib.sha256(
            Path(canonical.__file__).read_bytes()
        ).hexdigest(),
    }


def select_page(source: sqlite3.Connection, info: dict[str, str],
                hosts: list[str], limit: int) -> list[sqlite3.Row]:
    placeholders = ",".join("?" for _ in hosts)
    sql = f"""
    SELECT rowid AS source_rowid, event_id, timestamp, ip, line_offset,
           raw_path, normalized_path, referrer_host, ua, host
    FROM traffic_entries INDEXED BY idx_traffic_entries_timestamp_line_offset
    WHERE timestamp >= ? AND timestamp < ? AND rowid <= ?
      AND host IN ({placeholders})
      AND ({_non_browser_chain_firehose_sql()})
      AND (timestamp, line_offset, rowid) > (?, ?, ?)
    ORDER BY timestamp ASC, line_offset ASC, rowid ASC LIMIT ?
    """
    return source.execute(sql, (
        info["start"], info["end"], int(info["watermark"]), *hosts,
        info["cursor_time"], int(info["cursor_offset"]),
        int(info["cursor_rowid"]), limit,
    )).fetchall()


def _utc_boundary(raw: str) -> str:
    stamp = datetime.fromisoformat(raw)
    if stamp.tzinfo is None:
        raise RuntimeError("STOP: offset-aware UTC boundary required")
    stamp = stamp.astimezone(timezone.utc)
    if any((stamp.hour, stamp.minute, stamp.second, stamp.microsecond)):
        raise RuntimeError("STOP: only whole UTC days permitted")
    return stamp.isoformat()


def _metadata(state: sqlite3.Connection) -> dict[str, str]:
    return dict(state.execute("SELECT key,value FROM metadata"))


def advance(raw: Path, checkpoint: Path, *, start: str, end: str,
            max_rows: int = 2000, budget_seconds: float = 15) -> dict[str, Any]:
    if not 1 <= max_rows <= 20000 or not 1 <= budget_seconds <= 120:
        raise RuntimeError("STOP: row/time budget outside permitted bounds")
    if raw.resolve() == checkpoint.resolve() or checkpoint.is_symlink():
        raise RuntimeError("STOP: checkpoint aliases raw source or symlink")
    if checkpoint.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("STOP: private checkpoint must stay outside the source repository")
    if end <= start or end > canonical.utc_midnight(datetime.now(timezone.utc).date()).isoformat():
        raise RuntimeError("STOP: full UTC days only")
    hosts = canonical.project_hosts()
    rules = canonical.safe_list_visibility_rules(active_only=True)
    if not hosts:
        raise RuntimeError("STOP: no project hosts")
    new = not checkpoint.exists()
    if new:
        if not checkpoint.parent.is_dir():
            raise RuntimeError("STOP: checkpoint parent missing")
        fd = os.open(checkpoint, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    elif not checkpoint.is_file():
        raise RuntimeError("STOP: checkpoint not a file")

    tick = time.monotonic()
    with source_connection(raw) as src:
        src.set_progress_handler(
            lambda: int(time.monotonic() - tick > budget_seconds), 1000
        )
        with sqlite3.connect(checkpoint, timeout=0.25) as state:
            state.row_factory = sqlite3.Row
            if new:
                # Creates staging tables only. No connection to publication tables.
                state.executescript(SCHEMA)
            state.execute("BEGIN IMMEDIATE")
            if new:
                # O(log N) rowid high-water lookup, rather than scanning
                # millions of timestamp-filtered rows to compute MAX(rowid).
                # The timestamp predicate in select_page still excludes
                # current/future-day rows; both watermarks select exactly
                # the same eligible rows at the captured snapshot.
                watermark = int(src.execute(
                    "SELECT COALESCE(MAX(rowid),0) FROM traffic_entries"
                ).fetchone()[0])
                info = source_identity(raw, start, end, watermark, hosts, rules)
                info.update({
                    "cursor_time": start, "cursor_offset": "-9223372036854775808",
                    "cursor_rowid": "0", "raw_scanned": "0", "accepted": "0",
                    "phase": "PASS1_RUNNING",
                })
                state.executemany("INSERT INTO metadata VALUES(?,?)", info.items())
            else:
                info = _metadata(state)
                if not info:
                    raise RuntimeError(
                        "STOP: incomplete checkpoint initialization; quarantine this "
                        "shadow file and start a fresh checkpoint path."
                    )
                expected = source_identity(
                    raw, start, end, int(info["watermark"]), hosts, rules
                )
                for key, val in expected.items():
                    if info.get(key) != val:
                        raise RuntimeError(f"STOP: input identity changed ({key})")
                if info["phase"] != "PASS1_RUNNING":
                    raise RuntimeError("STOP: completed checkpoint cannot be extended")

            rows = select_page(src, info, hosts, max_rows)
            groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(
                lambda: {"count": 0, "direct": 0, "uas": set(), "paths": set()}
            )
            accepted = 0
            for row in rows:
                item = canonical.normalize_row(row, rules=rules)
                if item is None:
                    continue
                accepted += 1
                key = (item["host"], item["ip"])
                stat = groups[key]
                stat["count"] += 1
                ua = (item.get("ua") or "").lower().strip()
                if ua:
                    stat["uas"].add(ua)
                stat["paths"].add(item["normalized_path"])
                if (item.get("referrer_host") or canonical.UNKNOWN_REFERRER) in {
                    canonical.UNKNOWN_REFERRER, "", canonical.UNKNOWN_HOST,
                }:
                    stat["direct"] += 1

            state.executemany(
                """INSERT INTO ip_counts VALUES(?,?,?,?)
                   ON CONFLICT(host,ip) DO UPDATE SET
                   requests=requests+excluded.requests,
                   direct_referrers=direct_referrers+excluded.direct_referrers""",
                [(host, ip, value["count"], value["direct"])
                 for (host, ip), value in groups.items()],
            )
            state.executemany(
                "INSERT OR IGNORE INTO ip_uas VALUES(?,?,?)",
                [(host, ip, ua) for (host, ip), value in groups.items()
                 for ua in value["uas"]],
            )
            state.executemany(
                "INSERT OR IGNORE INTO ip_paths VALUES(?,?,?)",
                [(host, ip, path) for (host, ip), value in groups.items()
                 for path in value["paths"]],
            )
            updates = {
                "raw_scanned": str(int(info["raw_scanned"]) + len(rows)),
                "accepted": str(int(info["accepted"]) + accepted),
                "phase": "PASS1_COMPLETE" if len(rows) < max_rows else "PASS1_RUNNING",
            }
            if rows:
                updates.update({
                    "cursor_time": str(rows[-1]["timestamp"]),
                    "cursor_offset": str(rows[-1]["line_offset"]),
                    "cursor_rowid": str(rows[-1]["source_rowid"]),
                })
            state.executemany(
                "UPDATE metadata SET value=? WHERE key=?",
                [(value, key) for key, value in updates.items()],
            )
            state.commit()
            info.update(updates)
    return {
        "phase": info["phase"],
        "step_rows": len(rows),
        "step_accepted": accepted,
        "raw_scanned": int(info["raw_scanned"]),
        "accepted": int(info["accepted"]),
        "source_max_rowid": int(info["watermark"]),
        "cursor_date": info["cursor_time"][:10],
        "publish_authorized": False,
        "semantic_equivalence_certified": False,
    }



def one_ip_behavior(checkpoint: Path, host: str, ip: str) -> dict[str, Any]:
    """Fixture/engineering-only exact canonical behavior for a single host/IP."""
    if checkpoint.is_symlink() or not checkpoint.is_file():
        raise RuntimeError("STOP: no checkpoint")
    with sqlite3.connect(f"file:{checkpoint.resolve().as_posix()}?mode=ro",
                         uri=True) as db:
        db.row_factory = sqlite3.Row
        info = _metadata(db)
        if info.get("phase") != "PASS1_COMPLETE":
            raise RuntimeError("STOP: behavior cannot be read before pass one completes")
        count = db.execute(
            "SELECT requests,direct_referrers FROM ip_counts WHERE host=? AND ip=?",
            (host, ip),
        ).fetchone()
        if count is None:
            raise KeyError("host/IP absent from checkpoint")
        uas = {row[0] for row in db.execute(
            "SELECT ua FROM ip_uas WHERE host=? AND ip=?", (host, ip)
        )}
        paths = {row[0] for row in db.execute(
            "SELECT path FROM ip_paths WHERE host=? AND ip=?", (host, ip)
        )}
    requests = int(count["requests"])
    direct = int(count["direct_referrers"])
    suspicious = (
        requests >= canonical.ROTATING_UA_ROUTE_SPAM_MIN_REQUESTS
        and len(uas) >= canonical.ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_UAS
        and canonical.ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_PATHS
            <= len(paths) <= canonical.ROTATING_UA_ROUTE_SPAM_MAX_UNIQUE_PATHS
        and all(canonical._is_framework_route_bundle_path(path) for path in paths)
        and direct / requests >= canonical.ROTATING_UA_ROUTE_SPAM_DIRECT_RATIO
    )
    return {
        "request_count": requests,
        "unique_uas": len(uas),
        "unique_paths": len(paths),
        "route_bundle_paths": sorted(paths),
        "route_bundle_spam": suspicious,
    }



def status(checkpoint: Path) -> dict[str, Any]:
    if checkpoint.is_symlink() or not checkpoint.is_file():
        raise RuntimeError("STOP: no checkpoint")
    with sqlite3.connect(f"file:{checkpoint.resolve().as_posix()}?mode=ro",
                         uri=True) as state:
        info = dict(state.execute("SELECT key,value FROM metadata"))
    if info.get("schema") != VERSION:
        raise RuntimeError("STOP: unrecognized state")
    return {
        "phase": info["phase"], "start": info["start"], "end": info["end"],
        "raw_scanned": int(info["raw_scanned"]),
        "accepted": int(info["accepted"]),
        "source_max_rowid": int(info["watermark"]),
        "publish_authorized": False,
        "semantic_equivalence_certified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("advance", "status"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=PERSIST_DB_PATH)
    parser.add_argument("--start", default=canonical.utc_midnight(canonical.DEFAULT_START).isoformat())
    parser.add_argument("--end", default=canonical.utc_midnight(datetime.now(timezone.utc).date()).isoformat())
    parser.add_argument("--max-rows", type=int, default=2000)
    parser.add_argument("--budget-seconds", type=float, default=15)
    args = parser.parse_args()
    result = (status(args.state) if args.command == "status" else advance(
        args.source, args.state, start=_utc_boundary(args.start),
        end=_utc_boundary(args.end), max_rows=args.max_rows,
        budget_seconds=args.budget_seconds,
    ))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
