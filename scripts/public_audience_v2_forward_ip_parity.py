#!/usr/bin/env python3
"""Read-only independent private IP-shadow parity against canonical saved inputs.

Recompute each per-(host,IP) count, direct referrer count, and distinct user
agents/paths in memory from the exact retained prefix. Emit aggregate data only.
This is NOT session parity or authority to publish any UTC day.
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

from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_forward_ip_shadow as shadow_mod
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions
from scripts import rebuild_public_audience_archive as canonical


def require(ok: bool, msg: str) -> None:
    guard.require(ok, msg)


def compare(ledger: sqlite3.Connection, shadow: sqlite3.Connection, *,
            rules: list, max_events: int) -> dict:
    meta = dict(shadow.execute("SELECT key,value FROM shadow_metadata"))
    cursor = int(meta["last_source_rowid"])
    processed = int(meta["processed_inputs"])
    require(0 <= processed <= max_events <= 200_000, "parity row budget exceeded")
    require(cursor >= 0, "invalid private IP cursor")
    prefix = int(ledger.execute(
        "SELECT COUNT(*) FROM future_events WHERE source_rowid<=?", (cursor,)
    ).fetchone()[0])
    require(prefix == processed, "ledger prefix and shadow cursor count diverged")

    stats = defaultdict(lambda: [0, 0, set(), set()])
    count = 0
    for rowid, raw_json in ledger.execute(
        "SELECT source_rowid,event_json FROM future_events "
        "WHERE source_rowid<=? ORDER BY source_rowid", (cursor,)
    ):
        count += 1
        require(count <= max_events, "parity memory bound exceeded")
        item = json.loads(raw_json)
        require(type(item) is dict and type(item.get("source_rowid")) is int
                and item["source_rowid"] == rowid,
                "stored forward source rowid drift")
        event = canonical.normalize_row(item, rules=rules)
        require(event is not None, "accepted forward event no longer canonical")
        require(event["timestamp_iso"] >= forward.START,
                "future event belongs to sealed historical epoch")
        entry = stats[(event["host"], event["ip"])]
        entry[0] += 1
        ua = (event.get("ua") or "").lower().strip()
        if ua:
            entry[2].add(ua)
        entry[3].add(event["normalized_path"])
        if (event.get("referrer_host") or canonical.UNKNOWN_REFERRER) in {
            canonical.UNKNOWN_REFERRER, "", canonical.UNKNOWN_HOST
        }:
            entry[1] += 1
    require(count == processed, "incomplete ledger parity scan")

    stored_counts = 0
    for host, ip, requests, direct in shadow.execute(
        "SELECT host,ip,requests,direct_referrers FROM ip_counts"
    ):
        expected = stats.get((host, ip))
        require(expected is not None and (requests, direct) == tuple(expected[:2]),
                "per-actor counts mismatch")
        stored_counts += 1
    require(stored_counts == len(stats), "private shadow missing actor counts")

    stored_uas = 0
    for host, ip, ua in shadow.execute("SELECT host,ip,ua FROM ip_uas"):
        record = stats.get((host, ip))
        require(record is not None and ua in record[2],
                "private UA evidence mismatch")
        record[2].remove(ua)
        stored_uas += 1
    require(all(not record[2] for record in stats.values()),
            "private UA distinct evidence missing")

    stored_paths = 0
    for host, ip, path in shadow.execute("SELECT host,ip,path FROM ip_paths"):
        record = stats.get((host, ip))
        require(record is not None and path in record[3],
                "private normalized path evidence mismatch")
        record[3].remove(path)
        stored_paths += 1
    require(all(not record[3] for record in stats.values()),
            "private distinct path evidence missing")
    return {
        "result": "PRIVATE_CANONICAL_IP_PARITY_VERIFIED",
        "source_events_compared": count,
        "private_actor_records_compared": stored_counts,
        "private_distinct_uas_compared": stored_uas,
        "private_distinct_paths_compared": stored_paths,
        "source_rowid_cursor": cursor,
        "read_only": True,
        "daily_session_parity_certified": False,
        "ready_to_publish_days": [],
        "publication_authorized": False,
    }


def inspect(source: Path, checkpoint: Path, ledger: Path,
            shadow: Path, max_events: int) -> dict:
    require(1 <= max_events <= 200_000, "invalid max event cap")
    for path in (source, checkpoint, ledger, shadow):
        require(path.is_file() and not path.is_symlink(), "source/evidence unavailable")
    require(checkpoint.parent == ledger.parent == shadow.parent,
            "private evidence directories differ")
    require(checkpoint.parent.stat().st_mode & 0o077 == 0,
            "private directory permissions drift")
    for path in (checkpoint, ledger, shadow):
        require(path.stat().st_mode & 0o777 == 0o600,
                "private evidence permissions drift")

    lockfd = os.open(checkpoint.parent / ".canary.lock",
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(stat.S_ISREG(os.fstat(lockfd).st_mode),
                "private canary lock invalid")
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        historical = guard.checkpoint_info(checkpoint)
        guard.verify_frozen(source, checkpoint, historical)
        require(historical["phase"] == "PASS2_COMPLETE",
                "historical checkpoint not completed")
        _, rules = sessions.verified_state(source, checkpoint, historical)
        with closing(v2.source_connection(source)) as src:
            forward.assert_published_history(src)
        with closing(sqlite3.connect(
            f"file:{ledger.resolve().as_posix()}?mode=ro", uri=True,
        )) as input_db, closing(sqlite3.connect(
            f"file:{shadow.resolve().as_posix()}?mode=ro", uri=True,
        )) as ip_db:
            for db in (input_db, ip_db):
                db.execute("PRAGMA query_only=ON")
            state = forward.read_metadata(input_db)
            forward.validate_ledger(state, historical)
            require(state["phase"] == "LIVE",
                    "forward collector bootstrap not completed")
            shadow_state = dict(ip_db.execute(
                "SELECT key,value FROM shadow_metadata"
            ))
            shadow_mod.validate_metadata(
                shadow_state, shadow_mod.fresh_metadata(historical, ledger),
            )
            require(int(shadow_state["processed_inputs"]) <= int(state["accepted"]),
                    "shadow count exceeds retained input evidence")
            return compare(input_db, ip_db, rules=rules, max_events=max_events)
    finally:
        os.close(lockfd)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "checkpoint", "ledger", "shadow"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--max-events", type=int, default=100_000)
    a = p.parse_args()
    try:
        print(json.dumps(inspect(
            a.source, a.checkpoint, a.ledger, a.shadow, a.max_events,
        ), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, TypeError, KeyError,
            OSError, sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
