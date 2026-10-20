#!/usr/bin/env python3
"""Compare OLD vs segmented private V2 checkpoint truth, without exposing events.

Read-only on both checkpoints. A matching report is an A/B replay diagnostic;
it is NOT historical semantic certification or public publication approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


def _feed(digest: Any, value: Any) -> None:
    digest.update(json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), default=str,
    ).encode("utf-8"))
    digest.update(b"\n")


def _has_table(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,),
    ).fetchone() is not None


def private_checkpoint_fingerprints(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("STOP: require regular private checkpoint, not symlink")
    if path.stat().st_mode & 0o077:
        raise RuntimeError("STOP: checkpoint is not private (mode must be 0600)")
    with closing(sqlite3.connect(
        f"file:{path.resolve().as_posix()}?mode=ro", uri=True,
    )) as db:
        db.execute("PRAGMA query_only=ON")
        meta = dict(db.execute("SELECT key,value FROM metadata"))
        if meta.get("phase") not in ("PASS2_RUNNING", "PASS2_COMPLETE"):
            raise RuntimeError("STOP: incomplete or unrecognized pass-two state")
        fingerprints: dict[str, str] = {}
        counts: dict[str, int] = {}
        for name, sql in (
            ("metadata", "SELECT key,value FROM metadata ORDER BY key"),
            ("daily", "SELECT day,total,suspected,confirmed FROM v2_daily ORDER BY day"),
            ("closed", "SELECT bucket,session_json FROM v2_closed ORDER BY rowid"),
        ):
            h = hashlib.sha256()
            n = 0
            for row in db.execute(sql):
                _feed(h, tuple(row))
                n += 1
            fingerprints[name] = h.hexdigest()
            counts[name] = n

        h = hashlib.sha256()
        n = 0
        has_segments = _has_table(db, "v2_open_segments")
        for host, ip, ua, events, last_time, version, bucket in db.execute(
            """SELECT host,ip,ua,events_json,last_time,version,bucket
               FROM v2_open ORDER BY host,ip,ua"""
        ):
            if events == "[]":
                if not has_segments:
                    raise RuntimeError("STOP: empty open session lacks segment table")
                segments = [
                    value for (value,) in db.execute(
                        """SELECT events_json FROM v2_open_segments
                           WHERE host=? AND ip=? AND ua=? ORDER BY seq""",
                        (host, ip, ua),
                    )
                ]
                if not segments or any(
                    not blob.startswith("[") or not blob.endswith("]")
                    for blob in segments
                ):
                    raise RuntimeError("STOP: missing/corrupt session segments")
                events = "[" + ",".join(blob[1:-1] for blob in segments) + "]"
            _feed(h, (host, ip, ua, events, last_time, version, bucket))
            n += 1
        fingerprints["open"] = h.hexdigest()
        counts["open"] = n
        return {"phase": meta["phase"], "raw": int(meta["p2_raw"]),
                "accepted": int(meta["p2_accepted"]),
                "digest": meta["p2_digest"], "counts": counts,
                "fingerprints": fingerprints}


def compare_checkpoints(original: Path, candidate: Path) -> dict[str, Any]:
    if original.resolve() == candidate.resolve():
        raise RuntimeError("STOP: comparison must use two distinct checkpoints")
    left = private_checkpoint_fingerprints(original)
    right = private_checkpoint_fingerprints(candidate)
    differences = [
        key for key in ("phase", "raw", "accepted", "digest")
        if left[key] != right[key]
    ]
    differences += [
        f"counts.{key}" for key in left["counts"]
        if left["counts"][key] != right["counts"][key]
    ]
    differences += [
        f"fingerprints.{key}" for key in left["fingerprints"]
        if left["fingerprints"][key] != right["fingerprints"][key]
    ]
    return {
        "status": "MATCH" if not differences else "BLOCKED",
        "differences": differences,
        "phase": right["phase"],
        "p2_raw": right["raw"],
        "p2_accepted": right["accepted"],
        "p2_digest": right["digest"],
        "row_counts": right["counts"],
        "private_only": True,
        "publication_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    args = parser.parse_args()
    result = compare_checkpoints(args.original, args.candidate)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "MATCH" else 2


if __name__ == "__main__":
    raise SystemExit(main())
