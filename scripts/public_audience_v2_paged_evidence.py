#!/usr/bin/env python3
"""Read-only bounded page continuation for canonical Traffic V2 day evidence.

Source-only primitive: no certified sessions, delivery witness, public writes,
service changes, or permission to replace the original 131 published days.
The immutable source prefix and host/rules identities MUST be established by
the preexisting guard/forward-ledger preflight before calling inspect_page.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time

from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts.public_audience_v2_day_ingest_evidence import (
    completed_day, evaluate_rows, require,
)

PAGE_CEILING = 20_000
INITIAL_DIGEST = hashlib.sha256(b"").hexdigest()
STATE_FIELDS = frozenset((
    "day", "source_epoch_sha256", "host_rules_sha256",
    "snapshot_rowid", "forward_prefix_rowid", "last_key",
    "pages", "total_rows", "missing_receipts", "invalid_clocks",
    "chain_sha256", "source_prefix_exhausted",
))


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _ordered_key(key: object, start: datetime, end: datetime) -> tuple[str, int, int]:
    require(isinstance(key, list) and len(key) == 3, "invalid continuation key")
    stamp, offset, rowid = key
    require(isinstance(stamp, str) and isinstance(offset, int)
            and not isinstance(offset, bool) and isinstance(rowid, int)
            and not isinstance(rowid, bool) and offset >= 0 and rowid > 0,
            "invalid continuation key members")
    parsed = datetime.fromisoformat(stamp)
    require(parsed.tzinfo is not None and
            start <= parsed.astimezone(timezone.utc) < end,
            "continuation outside canonical UTC day")
    return stamp, offset, rowid


def _state(day: str, source_epoch: str, host_rules: str,
           snapshot: int, prefix: int, continuation: dict | None,
           start: datetime, end: datetime) -> dict:
    require(_valid_digest(source_epoch) and _valid_digest(host_rules),
            "unbound source epoch or host policy hash")
    require(isinstance(snapshot, int) and not isinstance(snapshot, bool)
            and snapshot > 0 and isinstance(prefix, int)
            and not isinstance(prefix, bool) and prefix >= snapshot,
            "invalid fixed source/forward prefix")
    fresh = dict(
        day=day, source_epoch_sha256=source_epoch,
        host_rules_sha256=host_rules,
        snapshot_rowid=snapshot, forward_prefix_rowid=prefix,
        last_key=None, pages=0, total_rows=0,
        missing_receipts=0, invalid_clocks=0,
        chain_sha256=INITIAL_DIGEST, source_prefix_exhausted=False,
    )
    if continuation is None:
        return fresh
    require(type(continuation) is dict and set(continuation) == STATE_FIELDS,
            "continuation state shape drift")
    for field in ("day", "source_epoch_sha256", "host_rules_sha256",
                  "snapshot_rowid", "forward_prefix_rowid"):
        require(continuation[field] == fresh[field],
                "source/day/prefix continuation drift")
    require(_valid_digest(continuation["chain_sha256"]),
            "invalid continuation chain digest")
    for field in ("pages", "total_rows", "missing_receipts", "invalid_clocks"):
        x = continuation[field]
        require(type(x) is int and x >= 0, "invalid continuation count")
    require(type(continuation["source_prefix_exhausted"]) is bool,
            "completed-prefix flag invalid")
    require(continuation["pages"] < 1_000_000
            and continuation["missing_receipts"] <= continuation["total_rows"]
            and continuation["invalid_clocks"] <= continuation["total_rows"],
            "continuation count drift")
    if continuation["pages"] == 0:
        require(continuation["last_key"] is None
                and continuation["chain_sha256"] == INITIAL_DIGEST
                and continuation["total_rows"] == 0,
                "zero-page continuation drift")
    else:
        last = _ordered_key(continuation["last_key"], start, end)
        require(last[2] <= snapshot and continuation["total_rows"] > 0,
                "continuation rowid drift")
    return dict(continuation)


def inspect_page(db: sqlite3.Connection, *, day: str, now: datetime,
                 hosts: list[str], source_epoch_sha256: str,
                 host_rules_sha256: str, snapshot_rowid: int,
                 forward_prefix_rowid: int, continuation: dict | None = None,
                 page_rows: int = PAGE_CEILING,
                 budget_seconds: int = 30) -> dict:
    """Scan exactly one keyset page; caller must persist state privately.

    A SOURCE PREFIX scan is not remote-log delivery finality. Results always
    return HOLD and must never be ingested as certified public audience values.
    """
    start, end = completed_day(day, now=now)
    require(type(page_rows) is int and 1 <= page_rows <= PAGE_CEILING,
            "per-page scan bound invalid")
    require(type(budget_seconds) is int and 1 <= budget_seconds <= 45,
            "per-page execution budget invalid")
    require(bool(hosts) and all(isinstance(h, str) and h for h in hosts)
            and len(set(hosts)) == len(hosts) and len(hosts) <= 16,
            "invalid canonical host set")
    require(db.execute("PRAGMA query_only").fetchone()[0] == 1,
            "canonical source connection not query_only")
    indexes = {r[1] for r in db.execute("PRAGMA index_list(traffic_entries)")}
    require("idx_traffic_entries_timestamp_line_offset" in indexes,
            "canonical timestamp ordering index absent")
    state = _state(day, source_epoch_sha256, host_rules_sha256,
                   snapshot_rowid, forward_prefix_rowid,
                   continuation, start, end)
    require(not state["source_prefix_exhausted"],
            "source prefix already scanned; no repeated final page")
    previous = state["last_key"]
    where_next = ""
    parameters: list[object] = [start.isoformat(), end.isoformat(),
                                snapshot_rowid, *hosts]
    if previous is not None:
        where_next = """ AND (
           timestamp > ? OR (timestamp = ? AND line_offset > ?)
           OR (timestamp = ? AND line_offset = ? AND rowid > ?)
        )"""
        stamp, offset, rowid = previous
        parameters += [stamp, stamp, offset, stamp, offset, rowid]
    canonical_filter = _non_browser_chain_firehose_sql()
    host_params = ",".join("?" for _ in hosts)
    started = time.monotonic()
    # The caller must use a read-only snapshot connection. This progress
    # handler bounds the indexed query without scanning the whole 47GiB DB.
    db.set_progress_handler(lambda: int(time.monotonic() - started
                                        >= budget_seconds), 1000)
    try:
        rows = db.execute(f"""
            SELECT rowid,timestamp,line_offset,ingested_at_utc
            FROM traffic_entries INDEXED BY idx_traffic_entries_timestamp_line_offset
            WHERE timestamp >= ? AND timestamp < ? AND rowid <= ?
              AND host IN ({host_params}) AND ({canonical_filter})
              {where_next}
            ORDER BY timestamp,line_offset,rowid LIMIT ?
        """, (*parameters, page_rows + 1)).fetchall()
    finally:
        db.set_progress_handler(None, 0)
    require(time.monotonic() - started < budget_seconds,
            "bounded day page timed out")
    has_more = len(rows) > page_rows
    page = rows[:page_rows]
    last = tuple(previous) if previous is not None else None
    for rowid, timestamp, offset, received in page:
        key = (timestamp, offset, rowid)
        require(last is None or key > last,
                "page ordering or resume key collision")
        require(type(offset) is int and offset >= 0,
                "invalid source file offset")
        last = key
    result = evaluate_rows(
        [(r[0], r[1], r[3]) for r in page],
        day=day, now=now, cursor=forward_prefix_rowid,
        max_rowid=snapshot_rowid, retroactive_frozen_history=False,
    )
    # Chain digest across pages without exporting IP, UA or request paths.
    encoded = json.dumps(page, separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(bytes.fromhex(state["chain_sha256"]) + encoded).hexdigest()
    state.update(
        pages=state["pages"] + 1,
        total_rows=state["total_rows"] + len(page),
        missing_receipts=state["missing_receipts"]
                         + result["rows_with_missing_insertion_receipt"],
        invalid_clocks=state["invalid_clocks"]
                       + result["rows_with_invalid_insertion_clock"],
        last_key=list(last) if last is not None else previous,
        chain_sha256=digest,
        source_prefix_exhausted=not has_more,
    )
    return {
        "schema": "traffic.public-audience.paged-source-evidence.v1",
        "day": day,
        "status": ("HOLD_PAGE_CONTINUATION_REQUIRED" if has_more
                   else "HOLD_SOURCE_PREFIX_SCANNED_DELIVERY_AND_SESSIONS_UNKNOWN"),
        "page_rows_examined": len(page),
        "source_prefix_rows_examined": state["total_rows"],
        "source_prefix_missing_insertion_receipts": state["missing_receipts"],
        "source_prefix_invalid_clocks": state["invalid_clocks"],
        "has_more": has_more,
        "continuation": state,
        "source_read_only": True,
        "day_source_snapshot_fixed": True,
        "canonical_sessions_certified": False,
        "upstream_log_delivery_complete": False,
        "cross_midnight_sessions_certified": False,
        "late_arrival_stability_certified": False,
        "classification_stability_certified": False,
        "publication_authorized": False,
        "certified_days": [],
        "public_audience_writes": False,
    }


def _read_exact_private_file(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
                and stat.S_IMODE(s.st_mode) == 0o600,
                "private continuation not 0600 regular")
        data = os.read(fd, 4097)
        require(len(data) <= 4096, "checkpoint exceeds fixed byte budget")
        return data
    finally:
        os.close(fd)


def save_private_continuation(path: Path, state: dict, *,
                              expected_prior_sha256: str | None = None) -> str:
    """Single-writer 0600 atomic checkpoint with stable sibling flock.

    The digest/preimage protects against stale sequential writers. This is
    NOT an Ed25519 signer, full publisher, or retroactive delivery authority.
    """
    parent = path.parent
    ps = parent.lstat()
    require(stat.S_ISDIR(ps.st_mode) and stat.S_IMODE(ps.st_mode) == 0o700,
            "checkpoint directory not 0700 private")
    require(type(state) is dict and set(state) == STATE_FIELDS,
            "unrecognized state checkpoint")
    payload = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(payload) <= 4096, "checkpoint unexpectedly large")
    lockpath = parent / (path.name + ".lock")
    lockfd = os.open(lockpath, os.O_RDWR | os.O_CREAT |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        lockstat = os.fstat(lockfd)
        require(stat.S_ISREG(lockstat.st_mode) and lockstat.st_nlink == 1
                and stat.S_IMODE(lockstat.st_mode) == 0o600,
                "private checkpoint lock drift")
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if path.exists() or path.is_symlink():
            old_bytes = _read_exact_private_file(path)
            current_hash = hashlib.sha256(old_bytes).hexdigest()
            require(expected_prior_sha256 == current_hash,
                    "checkpoint concurrent-writer/preimage drift")
        else:
            require(expected_prior_sha256 is None, "checkpoint disappeared")
        fd, tmp = tempfile.mkstemp(prefix=".paged-state-", dir=parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(payload)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, path)
            dirfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
    finally:
        os.close(lockfd)
    return hashlib.sha256(payload).hexdigest()


def read_private_continuation(path: Path) -> tuple[dict, str]:
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode)
            and stat.S_IMODE(parent.st_mode) == 0o700,
            "checkpoint directory not private")
    data = _read_exact_private_file(path)
    state = json.loads(data)
    require(type(state) is dict and set(state) == STATE_FIELDS,
            "checkpoint fields have drifted")
    return state, hashlib.sha256(data).hexdigest()
