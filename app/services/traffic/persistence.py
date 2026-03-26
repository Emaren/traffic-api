from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from app.services.traffic.config import (
    LOG_PATH,
    PERSIST_DB_PATH,
    PERSIST_ENABLED,
    PERSIST_RETENTION_DAYS,
)
from app.services.traffic.parse import parse_iso_timestamp, parse_log_line

_SYNC_LOCK = Lock()


def persistence_enabled() -> bool:
    return PERSIST_ENABLED


def _connect() -> sqlite3.Connection:
    PERSIST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(PERSIST_DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS traffic_entries (
            event_id TEXT PRIMARY KEY,
            source_path TEXT NOT NULL,
            source_inode INTEGER NOT NULL,
            line_offset INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            request TEXT NOT NULL,
            method TEXT NOT NULL,
            raw_path TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            status INTEGER NOT NULL,
            referrer TEXT NOT NULL,
            referrer_host TEXT NOT NULL,
            ua TEXT NOT NULL,
            host TEXT NOT NULL,
            raw TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_traffic_entries_timestamp
            ON traffic_entries(timestamp);

        CREATE INDEX IF NOT EXISTS idx_traffic_entries_host_timestamp
            ON traffic_entries(host, timestamp);

        CREATE TABLE IF NOT EXISTS traffic_ingest_state (
            source_path TEXT PRIMARY KEY,
            source_inode INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )


def _event_id(*, source_path: str, source_inode: int, line_offset: int, raw_line: str) -> str:
    digest = hashlib.sha1(
        f"{source_path}|{source_inode}|{line_offset}|{raw_line}".encode("utf-8")
    ).hexdigest()
    return digest[:24]


def _prune_old_entries(connection: sqlite3.Connection) -> None:
    retention_cutoff = (datetime.now(timezone.utc) - timedelta(days=PERSIST_RETENTION_DAYS)).isoformat()
    connection.execute(
        "DELETE FROM traffic_entries WHERE timestamp < ?",
        (retention_cutoff,),
    )


def sync_log_to_persistence(log_path: Path = LOG_PATH) -> dict[str, int | str]:
    if not persistence_enabled():
        return {"inserted": 0, "offset": 0, "mode": "disabled"}
    if not log_path.exists():
        return {"inserted": 0, "offset": 0, "mode": "missing"}

    with _SYNC_LOCK:
        stat = log_path.stat()
        inserted = 0

        with _connect() as connection:
            _ensure_schema(connection)

            state = connection.execute(
                """
                SELECT source_inode, offset
                FROM traffic_ingest_state
                WHERE source_path = ?
                """,
                (str(log_path),),
            ).fetchone()

            offset = int(state["offset"]) if state else 0
            previous_inode = int(state["source_inode"]) if state else stat.st_ino
            if previous_inode != stat.st_ino or stat.st_size < offset:
                offset = 0

            batch: list[tuple[Any, ...]] = []
            with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)

                while True:
                    line_offset = handle.tell()
                    line = handle.readline()
                    if not line:
                        break

                    parsed = parse_log_line(line)
                    if not parsed:
                        continue

                    batch.append(
                        (
                            _event_id(
                                source_path=str(log_path),
                                source_inode=stat.st_ino,
                                line_offset=line_offset,
                                raw_line=line.rstrip("\n"),
                            ),
                            str(log_path),
                            stat.st_ino,
                            line_offset,
                            parsed["timestamp_iso"],
                            parsed["ip"],
                            parsed["request"],
                            parsed["method"],
                            parsed["raw_path"],
                            parsed["normalized_path"],
                            parsed["status"],
                            parsed["referrer"],
                            parsed["referrer_host"],
                            parsed["ua"],
                            parsed["host"],
                            parsed["raw"],
                        )
                    )

                final_offset = handle.tell()

            if batch:
                connection.executemany(
                    """
                    INSERT OR IGNORE INTO traffic_entries (
                        event_id,
                        source_path,
                        source_inode,
                        line_offset,
                        timestamp,
                        ip,
                        request,
                        method,
                        raw_path,
                        normalized_path,
                        status,
                        referrer,
                        referrer_host,
                        ua,
                        host,
                        raw
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    batch,
                )
                inserted = len(batch)

            connection.execute(
                """
                INSERT INTO traffic_ingest_state (source_path, source_inode, offset, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_path) DO UPDATE SET
                    source_inode = excluded.source_inode,
                    offset = excluded.offset,
                    updated_at = excluded.updated_at
                """,
                (
                    str(log_path),
                    stat.st_ino,
                    final_offset,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            _prune_old_entries(connection)
            connection.commit()

    return {"inserted": inserted, "offset": final_offset, "mode": "persisted"}


def load_recent_entries(
    window_hours: int | None,
    log_path: Path = LOG_PATH,
) -> list[dict[str, Any]] | None:
    if not persistence_enabled():
        return None

    try:
        sync_log_to_persistence(log_path)
    except Exception:
        return None

    try:
        with _connect() as connection:
            _ensure_schema(connection)
            query = """
                SELECT
                    timestamp,
                    ip,
                    request,
                    method,
                    raw_path,
                    normalized_path,
                    status,
                    referrer,
                    referrer_host,
                    ua,
                    host,
                    raw
                FROM traffic_entries
            """
            params: tuple[str, ...] = ()
            if window_hours is not None:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
                query += " WHERE timestamp >= ?"
                params = (cutoff,)
            query += " ORDER BY timestamp ASC"
            rows = connection.execute(query, params).fetchall()
    except Exception:
        return None

    entries: list[dict[str, Any]] = []
    for row in rows:
        parsed_timestamp = parse_iso_timestamp(row["timestamp"])
        if not parsed_timestamp:
            continue

        entries.append(
            {
                "ip": row["ip"],
                "timestamp": parsed_timestamp,
                "timestamp_iso": row["timestamp"],
                "request": row["request"],
                "method": row["method"],
                "raw_path": row["raw_path"],
                "normalized_path": row["normalized_path"],
                "status": row["status"],
                "referrer": row["referrer"],
                "referrer_host": row["referrer_host"],
                "ua": row["ua"],
                "host": row["host"],
                "raw": row["raw"],
            }
        )

    return entries
