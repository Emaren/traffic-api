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
_SCHEMA_LOCK = Lock()
_SCHEMA_READY = False


def persistence_enabled() -> bool:
    return PERSIST_ENABLED


def _connect() -> sqlite3.Connection:
    PERSIST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(PERSIST_DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def _ensure_schema(connection: sqlite3.Connection) -> None:
    global _SCHEMA_READY

    if _SCHEMA_READY:
        return

    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return

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

            CREATE TABLE IF NOT EXISTS traffic_notification_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_notification_mutes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL,
                match_value TEXT NOT NULL,
                label TEXT NOT NULL,
                reason TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_notification_mutes_active
                ON traffic_notification_mutes(active, rule_type);

            CREATE TABLE IF NOT EXISTS traffic_operator_identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL,
                match_value TEXT NOT NULL,
                label TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_operator_identities_match
                ON traffic_operator_identities(rule_type, match_value);

            CREATE INDEX IF NOT EXISTS idx_traffic_operator_identities_active
                ON traffic_operator_identities(active, updated_at DESC);

            CREATE TABLE IF NOT EXISTS traffic_visibility_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL,
                match_value TEXT NOT NULL,
                label TEXT NOT NULL,
                reason TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_visibility_rules_match
                ON traffic_visibility_rules(rule_type, match_value);

            CREATE INDEX IF NOT EXISTS idx_traffic_visibility_rules_active
                ON traffic_visibility_rules(active, created_at DESC);

            CREATE TABLE IF NOT EXISTS traffic_notification_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                traffic_event_id TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                project_slug TEXT NOT NULL,
                project_name TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                route_kind TEXT NOT NULL,
                person_key TEXT NOT NULL,
                visitor_profile_id TEXT NOT NULL,
                visitor_alias TEXT NOT NULL,
                ip TEXT NOT NULL,
                country_code TEXT NOT NULL,
                country TEXT NOT NULL,
                classification_state TEXT NOT NULL,
                verdict_label TEXT NOT NULL,
                returning_visitor INTEGER NOT NULL DEFAULT 0,
                total_project_visits INTEGER NOT NULL DEFAULT 0,
                projects_visited_in_window INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                suppression_reason TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                provider_message_id TEXT NOT NULL DEFAULT '',
                delivery_error TEXT NOT NULL DEFAULT '',
                notification_title TEXT NOT NULL DEFAULT '',
                notification_body TEXT NOT NULL DEFAULT '',
                destination_url TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                delivered_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_notification_events_status_time
                ON traffic_notification_events(status, event_timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_notification_events_person_time
                ON traffic_notification_events(person_key, event_timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_notification_events_session_time
                ON traffic_notification_events(session_id, event_timestamp DESC);

            CREATE TABLE IF NOT EXISTS traffic_push_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint TEXT NOT NULL UNIQUE,
                subscription_json TEXT NOT NULL,
                device_label TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                last_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_success_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_push_subscriptions_active
                ON traffic_push_subscriptions(active, updated_at DESC);
            """
        )
        connection.commit()
        _SCHEMA_READY = True


def _event_id(*, source_path: str, source_inode: int, line_offset: int, raw_line: str) -> str:
    digest = hashlib.sha1(
        f"{source_path}|{source_inode}|{line_offset}|{raw_line}".encode("utf-8")
    ).hexdigest()
    return digest[:24]


def _prune_old_entries(connection: sqlite3.Connection) -> None:
    retention_cutoff = (
        datetime.now(timezone.utc) - timedelta(days=PERSIST_RETENTION_DAYS)
    ).isoformat()
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


def _selected_columns(include_raw_fields: bool) -> list[str]:
    if include_raw_fields:
        return [
            "timestamp",
            "line_offset",
            "ip",
            "request",
            "method",
            "raw_path",
            "normalized_path",
            "status",
            "referrer",
            "referrer_host",
            "ua",
            "host",
            "raw",
        ]

    return [
        "timestamp",
        "line_offset",
        "ip",
        "raw_path",
        "normalized_path",
        "referrer_host",
        "ua",
        "host",
    ]


def _recent_entries_query(
    *,
    selected_columns: list[str],
    window_hours: int | None,
    hosts: list[str] | None,
    max_rows: int | None,
) -> tuple[str, list[str | int]]:
    query = """
        SELECT
            {}
        FROM traffic_entries
    """.format(",\n            ".join(selected_columns))

    params: list[str | int] = []
    where_clauses: list[str] = []

    if window_hours is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        where_clauses.append("timestamp >= ?")
        params.append(cutoff)

    if hosts is not None:
        where_clauses.append(f"host IN ({', '.join('?' for _ in hosts)})")
        params.extend(hosts)

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    if max_rows is not None:
        query += " ORDER BY timestamp DESC, line_offset DESC LIMIT ?"
        params.append(max_rows)
    else:
        query += " ORDER BY timestamp ASC, line_offset ASC"

    return query, params


def load_recent_entries(
    window_hours: int | None,
    log_path: Path = LOG_PATH,
    *,
    hosts: list[str] | None = None,
    include_raw_fields: bool = True,
    max_rows: int | None = None,
) -> list[dict[str, Any]] | None:
    if not persistence_enabled():
        return None

    if max_rows is not None and max_rows <= 0:
        return []

    try:
        sync_log_to_persistence(log_path)
    except Exception:
        return None

    try:
        with _connect() as connection:
            _ensure_schema(connection)

            if hosts is not None and not hosts:
                return []

            selected_columns = _selected_columns(include_raw_fields)
            query, params = _recent_entries_query(
                selected_columns=selected_columns,
                window_hours=window_hours,
                hosts=hosts,
                max_rows=max_rows,
            )

            cursor = connection.execute(query, tuple(params))

            entries: list[dict[str, Any]] = []
            for row in cursor:
                parsed_timestamp = parse_iso_timestamp(row["timestamp"])
                if not parsed_timestamp:
                    continue

                item: dict[str, Any] = {
                    "ip": row["ip"],
                    "timestamp": parsed_timestamp,
                    "timestamp_iso": row["timestamp"],
                    "line_offset": row["line_offset"],
                    "raw_path": row["raw_path"],
                    "normalized_path": row["normalized_path"],
                    "referrer_host": row["referrer_host"],
                    "ua": row["ua"],
                    "host": row["host"],
                }

                if include_raw_fields:
                    item["request"] = row["request"]
                    item["method"] = row["method"]
                    item["status"] = row["status"]
                    item["referrer"] = row["referrer"]
                    item["raw"] = row["raw"]

                entries.append(item)
    except Exception:
        return None

    if max_rows is not None:
        entries.reverse()

    return entries