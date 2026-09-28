#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.traffic.config import PERSIST_DB_PATH, PROJECTS

ROLLUP_STATE_RETENTION_DAYS = 3


def ip_prefix(ip: str) -> str:
    value = str(ip or "")
    parts = value.split(".")

    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return ".".join(parts[:3]) + ".*"

    if ":" in value:
        return ":".join(value.split(":")[:4]) + "::/64"

    return value or "unknown"


def is_core_page(path: str) -> bool:
    return path in {
        "/",
        "/profile",
        "/players",
        "/leaderboard",
        "/wolochain",
        "/staking",
        "/upload",
        "/replays",
        "/download",
        "/contact",
        "/about",
    }


def generous_human_shape(stats: dict) -> bool:
    events = stats["events"]
    distinct = len(stats["paths"])
    core = stats["core"]
    player = stats["player"]
    game = stats["game"]

    if events > 60 or distinct > 18:
        return False

    if events >= 8 and distinct >= 6 and core == 0:
        return False

    if player >= 10 and distinct >= 10:
        return False

    if game >= 10 and distinct >= 10:
        return False

    return core > 0 or events >= 2 or distinct >= 2


def strict_human_shape(
    ip: str,
    stats: dict,
    prefix_ips: dict[str, set[str]],
) -> bool:
    if not generous_human_shape(stats):
        return False

    fanout = len(prefix_ips[ip_prefix(ip)])
    events = stats["events"]
    distinct = len(stats["paths"])
    core = stats["core"]

    if fanout >= 8 and core == 0 and events <= 2:
        return False

    if fanout >= 16 and distinct <= 2 and events <= 4:
        return False

    if fanout >= 50 and core == 0:
        return False

    return True


def project_hosts(project_slug: str) -> list[str]:
    project = next(
        (
            item
            for item in PROJECTS
            if str(item.get("slug") or "") == project_slug
        ),
        None,
    )

    if not project:
        return []

    return [
        str(host)
        for host in project.get("hosts", [])
        if host
    ]


def day_range(start_day: date, end_day: date):
    current = start_day

    while current <= end_day:
        yield current
        current += timedelta(days=1)


def raw_day_bounds(
    conn: sqlite3.Connection,
    hosts: list[str],
) -> tuple[date | None, date | None]:
    placeholders = ",".join("?" for _ in hosts)

    row = conn.execute(
        f"""
        SELECT
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS latest_seen
        FROM traffic_entries
        WHERE host IN ({placeholders})
        """,
        hosts,
    ).fetchone()

    if not row or not row["first_seen"] or not row["latest_seen"]:
        return None, None

    return (
        date.fromisoformat(str(row["first_seen"])[:10]),
        date.fromisoformat(str(row["latest_seen"])[:10]),
    )



def _hosts_key(hosts: list[str]) -> str:
    return json.dumps(sorted(set(hosts)), separators=(",", ":"))


def ensure_incremental_state_schema(conn: sqlite3.Connection) -> None:
    """
    Create compact derived state for true incremental project rollups.

    Raw Traffic history remains authoritative. This state only caches the
    per-project/day/IP/path counts needed by the existing strict-human
    classifier so a 30-minute refresh does not rescan the entire active day.
    """
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS traffic_project_rollup_state (
            project_slug TEXT PRIMARY KEY,
            hosts_key TEXT NOT NULL,
            last_entry_rowid INTEGER NOT NULL,
            initialized_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS traffic_project_daily_path_state (
            project_slug TEXT NOT NULL,
            bucket_day TEXT NOT NULL,
            ip TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            hits INTEGER NOT NULL,
            PRIMARY KEY (
                project_slug,
                bucket_day,
                ip,
                normalized_path
            )
        );

        CREATE INDEX IF NOT EXISTS
            ix_traffic_project_daily_path_state_project_day
        ON traffic_project_daily_path_state (
            project_slug,
            bucket_day
        );
        """
    )
    conn.commit()


def _eligible_path_rows_to_totals(rows) -> tuple[int, int]:    return _eligible_path_rows_to_totals(rows)


def _project_max_rowid(
    conn: sqlite3.Connection,
    hosts: list[str],
) -> int:
    placeholders = ",".join("?" for _ in hosts)
    row = conn.execute(
        f"""
        SELECT COALESCE(MAX(rowid), 0) AS max_rowid
        FROM traffic_entries
        WHERE host IN ({placeholders})
        """,
        hosts,
    ).fetchone()
    return int(row["max_rowid"] or 0) if row else 0


def _load_rollup_state(
    conn: sqlite3.Connection,
    project_slug: str,
):
    return conn.execute(
        """
        SELECT
            hosts_key,
            last_entry_rowid,
            initialized_at,
            updated_at
        FROM traffic_project_rollup_state
        WHERE project_slug = ?
        """,
        (project_slug,),
    ).fetchone()


def _store_rollup_state(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    hosts_key: str,
    last_entry_rowid: int,
    initialized_at: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    existing = _load_rollup_state(conn, project_slug)
    created = (
        initialized_at
        or (str(existing["initialized_at"]) if existing else now)
    )

    conn.execute(
        """
        INSERT INTO traffic_project_rollup_state (
            project_slug,
            hosts_key,
            last_entry_rowid,
            initialized_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(project_slug) DO UPDATE SET
            hosts_key = excluded.hosts_key,
            last_entry_rowid = excluded.last_entry_rowid,
            initialized_at = excluded.initialized_at,
            updated_at = excluded.updated_at
        """,
        (
            project_slug,
            hosts_key,
            int(last_entry_rowid),
            created,
            now,
        ),
    )


def _clear_incremental_project_state(
    conn: sqlite3.Connection,
    project_slug: str,
) -> None:
    conn.execute(
        """
        DELETE FROM traffic_project_daily_path_state
        WHERE project_slug = ?
        """,
        (project_slug,),
    )
    conn.execute(
        """
        DELETE FROM traffic_project_rollup_state
        WHERE project_slug = ?
        """,
        (project_slug,),
    )
    conn.commit()


def _day_bounds(bucket_day: date) -> tuple[str, str]:
    start_at = datetime.combine(
        bucket_day,
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    end_at = start_at + timedelta(days=1)
    return start_at.isoformat(), end_at.isoformat()


def _load_raw_day_path_rows(
    conn: sqlite3.Connection,
    *,
    hosts: list[str],
    bucket_day: date,
    through_rowid: int | None = None,
):
    placeholders = ",".join("?" for _ in hosts)
    start_at, end_at = _day_bounds(bucket_day)
    rowid_clause = (
        "AND rowid <= ?"
        if through_rowid is not None
        else ""
    )
    params: list[object] = [
        *hosts,
        start_at,
        end_at,
    ]
    if through_rowid is not None:
        params.append(int(through_rowid))

    return conn.execute(
        f"""
        SELECT
            ip,
            normalized_path,
            COUNT(*) AS hits
        FROM traffic_entries
        WHERE host IN ({placeholders})
          AND timestamp >= ?
          AND timestamp < ?
          {rowid_clause}
          AND status BETWEEN 200 AND 399
          AND method = 'GET'
          AND ua LIKE '%Mozilla%'
          AND normalized_path NOT LIKE '/api/%'
          AND normalized_path NOT LIKE '/rpc-%'
          AND normalized_path NOT LIKE '/rest-%'
          AND normalized_path NOT LIKE '/_next/%'
          AND normalized_path NOT LIKE '/assets/%'
          AND normalized_path NOT LIKE '/static/%'
          AND normalized_path NOT LIKE '/wp-%'
          AND normalized_path NOT LIKE '/wp/%'
          AND normalized_path NOT LIKE '/.env%'
          AND normalized_path NOT LIKE '/xmlrpc%'
          AND normalized_path NOT LIKE '/server-status%'
          AND normalized_path NOT IN (
            '/robots.txt',
            '/favicon.ico',
            '/manifest.webmanifest',
            '/admin-manifest.webmanifest'
          )
        GROUP BY ip, normalized_path
        """,
        params,
    ).fetchall()


def _replace_day_path_state(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    hosts: list[str],
    bucket_day: date,
    through_rowid: int,
) -> None:
    rows = _load_raw_day_path_rows(
        conn,
        hosts=hosts,
        bucket_day=bucket_day,
        through_rowid=through_rowid,
    )
    day_key = bucket_day.isoformat()

    conn.execute(
        """
        DELETE FROM traffic_project_daily_path_state
        WHERE project_slug = ?
          AND bucket_day = ?
        """,
        (project_slug, day_key),
    )

    conn.executemany(
        """
        INSERT INTO traffic_project_daily_path_state (
            project_slug,
            bucket_day,
            ip,
            normalized_path,
            hits
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                project_slug,
                day_key,
                str(row["ip"] or ""),
                str(row["normalized_path"] or ""),
                int(row["hits"] or 0),
            )
            for row in rows
            if str(row["ip"] or "") and int(row["hits"] or 0) > 0
        ],
    )


def _path_state_exists(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    bucket_day: date,
) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM traffic_project_daily_path_state
        WHERE project_slug = ?
          AND bucket_day = ?
        LIMIT 1
        """,
        (project_slug, bucket_day.isoformat()),
    ).fetchone()
    return row is not None


def _load_new_eligible_path_rows(
    conn: sqlite3.Connection,
    *,
    hosts: list[str],
    after_rowid: int,
    through_rowid: int,
):
    placeholders = ",".join("?" for _ in hosts)
    return conn.execute(
        f"""
        SELECT
            substr(timestamp, 1, 10) AS bucket_day,
            ip,
            normalized_path,
            COUNT(*) AS hits
        FROM traffic_entries
        WHERE host IN ({placeholders})
          AND rowid > ?
          AND rowid <= ?
          AND status BETWEEN 200 AND 399
          AND method = 'GET'
          AND ua LIKE '%Mozilla%'
          AND normalized_path NOT LIKE '/api/%'
          AND normalized_path NOT LIKE '/rpc-%'
          AND normalized_path NOT LIKE '/rest-%'
          AND normalized_path NOT LIKE '/_next/%'
          AND normalized_path NOT LIKE '/assets/%'
          AND normalized_path NOT LIKE '/static/%'
          AND normalized_path NOT LIKE '/wp-%'
          AND normalized_path NOT LIKE '/wp/%'
          AND normalized_path NOT LIKE '/.env%'
          AND normalized_path NOT LIKE '/xmlrpc%'
          AND normalized_path NOT LIKE '/server-status%'
          AND normalized_path NOT IN (
            '/robots.txt',
            '/favicon.ico',
            '/manifest.webmanifest',
            '/admin-manifest.webmanifest'
          )
        GROUP BY
            substr(timestamp, 1, 10),
            ip,
            normalized_path
        ORDER BY bucket_day, ip, normalized_path
        """,
        [
            *hosts,
            int(after_rowid),
            int(through_rowid),
        ],
    ).fetchall()


def _merge_path_state_rows(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    rows,
) -> None:
    conn.executemany(
        """
        INSERT INTO traffic_project_daily_path_state (
            project_slug,
            bucket_day,
            ip,
            normalized_path,
            hits
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(
            project_slug,
            bucket_day,
            ip,
            normalized_path
        ) DO UPDATE SET
            hits = hits + excluded.hits
        """,
        [
            (
                project_slug,
                str(row["bucket_day"]),
                str(row["ip"] or ""),
                str(row["normalized_path"] or ""),
                int(row["hits"] or 0),
            )
            for row in rows
            if (
                str(row["bucket_day"] or "")
                and str(row["ip"] or "")
                and int(row["hits"] or 0) > 0
            )
        ],
    )


def _compute_project_day_from_state(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    bucket_day: date,
) -> tuple[int, int]:
    rows = conn.execute(
        """
        SELECT
            ip,
            normalized_path,
            hits
        FROM traffic_project_daily_path_state
        WHERE project_slug = ?
          AND bucket_day = ?
        """,
        (project_slug, bucket_day.isoformat()),
    ).fetchall()
    return _eligible_path_rows_to_totals(rows)


def _prune_incremental_path_state(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    newest_day: date,
) -> None:
    cutoff = newest_day - timedelta(
        days=max(1, ROLLUP_STATE_RETENTION_DAYS - 1),
    )
    conn.execute(
        """
        DELETE FROM traffic_project_daily_path_state
        WHERE project_slug = ?
          AND bucket_day < ?
        """,
        (project_slug, cutoff.isoformat()),
    )


def _bootstrap_incremental_project(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    hosts: list[str],
    latest_raw_day: date,
    through_rowid: int,
) -> dict:
    _clear_incremental_project_state(
        conn,
        project_slug,
    )

    _replace_day_path_state(
        conn,
        project_slug=project_slug,
        hosts=hosts,
        bucket_day=latest_raw_day,
        through_rowid=through_rowid,
    )
    visitors, events = _compute_project_day_from_state(
        conn,
        project_slug=project_slug,
        bucket_day=latest_raw_day,
    )
    upsert_project_day(
        conn,
        project_slug=project_slug,
        bucket_day=latest_raw_day,
        visitors=visitors,
        events=events,
    )
    _store_rollup_state(
        conn,
        project_slug=project_slug,
        hosts_key=_hosts_key(hosts),
        last_entry_rowid=through_rowid,
    )
    _prune_incremental_path_state(
        conn,
        project_slug=project_slug,
        newest_day=latest_raw_day,
    )
    conn.commit()

    return {
        "project_slug": project_slug,
        "mode": "incremental_bootstrap",
        "start_day": latest_raw_day.isoformat(),
        "end_day": latest_raw_day.isoformat(),
        "days": 1,
        "visitors": visitors,
        "events": events,
        "watermark_rowid": through_rowid,
    }


def refresh_project_incremental(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    hosts: list[str],
    latest_raw_day: date,
) -> dict:
    ensure_incremental_state_schema(conn)

    hosts_key = _hosts_key(hosts)
    current_max_rowid = _project_max_rowid(
        conn,
        hosts,
    )
    state = _load_rollup_state(
        conn,
        project_slug,
    )

    if (
        state is None
        or str(state["hosts_key"]) != hosts_key
        or int(state["last_entry_rowid"] or 0) > current_max_rowid
    ):
        return _bootstrap_incremental_project(
            conn,
            project_slug=project_slug,
            hosts=hosts,
            latest_raw_day=latest_raw_day,
            through_rowid=current_max_rowid,
        )

    previous_rowid = int(
        state["last_entry_rowid"] or 0,
    )

    if current_max_rowid <= previous_rowid:
        return {
            "project_slug": project_slug,
            "mode": "incremental_noop",
            "start_day": latest_raw_day.isoformat(),
            "end_day": latest_raw_day.isoformat(),
            "days": 0,
            "visitors": 0,
            "events": 0,
            "watermark_rowid": current_max_rowid,
        }

    new_rows = _load_new_eligible_path_rows(
        conn,
        hosts=hosts,
        after_rowid=previous_rowid,
        through_rowid=current_max_rowid,
    )

    rows_by_day: dict[date, list] = defaultdict(list)
    for row in new_rows:
        raw_day = str(row["bucket_day"] or "")
        try:
            bucket_day = date.fromisoformat(raw_day)
        except ValueError:
            continue
        rows_by_day[bucket_day].append(row)

    processed = 0
    total_visitors = 0
    total_events = 0

    for bucket_day in sorted(rows_by_day):
        if _path_state_exists(
            conn,
            project_slug=project_slug,
            bucket_day=bucket_day,
        ):
            _merge_path_state_rows(
                conn,
                project_slug=project_slug,
                rows=rows_by_day[bucket_day],
            )
        else:
            # A late event may target a historical day whose compact state was
            # pruned. Rebuild only that day from raw truth, never the estate.
            _replace_day_path_state(
                conn,
                project_slug=project_slug,
                hosts=hosts,
                bucket_day=bucket_day,
                through_rowid=current_max_rowid,
            )

        visitors, events = _compute_project_day_from_state(
            conn,
            project_slug=project_slug,
            bucket_day=bucket_day,
        )
        upsert_project_day(
            conn,
            project_slug=project_slug,
            bucket_day=bucket_day,
            visitors=visitors,
            events=events,
        )

        processed += 1
        total_visitors += visitors
        total_events += events

        print(
            f"{project_slug}: "
            f"{bucket_day.isoformat()} "
            f"visitors={visitors} "
            f"events={events}",
            flush=True,
        )

    _store_rollup_state(
        conn,
        project_slug=project_slug,
        hosts_key=hosts_key,
        last_entry_rowid=current_max_rowid,
    )
    _prune_incremental_path_state(
        conn,
        project_slug=project_slug,
        newest_day=latest_raw_day,
    )
    conn.commit()

    return {
        "project_slug": project_slug,
        "mode": "incremental",
        "start_day": (
            min(rows_by_day).isoformat()
            if rows_by_day
            else latest_raw_day.isoformat()
        ),
        "end_day": (
            max(rows_by_day).isoformat()
            if rows_by_day
            else latest_raw_day.isoformat()
        ),
        "days": processed,
        "visitors": total_visitors,
        "events": total_events,
        "watermark_rowid": current_max_rowid,
        "eligible_path_groups": len(new_rows),
    }


def compute_project_day(
    conn: sqlite3.Connection,
    *,
    hosts: list[str],
    bucket_day: date,
) -> tuple[int, int]:
    placeholders = ",".join("?" for _ in hosts)

    start_at = datetime.combine(
        bucket_day,
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    end_at = start_at + timedelta(days=1)

    # Aggregate by IP/path inside SQLite first. This preserves the existing
    # strict-human shape math while avoiding one Python object per raw request.
    rows = conn.execute(
        f"""
        SELECT
            ip,
            normalized_path,
            COUNT(*) AS hits
        FROM traffic_entries
        WHERE host IN ({placeholders})
          AND timestamp >= ?
          AND timestamp < ?
          AND status BETWEEN 200 AND 399
          AND method = 'GET'
          AND ua LIKE '%Mozilla%'
          AND normalized_path NOT LIKE '/api/%'
          AND normalized_path NOT LIKE '/rpc-%'
          AND normalized_path NOT LIKE '/rest-%'
          AND normalized_path NOT LIKE '/_next/%'
          AND normalized_path NOT LIKE '/assets/%'
          AND normalized_path NOT LIKE '/static/%'
          AND normalized_path NOT LIKE '/wp-%'
          AND normalized_path NOT LIKE '/wp/%'
          AND normalized_path NOT LIKE '/.env%'
          AND normalized_path NOT LIKE '/xmlrpc%'
          AND normalized_path NOT LIKE '/server-status%'
          AND normalized_path NOT IN (
            '/robots.txt',
            '/favicon.ico',
            '/manifest.webmanifest',
            '/admin-manifest.webmanifest'
          )
        GROUP BY ip, normalized_path
        """,
        [
            *hosts,
            start_at.isoformat(),
            end_at.isoformat(),
        ],
    ).fetchall()

    stats = defaultdict(
        lambda: {
            "events": 0,
            "paths": Counter(),
            "core": 0,
            "player": 0,
            "game": 0,
        }
    )

    prefix_ips: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        ip = str(row["ip"] or "")
        path = str(row["normalized_path"] or "")
        hits = int(row["hits"] or 0)

        if not ip or hits <= 0:
            continue

        item = stats[ip]
        item["events"] += hits
        item["paths"][path] += hits

        if is_core_page(path):
            item["core"] += hits

        if path.startswith("/players/"):
            item["player"] += hits

        if path.startswith("/game-stats/"):
            item["game"] += hits

        prefix_ips[ip_prefix(ip)].add(ip)

    visitors = 0
    events = 0

    for ip, item in stats.items():
        if strict_human_shape(ip, item, prefix_ips):
            visitors += 1
            events += item["events"]

    return visitors, events


def upsert_project_day(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    bucket_day: date,
    visitors: int,
    events: int,
) -> None:
    conn.execute(
        """
        INSERT INTO traffic_project_daily_rollups (
            project_slug,
            bucket_day,
            visitors,
            events,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(project_slug, bucket_day) DO UPDATE SET
            visitors = excluded.visitors,
            events = excluded.events,
            updated_at = excluded.updated_at
        """,
        (
            project_slug,
            bucket_day.isoformat(),
            visitors,
            events,
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def upsert_project_day_with_retry(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    bucket_day: date,
    visitors: int,
    events: int,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
) -> None:
    if attempts <= 0:
        raise ValueError("attempts must be positive")
    for attempt in range(1, attempts + 1):
        try:
            upsert_project_day(
                conn,
                project_slug=project_slug,
                bucket_day=bucket_day,
                visitors=visitors,
                events=events,
            )
            conn.commit()
            return
        except sqlite3.OperationalError as exc:
            conn.rollback()
            if "locked" not in str(exc).lower() or attempt >= attempts:
                raise
            time.sleep(retry_delay_seconds * attempt)


def refresh_project(
    conn: sqlite3.Connection,
    *,
    project_slug: str,
    incremental: bool,
) -> dict:
    hosts = project_hosts(project_slug)

    if not hosts:
        return {
            "project_slug": project_slug,
            "mode": "skipped",
            "reason": "no_hosts",
            "days": 0,
        }

    first_raw_day, latest_raw_day = raw_day_bounds(
        conn,
        hosts,
    )

    if first_raw_day is None or latest_raw_day is None:
        return {
            "project_slug": project_slug,
            "mode": "noop",
            "reason": "no_raw_rows",
            "days": 0,
        }

    latest_rollup_row = conn.execute(
        """
        SELECT MAX(bucket_day) AS latest_day
        FROM traffic_project_daily_rollups
        WHERE project_slug = ?
        """,
        (project_slug,),
    ).fetchone()

    latest_rollup_day = (
        date.fromisoformat(str(latest_rollup_row["latest_day"]))
        if latest_rollup_row
        and latest_rollup_row["latest_day"]
        else None
    )

    if incremental:
        return refresh_project_incremental(
            conn,
            project_slug=project_slug,
            hosts=hosts,
            latest_raw_day=latest_raw_day,
        )
    else:
        _clear_incremental_project_state(
            conn,
            project_slug,
        )
        conn.execute(
            """
            DELETE FROM traffic_project_daily_rollups
            WHERE project_slug = ?
            """,
            (project_slug,),
        )
        conn.commit()

        start_day = first_raw_day
        mode = "rebuild"

    processed = 0
    total_visitors = 0
    total_events = 0

    for bucket_day in day_range(
        start_day,
        latest_raw_day,
    ):
        visitors, events = compute_project_day(
            conn,
            hosts=hosts,
            bucket_day=bucket_day,
        )

        upsert_project_day_with_retry(
            conn,
            project_slug=project_slug,
            bucket_day=bucket_day,
            visitors=visitors,
            events=events,
        )

        processed += 1
        total_visitors += visitors
        total_events += events

        print(
            f"{project_slug}: "
            f"{bucket_day.isoformat()} "
            f"visitors={visitors} "
            f"events={events}",
            flush=True,
        )

    return {
        "project_slug": project_slug,
        "mode": mode,
        "start_day": start_day.isoformat(),
        "end_day": latest_raw_day.isoformat(),
        "days": processed,
        "visitors": total_visitors,
        "events": total_events,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build or incrementally refresh Traffic's strict "
            "project daily human-signal rollups."
        )
    )

    parser.add_argument(
        "--incremental",
        action="store_true",
        help=(
            "Recompute the newest existing rollup day and "
            "fill forward through the newest raw Traffic day."
        ),
    )

    parser.add_argument(
        "--project",
        action="append",
        dest="projects",
        help=(
            "Project slug to process. Repeat for multiple projects. "
            "Default: every configured project."
        ),
    )

    args = parser.parse_args()

    configured_slugs = [
        str(project.get("slug") or "")
        for project in PROJECTS
        if project.get("slug")
    ]

    selected = (
        args.projects
        if args.projects
        else configured_slugs
    )

    unknown = [
        slug
        for slug in selected
        if slug not in configured_slugs
    ]

    if unknown:
        raise SystemExit(
            "Unknown project slug(s): "
            + ", ".join(unknown)
        )

    conn = sqlite3.connect(
        PERSIST_DB_PATH,
        timeout=30,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    try:
        results = []

        for project_slug in selected:
            result = refresh_project(
                conn,
                project_slug=project_slug,
                incremental=args.incremental,
            )
            results.append(result)

        print()
        print("== rollup summary ==")

        for result in results:
            print(
                json.dumps(
                    result,
                    sort_keys=True,
                )
            )

    finally:
        conn.close()


if __name__ == "__main__":
    main()
