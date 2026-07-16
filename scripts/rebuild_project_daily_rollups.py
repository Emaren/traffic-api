#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.traffic.config import PERSIST_DB_PATH, PROJECTS


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

    if incremental and latest_rollup_day is not None:
        # Recalculate the newest existing day because it may still be receiving
        # late requests, then fill every day through current raw data.
        start_day = max(
            first_raw_day,
            min(latest_rollup_day, latest_raw_day),
        )
        mode = "incremental"
    else:
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

        upsert_project_day(
            conn,
            project_slug=project_slug,
            bucket_day=bucket_day,
            visitors=visitors,
            events=events,
        )

        # Short transactions: don't hold a SQLite writer lock through a
        # multi-day backfill.
        conn.commit()

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
