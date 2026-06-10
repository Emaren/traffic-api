#!/usr/bin/env python3
from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from app.services.traffic.config import PROJECTS

DB_PATH = Path("/mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3")


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


def strict_human_shape(day: str, ip: str, stats: dict, prefix_ips: dict) -> bool:
    if not generous_human_shape(stats):
        return False

    fanout = len(prefix_ips[(day, ip_prefix(ip))])
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


def rebuild() -> None:
    now = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    conn.execute("DELETE FROM traffic_project_daily_rollups")

    for project in PROJECTS:
        slug = project["slug"]
        hosts = [str(host) for host in project.get("hosts", []) if host]
        if not hosts:
            print(f"{slug}: skipped, no hosts")
            continue

        placeholders = ",".join("?" for _ in hosts)
        rows = conn.execute(
            f"""
            SELECT
                substr(timestamp, 1, 10) AS day,
                ip,
                normalized_path
            FROM traffic_entries
            WHERE host IN ({placeholders})
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
            """,
            hosts,
        ).fetchall()

        stats = defaultdict(lambda: {
            "events": 0,
            "paths": Counter(),
            "core": 0,
            "player": 0,
            "game": 0,
        })
        prefix_ips = defaultdict(set)

        for row in rows:
            day = row["day"]
            ip = row["ip"]
            path = row["normalized_path"] or ""

            key = (day, ip)
            stats[key]["events"] += 1
            stats[key]["paths"][path] += 1
            stats[key]["core"] += 1 if is_core_page(path) else 0
            stats[key]["player"] += 1 if path.startswith("/players/") else 0
            stats[key]["game"] += 1 if path.startswith("/game-stats/") else 0
            prefix_ips[(day, ip_prefix(ip))].add(ip)

        daily_visitors = Counter()
        daily_events = Counter()

        for (day, ip), item in stats.items():
            if strict_human_shape(day, ip, item, prefix_ips):
                daily_visitors[day] += 1
                daily_events[day] += item["events"]

        for day in sorted(daily_visitors):
            conn.execute(
                """
                INSERT OR REPLACE INTO traffic_project_daily_rollups (
                    project_slug,
                    bucket_day,
                    visitors,
                    events,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (slug, day, daily_visitors[day], daily_events[day], now),
            )

        max_day = max(daily_visitors.items(), key=lambda item: item[1]) if daily_visitors else None
        print(
            f"{slug}: days={len(daily_visitors)} "
            f"visitors={sum(daily_visitors.values())} "
            f"max={max_day} "
            f"events={sum(daily_events.values())}"
        )

    conn.commit()

    print()
    print("== final rollup totals ==")
    for row in conn.execute(
        """
        SELECT
            project_slug,
            COUNT(*) AS days,
            SUM(visitors) AS visitors,
            MAX(visitors) AS max_day_visitors,
            SUM(events) AS events
        FROM traffic_project_daily_rollups
        GROUP BY project_slug
        ORDER BY visitors DESC
        """
    ):
        print(dict(row))

    conn.close()


if __name__ == "__main__":
    rebuild()
