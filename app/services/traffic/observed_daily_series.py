"""Bounded, observational daily AoE2WAR activity. NEVER a human-audience certificate.

This source is entirely separate from traffic_public_daily_audience_rollups.
It reads previously computed project rollups only; no scan of raw 48GB logs,
no IP, UA, visitor identity, sessions or custody data leave the service.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import sqlite3

PROJECT = "aoe2hdbets"
MAX_DAYS = 45


def observed_daily_series(database: Path, *, today_utc: date | None = None) -> dict:
    today_utc = today_utc or datetime.now(timezone.utc).date()
    if type(today_utc) is not date:
        raise ValueError("UTC day must be a date")

    uri = f"file:{database.resolve()}?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=3.0)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=3000")
        last_certified = db.execute(
            "SELECT MAX(bucket_day) FROM traffic_public_daily_audience_rollups "
            "WHERE project_slug=?", (PROJECT,)
        ).fetchone()[0]
        if last_certified is not None:
            last_certified_day = date.fromisoformat(str(last_certified))
            if last_certified_day >= today_utc:
                raise ValueError("certified archive cannot include today or a future date")
        else:
            last_certified_day = None

        start_day = today_utc - timedelta(days=MAX_DAYS-1)
        if last_certified_day and last_certified_day >= start_day:
            start_day = last_certified_day + timedelta(days=1)

        rows = db.execute(
            "SELECT bucket_day, visitors, events, updated_at "
            "FROM traffic_project_daily_rollups "
            "WHERE project_slug=? AND bucket_day>=? AND bucket_day<=? "
            "ORDER BY bucket_day ASC LIMIT ?",
            (PROJECT, start_day.isoformat(), today_utc.isoformat(), MAX_DAYS)
        ).fetchall()
    finally:
        db.close()

    points = []
    previous = None
    for item in rows:
        day = date.fromisoformat(str(item["bucket_day"]))
        visitors, events = item["visitors"], item["events"]
        if (previous is not None and day <= previous
            or day < start_day or day > today_utc
            or type(visitors) is not int or type(events) is not int
            or visitors < 0 or events < visitors):
            raise ValueError("observed project rollup invariant failed")
        updated_at = str(item["updated_at"])
        if not updated_at or len(updated_at) > 64:
            raise ValueError("observed rollup update time invalid")
        points.append({
            "date": day.isoformat(),
            "observed_qualifying_ips": visitors,
            "observed_get_events": events,
            "updated_at": updated_at,
            "utc_day_complete": day < today_utc,
            "certified_human": False,
        })
        previous = day

    return {
        "ok": True,
        "project_slug": PROJECT,
        "kind": "provisional_observed_project_daily",
        "last_certified_day": last_certified_day.isoformat() if last_certified_day else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "points": points,
        "semantics": {
            "observed_qualifying_ips": "Unique IPs passing project-page filters; NOT unique people or human sessions.",
            "observed_get_events": "Eligible filtered page GETs; NOT canonical page sessions.",
            "utc_day_complete": "Calendar day finished in UTC, NOT ingestion/finality certified.",
            "certification": "Every point is PROVISIONAL/UNVERIFIED; cannot extend or replace the certified Traffic archive."
        },
    }
