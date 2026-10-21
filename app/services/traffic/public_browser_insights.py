"""Read-only, bounded observations of actual browser beacon sessions.

These are NOT the historical canonical audience counts or verified humans.
No raw IP, persistent browser identifier, UA or private route is returned.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import time

from app.services.traffic.config import PERSIST_DB_PATH
from app.services.traffic.config import BROWSER_EVENT_STORY_REJECT_UA_TERMS

DAYS = 7
MAX_ROWS = 80_000
MAX_QUERY_SECONDS = 4.0
MAX_VISIBLE_MS_PER_PAGE = 12 * 60 * 60 * 1000
MIN_COUNTRY_VISITORS = 5
EXCLUDED_PATH_PREFIXES = (
    "/api", "/admin", "/_next", "/static", "/assets",
    "/.well-known", "/auth", "/login", "/signup", "/account",
    "/settings", "/billing", "/profile", "/internal",
)
ASSET_EXTENSIONS = (
    ".js", ".css", ".json", ".svg", ".png", ".jpg", ".jpeg",
    ".gif", ".webp", ".ico", ".woff", ".woff2", ".map", ".txt",
    ".xml", ".pdf", ".mp4", ".mp3",
)


class ObservedInsightsUnavailable(RuntimeError):
    pass


def public_path(value: str) -> str | None:
    path = (value or "").split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/") or "//" in path or len(path) > 240:
        return None
    lowered = path.lower().rstrip("/") or "/"
    if any(lowered == prefix or lowered.startswith(prefix + "/")
           for prefix in EXCLUDED_PATH_PREFIXES):
        return None
    if lowered.endswith(ASSET_EXTENSIONS):
        return None
    return path.rstrip("/") or "/"


def build_observed_browser_insights(
    project_slug: str,
    *,
    db_path: Path = PERSIST_DB_PATH,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("UTC-aware clock required")
    current = current.astimezone(timezone.utc)
    end = current.replace(hour=0, minute=0, second=0, microsecond=0)
    begin = end - timedelta(days=DAYS)
    if not db_path.is_file() or db_path.is_symlink():
        raise ObservedInsightsUnavailable("browser evidence database unavailable")

    opened = time.monotonic()
    uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=1)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA busy_timeout=1000")
            db.set_progress_handler(
                lambda: int(time.monotonic() - opened > MAX_QUERY_SECONDS), 1000
            )
            # The index orders a bounded completed-UTC-day window. Never truncate
            # an oversized cohort and present its first N events as all visitors.
            rows = db.execute(
                """SELECT received_at, event_type, path, visitor_id, session_id,
                          page_view_id, visible_ms, country, user_agent
                   FROM traffic_browser_events
                   INDEXED BY idx_traffic_browser_events_project_received
                   WHERE project_slug=? AND received_at>=? AND received_at<?
                   ORDER BY received_at DESC LIMIT ?""",
                (project_slug, begin.isoformat(), end.isoformat(), MAX_ROWS + 1),
            ).fetchall()
    except sqlite3.Error as exc:
        raise ObservedInsightsUnavailable(
            "bounded read-only browser evidence scan failed"
        ) from exc
    if len(rows) > MAX_ROWS:
        raise ObservedInsightsUnavailable(
            "browser cohort exceeds bounded scan; do not publish partial ranking"
        )

    page_views: dict[tuple[str, str, str], dict] = {}
    duration_by_view: dict[tuple[str, str, str], int] = defaultdict(int)
    for row in rows:
        ua = str(row["user_agent"] or "").lower()
        if any(token in ua for token in BROWSER_EVENT_STORY_REJECT_UA_TERMS):
            continue
        visitor, session, view = (
            str(row[k] or "") for k in ("visitor_id", "session_id", "page_view_id")
        )
        if not visitor or not session or not view:
            continue
        key = (visitor, session, view)
        if row["event_type"] == "page_view":
            path = public_path(str(row["path"] or ""))
            if path is None:
                continue
            page_views[key] = {
                "path": path, "country": str(row["country"] or "").strip()[:80],
            }
        visible = row["visible_ms"]
        if type(visible) is int and 0 < visible <= MAX_VISIBLE_MS_PER_PAGE:
            duration_by_view[key] = max(duration_by_view[key], visible)

    # Count distinct page-view IDs, not all heartbeat/click requests.
    page_counter = Counter(item["path"] for item in page_views.values())
    # Multiple pages belonging to one browser session contribute their distinct
    # maximum measured visible times. Zero-second sessions do not enter the mean.
    by_session: dict[tuple[str, str], int] = defaultdict(int)
    distinct_country_visitors: dict[str, set[str]] = defaultdict(set)
    geolocated = 0
    for (visitor, session, view), item in page_views.items():
        by_session[(visitor, session)] += duration_by_view[(visitor, session, view)]
        country = item["country"]
        if country and country.lower() not in {"unknown", "n/a", "-"}:
            geolocated += 1
            distinct_country_visitors[country].add(visitor)
    positive_ms = [ms for ms in by_session.values() if ms > 0]
    country_counts = [
        (country, len(identifiers))
        for country, identifiers in distinct_country_visitors.items()
        if len(identifiers) >= MIN_COUNTRY_VISITORS
    ]
    country_counts.sort(key=lambda p: (-p[1], p[0]))
    pages = sorted(page_counter.items(), key=lambda p: (-p[1], p[0]))[:5]
    average = (
        round(sum(positive_ms) / len(positive_ms) / 1000)
        if positive_ms else None
    )
    return {
        "ok": True,
        "status": "OBSERVED_ONLY",
        "source": "browser_beacon",
        "scope": "last_7_completed_utc_days",
        "from_day": begin.date().isoformat(),
        "through_day": (end - timedelta(days=1)).date().isoformat(),
        "coverage": {
            "browser_page_views": len(page_views),
            "geolocated_page_views": geolocated,
            "observed_browser_sessions": len(by_session),
            "positive_duration_sessions": len(positive_ms),
            "excluded_zero_duration_sessions": len(by_session) - len(positive_ms),
            "rows_scanned": len(rows),
        },
        "top_countries": [
            {"name": country, "unique_browser_ids": count}
            for country, count in country_counts[:5]
        ],
        "top_pages": [
            {"path": path, "page_views": count} for path, count in pages
        ],
        "average_visible_seconds": average,
        "semantics": (
            "Browser beacon observations, not independently classified humans "
            "or canonical historical audience sessions. Per-page cumulative "
            "visible_ms maximum; per-session sum; exclude zero duration. "
            "Countries use on-ingest GeoIP and browser visitor identifiers, "
            "which are not unique humans or independently trusted IPs."
        ),
    }
