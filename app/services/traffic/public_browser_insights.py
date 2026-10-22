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
# Bound each cold read even on a busy production volume; the normal path
# reads indexed page views plus SQL-compacted visible maxima, not 80k full rows.
MAX_QUERY_SECONDS = 12.0
MAX_VISIBLE_MS_PER_PAGE = 12 * 60 * 60 * 1000
MIN_COUNTRY_VISITORS = 5
EXCLUDED_PATH_PREFIXES = (
    "/api", "/admin", "/_next", "/static", "/assets",
    "/.well-known", "/auth", "/login", "/signup", "/account",
    "/settings", "/billing", "/profile", "/internal",
)
# Reviewed public static routes from the AoE2WAR Kingdom Index snapshot.
# Dynamic IDs, private/account paths, query-bearing URLs and unreviewed routes
# are NEVER displayed in an unauthenticated page ranking. Update deliberately
# when publicly approved static routes change, not via runtime discovery.
APPROVED_PUBLIC_PATHS = frozenset({
    "/",
    "/about",
    "/academy",
    "/ai",
    "/aoe2war-os",
    "/battle-archive",
    "/belts",
    "/bets",
    "/betting-mechanics",
    "/bounties",
    "/challenge",
    "/champions",
    "/champions/e2",
    "/champions/e3",
    "/champions/e4",
    "/champions/e5",
    "/champions/legacy",
    "/chaosium",
    "/clans",
    "/download",
    "/forum",
    "/game-stats",
    "/general-inspections",
    "/hd-replay-engine",
    "/kingdom",
    "/kingdom-agents",
    "/kingdom-bettors",
    "/kingdom-brain",
    "/kingdom-forge",
    "/kingdom-index",
    "/kingdom-intelligence",
    "/kingdom-progress",
    "/kingdom-recovery",
    "/kingdom-sensors",
    "/kingdom-systems",
    "/kingdom-tests",
    "/kingdom-treasury",
    "/leaderboard",
    "/leaderboard/og",
    "/leagues",
    "/library",
    "/live-games",
    "/market",
    "/national-champions",
    "/nations",
    "/olympia",
    "/oracle",
    "/players",
    "/radio",
    "/realm",
    "/renaissance",
    "/renaissance/arbiter",
    "/renaissance/architect",
    "/renaissance/atlas",
    "/renaissance/chronicles",
    "/renaissance/circuit",
    "/renaissance/doctor",
    "/renaissance/forge",
    "/renaissance/marshal",
    "/renaissance/sentinel",
    "/renaissance/train",
    "/renaissance/vault",
    "/replay-laboratory",
    "/replay-parser",
    "/requests",
    "/rivalries",
    "/roadmap",
    "/round-chamber",
    "/speed",
    "/staking",
    "/statistics",
    "/submit",
    "/television-wolo",
    "/tournaments",
    "/traffic",
    "/war-chest",
    "/war-engine",
    "/wargraph",
    "/watch",
    "/wolo",
    "/wolo-1",
    "/wolochain",
    "/wolomania",
    "/workshop",
    "/zodiac",
})

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
    return lowered if lowered in APPROVED_PUBLIC_PATHS else None


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
    # The production configuration uses a managed SQLite path alias to the
    # mounted volume. A symbolic link at that alias is not evidence corruption:
    # resolve it once to an existing regular file, then open that immutable
    # resolved pathname with SQLite mode=ro + PRAGMA query_only.
    # Broken links, directory targets and circular aliases still fail closed.
    try:
        resolved = db_path.resolve(strict=True)
        if not resolved.is_file():
            raise ObservedInsightsUnavailable(
                "browser evidence database unavailable"
            )
    except (OSError, RuntimeError) as exc:
        raise ObservedInsightsUnavailable(
            "browser evidence database unavailable"
        ) from exc

    opened = time.monotonic()
    uri = f"file:{resolved.as_posix()}?mode=ro"
    expired = False

    def progress() -> int:
        nonlocal expired
        if time.monotonic() - opened > MAX_QUERY_SECONDS:
            expired = True
            return 1
        return 0

    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=1)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA busy_timeout=1000")
            db.set_progress_handler(progress, 1000)

            # First prove that the *entire* seven-day window fits the cap.
            # COUNT(*) can use the existing (project_slug,received_at) index.
            # Never LIMIT a partial cohort and imply it is a full ranking.
            rows_scanned = int(db.execute(
                """SELECT COUNT(*) FROM traffic_browser_events
                   INDEXED BY idx_traffic_browser_events_project_received
                   WHERE project_slug=? AND received_at>=? AND received_at<?""",
                (project_slug, begin.isoformat(), end.isoformat()),
            ).fetchone()[0])
            if rows_scanned > MAX_ROWS:
                raise ObservedInsightsUnavailable(
                    "browser cohort exceeds bounded scan; do not publish partial ranking"
                )

            # The overwhelming majority of browser rows are heartbeats. Use
            # the existing (project_slug,event_type,received_at) index so only
            # genuine page_view metadata, not tens of thousands of heartbeats,
            # crosses into Python.
            page_rows = db.execute(
                """SELECT path, visitor_id, session_id, page_view_id,
                          country, user_agent
                   FROM traffic_browser_events
                   INDEXED BY idx_traffic_browser_events_project_type_received
                   WHERE project_slug=? AND event_type='page_view'
                     AND received_at>=? AND received_at<?
                   ORDER BY received_at DESC""",
                (project_slug, begin.isoformat(), end.isoformat()),
            ).fetchall()

            # Collapse repeated cumulative heartbeat readings inside SQLite.
            # Group by UA as well as page identity, preserving the original
            # per-event bot exclusion even if one page identity contains
            # events from different user agents. MAX is NOT SUM: every
            # heartbeat repeats elapsed visible time.
            visible_rows = db.execute(
                """SELECT visitor_id, session_id, page_view_id, user_agent,
                          MAX(visible_ms) AS max_visible_ms
                   FROM traffic_browser_events
                   INDEXED BY idx_traffic_browser_events_project_received
                   WHERE project_slug=? AND received_at>=? AND received_at<?
                     AND typeof(visible_ms)='integer'
                     AND visible_ms>0 AND visible_ms<=?
                   GROUP BY visitor_id, session_id, page_view_id, user_agent""",
                (project_slug, begin.isoformat(), end.isoformat(),
                 MAX_VISIBLE_MS_PER_PAGE),
            ).fetchall()
    except sqlite3.Error as exc:
        raise ObservedInsightsUnavailable(
            "bounded browser evidence query exceeded time budget"
            if expired else "bounded read-only browser evidence scan failed"
        ) from exc

    page_views: dict[tuple[str, str, str], dict] = {}
    for row in page_rows:
        ua = str(row["user_agent"] or "").lower()
        if any(token in ua for token in BROWSER_EVENT_STORY_REJECT_UA_TERMS):
            continue
        visitor, session, view = (
            str(row[k] or "") for k in ("visitor_id", "session_id", "page_view_id")
        )
        if not visitor or not session or not view:
            continue
        path = public_path(str(row["path"] or ""))
        if path is None:
            continue
        # Match the existing descending-read last-write-wins semantics for
        # duplicate page-view IDs. Never infer a new page from heartbeats.
        page_views[(visitor, session, view)] = {
            "path": path, "country": str(row["country"] or "").strip()[:80],
        }

    duration_by_view: dict[tuple[str, str, str], int] = defaultdict(int)
    for row in visible_rows:
        ua = str(row["user_agent"] or "").lower()
        if any(token in ua for token in BROWSER_EVENT_STORY_REJECT_UA_TERMS):
            continue
        visitor, session, view = (
            str(row[k] or "") for k in ("visitor_id", "session_id", "page_view_id")
        )
        if not visitor or not session or not view:
            continue
        key = (visitor, session, view)
        duration_by_view[key] = max(
            duration_by_view[key], int(row["max_visible_ms"])
        )

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
    # Rank distinct observed browser IDs, never requests. Browser identifiers
    # are not verified people; publish only country-level aggregate counts,
    # never the underlying browser IDs, IPs, UAs or individual events.
    country_counts = [
        (country, len(identifiers))
        for country, identifiers in distinct_country_visitors.items()
    ]
    country_counts.sort(key=lambda p: (-p[1], p[0]))
    pages = sorted(page_counter.items(), key=lambda p: (-p[1], p[0]))[:5]
    average = (
        max(1, round(sum(positive_ms) / len(positive_ms) / 1000))
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
            "rows_scanned": rows_scanned,
        },
        "top_countries": [
            {
                "name": country,
                # Backward compatible with already-deployed consumers that
                # still apply the original small-cohort suppression contract.
                "unique_browser_ids": count if count >= MIN_COUNTRY_VISITORS else None,
                "small_cohort": count < MIN_COUNTRY_VISITORS,
                # Public country-level aggregate (not raw visitor IDs).
                # Allows the next UI to show exact 1–4 counts without breaking
                # the currently certified website during the two-repo rollout.
                "observed_browser_ids": count,
            }
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
