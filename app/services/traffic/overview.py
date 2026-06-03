from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from threading import Event, Lock, Thread
from time import monotonic
from typing import Any

from app.services.traffic.classify import classify_request, detect_route_kind
from app.services.traffic.config import (
    INTERNAL_IGNORE_PATHS,
    LIVE_TILE_LIMIT,
    LOG_PATH,
    LOG_PATHS,
    PERSIST_DB_PATH,
    SERIES_BUCKET_MINUTES,
    TAIL_LINES,
    TOP_LIMIT,
    VISITOR_SESSION_LIMIT,
    VISITS_HISTORY_LIMIT,
    PROJECTS,
    ALBERTA_TZ_NAME,
)
from app.services.traffic.geo import get_geo_details
from app.services.traffic.normalize import ALLOWED_HOSTS, is_allowed_host, project_for_host
from app.services.traffic.parse import iso_now, parse_log_line, read_recent_log_lines
from app.services.traffic.persistence import load_recent_entries, persistence_enabled
from app.services.traffic.sessions import (
    activity_sequence_for_events,
    build_path_stats,
    build_sessions,
    live_session_sort_key,
    ordered_unique,
    page_sequence_for_events,
    session_id_for_events,
    split_session_events,
)
from app.services.traffic.visibility import (
    entry_hidden_by_visibility_rules,
    safe_list_visibility_rules,
    visibility_signature,
)

from zoneinfo import ZoneInfo

ALBERTA_ZONE = ZoneInfo(ALBERTA_TZ_NAME)
PROJECT_GRAPH_RANGES: dict[str, dict[str, Any]] = {
    "24h": {"label": "24 Hours", "window_hours": 24},
    "7d": {"label": "1 Week", "window_hours": 24 * 7},
    "30d": {"label": "1 Month", "window_hours": 24 * 30},
    "all": {"label": "All Time", "window_hours": None},
}
SESSION_SNAPSHOT_CACHE_TTL_SECONDS = 15.0
SESSION_SNAPSHOT_CACHE_STALE_SECONDS = 120.0
SESSION_SNAPSHOT_ALL_TIME_TTL_SECONDS = 60.0
SESSION_SNAPSHOT_ALL_TIME_STALE_SECONDS = 300.0
SESSION_SNAPSHOT_CACHE_LIMIT = 8
_SESSION_SNAPSHOT_CACHE_LOCK = Lock()
_SESSION_SNAPSHOT_CACHE: dict[tuple[int | None, tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
_SESSION_SNAPSHOT_CACHE_REFRESHING: set[tuple[int | None, tuple[str, ...], tuple[str, ...]]] = set()
_SESSION_SNAPSHOT_CACHE_EVENTS: dict[tuple[int | None, tuple[str, ...], tuple[str, ...]], Event] = {}
LINKABLE_VISITOR_STATES = {"human_confirmed", "likely_human", "candidate"}
HUMAN_VISIBLE_STATES = {"human_confirmed", "likely_human", "candidate"}
AUTOMATED_OR_SCRIPT_STATES = {"browser_script", "script_burst", "bot", "suspicious"}
LINKED_VISITOR_LIMIT = 6


def should_ignore_entry(entry: dict[str, Any]) -> bool:
    host = entry["host"]
    path = entry["normalized_path"]
    ip = entry["ip"]
    ua = (entry["ua"] or "").lower()

    if path in INTERNAL_IGNORE_PATHS:
        if host == "vps-sentry.tokentap.ca":
            return True
        if ip in {"127.0.0.1", "::1", "157.180.114.124"}:
            return True
        if "node" in ua:
            return True

    return False


def collect_recent_entries(
    window_hours: int | None = 24,
) -> list[dict[str, Any]]:
    recent_entries, _ = collect_recent_entries_with_source(window_hours=window_hours)
    return recent_entries


def collect_recent_entries_with_source(
    window_hours: int | None = 24,
    *,
    project_slugs: set[str] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
        if window_hours is not None
        else None
    )
    recent_entries: list[dict[str, Any]] = []
    project_hosts = _hosts_for_projects(project_slugs)
    active_visibility_rules = safe_list_visibility_rules(active_only=True)
    persisted_entries = load_recent_entries(
        window_hours=window_hours,
        hosts=project_hosts,
        include_raw_fields=False,
    )
    source_mode = "durable_store" if persisted_entries is not None else "log_tail"

    if persisted_entries is None:
        source_entries: list[dict[str, Any]] = []
        seen_lines: set[str] = set()
        for log_path in LOG_PATHS:
            for line in read_recent_log_lines(log_path, TAIL_LINES):
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                parsed = parse_log_line(line)
                if parsed:
                    source_entries.append(parsed)
        source_entries.sort(key=lambda entry: entry["timestamp"])
    else:
        source_entries = persisted_entries

    for parsed in source_entries:
        if not is_allowed_host(parsed["host"]):
            continue

        if cutoff is not None and parsed["timestamp"] < cutoff:
            continue

        project = project_for_host(parsed["host"])
        if project_slugs is not None and project["slug"] not in project_slugs:
            continue

        parsed["category"] = classify_request(parsed["ua"], parsed["normalized_path"])
        parsed["route_kind"] = detect_route_kind(parsed["normalized_path"])

        if entry_hidden_by_visibility_rules(parsed, rules=active_visibility_rules):
            continue

        if should_ignore_entry(parsed):
            continue

        recent_entries.append(parsed)

    return recent_entries, source_mode


def _hosts_for_projects(project_slugs: set[str] | None) -> list[str] | None:
    if project_slugs is None:
        return None

    return sorted(
        {
            host
            for project in PROJECTS
            if project["slug"] in project_slugs
            for host in project["hosts"]
        }
    )


def _session_snapshot_key(
    window_hours: int | None,
    project_slugs: set[str] | None,
) -> tuple[int | None, tuple[str, ...], tuple[str, ...]]:
    return window_hours, tuple(sorted(project_slugs or ())), visibility_signature()


def _cached_session_snapshot(
    window_hours: int | None,
    *,
    project_slugs: set[str] | None = None,
    allow_stale: bool = False,
) -> dict[str, Any] | None:
    cache_key = _session_snapshot_key(window_hours, project_slugs)
    now_tick = monotonic()

    with _SESSION_SNAPSHOT_CACHE_LOCK:
        cached = _SESSION_SNAPSHOT_CACHE.get(cache_key)
        if not cached:
            return None
        if cached["expires_at"] > now_tick:
            return cached["value"]
        if not allow_stale or cached["stale_until"] <= now_tick:
            return None
        return cached["value"]


def _store_session_snapshot(
    window_hours: int | None,
    *,
    project_slugs: set[str] | None = None,
    sessions: list[dict[str, Any]],
    source_mode: str,
    earliest_entry_at: datetime | None,
) -> dict[str, Any]:
    cache_key = _session_snapshot_key(window_hours, project_slugs)
    value = {
        "sessions": sessions,
        "source_mode": source_mode,
        "earliest_entry_at": earliest_entry_at,
    }
    now_tick = monotonic()
    fresh_ttl = (
        SESSION_SNAPSHOT_ALL_TIME_TTL_SECONDS
        if window_hours is None
        else SESSION_SNAPSHOT_CACHE_TTL_SECONDS
    )
    stale_ttl = (
        SESSION_SNAPSHOT_ALL_TIME_STALE_SECONDS
        if window_hours is None
        else SESSION_SNAPSHOT_CACHE_STALE_SECONDS
    )

    with _SESSION_SNAPSHOT_CACHE_LOCK:
        if len(_SESSION_SNAPSHOT_CACHE) >= SESSION_SNAPSHOT_CACHE_LIMIT:
            _SESSION_SNAPSHOT_CACHE.clear()
        _SESSION_SNAPSHOT_CACHE[cache_key] = {
            "expires_at": now_tick + fresh_ttl,
            "stale_until": now_tick + fresh_ttl + stale_ttl,
            "value": value,
        }

    return value


def _rebuild_session_snapshot(
    *,
    window_hours: int | None,
    project_slugs: set[str] | None = None,
) -> dict[str, Any]:
    entries, source_mode = collect_recent_entries_with_source(
        window_hours=window_hours,
        project_slugs=project_slugs,
    )
    sessions = build_sessions(entries)
    return _store_session_snapshot(
        window_hours,
        project_slugs=project_slugs,
        sessions=sessions,
        source_mode=source_mode,
        earliest_entry_at=min((entry["timestamp"] for entry in entries), default=None),
    )


def _refresh_session_snapshot_async(
    *,
    window_hours: int | None,
    project_slugs: set[str] | None = None,
) -> bool:
    cache_key = _session_snapshot_key(window_hours, project_slugs)

    with _SESSION_SNAPSHOT_CACHE_LOCK:
        if cache_key in _SESSION_SNAPSHOT_CACHE_REFRESHING:
            return False
        _SESSION_SNAPSHOT_CACHE_REFRESHING.add(cache_key)
        refresh_event = Event()
        _SESSION_SNAPSHOT_CACHE_EVENTS[cache_key] = refresh_event

    def refresh() -> None:
        try:
            _rebuild_session_snapshot(
                window_hours=window_hours,
                project_slugs=project_slugs,
            )
        finally:
            with _SESSION_SNAPSHOT_CACHE_LOCK:
                _SESSION_SNAPSHOT_CACHE_REFRESHING.discard(cache_key)
                _SESSION_SNAPSHOT_CACHE_EVENTS.get(cache_key, refresh_event).set()

    Thread(target=refresh, daemon=True).start()
    return True


def _wait_for_session_snapshot_refresh(
    *,
    window_hours: int | None,
    project_slugs: set[str] | None = None,
) -> dict[str, Any] | None:
    cache_key = _session_snapshot_key(window_hours, project_slugs)
    timeout_seconds = 90.0 if window_hours is None else 60.0

    with _SESSION_SNAPSHOT_CACHE_LOCK:
        if cache_key not in _SESSION_SNAPSHOT_CACHE_REFRESHING:
            return None
        refresh_event = _SESSION_SNAPSHOT_CACHE_EVENTS.get(cache_key)

    if refresh_event is None:
        return None

    refresh_event.wait(timeout=timeout_seconds)
    return _cached_session_snapshot(window_hours, project_slugs=project_slugs)


def _build_session_snapshot(
    *,
    window_hours: int | None,
    project_slugs: set[str] | None = None,
) -> dict[str, Any]:
    cached = _cached_session_snapshot(window_hours, project_slugs=project_slugs)
    if cached:
        return cached

    stale = _cached_session_snapshot(
        window_hours,
        project_slugs=project_slugs,
        allow_stale=True,
    )
    if stale:
        _refresh_session_snapshot_async(
            window_hours=window_hours,
            project_slugs=project_slugs,
        )
        return stale

    waited = _wait_for_session_snapshot_refresh(
        window_hours=window_hours,
        project_slugs=project_slugs,
    )
    if waited:
        return waited

    return _rebuild_session_snapshot(
        window_hours=window_hours,
        project_slugs=project_slugs,
    )


def warm_session_snapshots() -> None:
    _refresh_session_snapshot_async(window_hours=24)
    _refresh_session_snapshot_async(window_hours=None)


def clear_session_snapshot_cache() -> None:
    with _SESSION_SNAPSHOT_CACHE_LOCK:
        _SESSION_SNAPSHOT_CACHE.clear()
        _SESSION_SNAPSHOT_CACHE_REFRESHING.clear()
        _SESSION_SNAPSHOT_CACHE_EVENTS.clear()


def _project_options() -> list[dict[str, str]]:
    return [{"slug": project["slug"], "name": project["name"]} for project in PROJECTS]


def build_overview(range_key: str = "24h") -> dict[str, Any]:
    range_config = _range_config(range_key)
    window_hours = _window_hours_for_range(range_key)
    recent_entries, source_mode = collect_recent_entries_with_source(window_hours=window_hours)
    cached_snapshot = _cached_session_snapshot(window_hours)
    earliest_entry_at = min((entry["timestamp"] for entry in recent_entries), default=None)
    now = datetime.now(timezone.utc)
    requested_start = (
        now - timedelta(hours=window_hours) if window_hours is not None else None
    )

    host_request_counter = Counter()
    project_request_counter = Counter()
    project_session_counter = Counter()
    project_engaged_counter = Counter()
    project_suspicious_counter = Counter()
    project_human_confirmed_counter = Counter()
    unique_visitors = set()

    human_requests = 0
    bot_requests = 0
    suspicious_requests = 0
    unknown_requests = 0

    country_sessions = Counter()
    area_sessions = Counter()
    city_sessions = Counter()
    suspicious_path_counter = Counter()
    top_ip_counter = Counter()
    top_ip_category: dict[str, str] = {}
    top_ip_last_seen: dict[str, str] = {}

    total_requests = 0

    host_visitors = defaultdict(set)
    host_humans = Counter()
    host_bots = Counter()
    host_suspicious = Counter()
    host_top_entry = Counter()
    host_top_exit = Counter()
    host_session_seconds = Counter()
    host_session_counts = Counter()

    for parsed in recent_entries:
        total_requests += 1
        unique_visitors.add((parsed["host"], parsed["ip"], (parsed["ua"] or "").lower()))
        host_request_counter[parsed["host"]] += 1
        host_visitors[parsed["host"]].add(parsed["ip"])

        project = project_for_host(parsed["host"])
        project_request_counter[project["slug"]] += 1

        top_ip_counter[parsed["ip"]] += 1
        top_ip_category[parsed["ip"]] = parsed["category"]
        top_ip_last_seen[parsed["ip"]] = parsed["timestamp_iso"]

        if parsed["category"] == "human":
            human_requests += 1
            host_humans[parsed["host"]] += 1
        elif parsed["category"] == "bot":
            bot_requests += 1
            host_bots[parsed["host"]] += 1
        elif parsed["category"] == "suspicious":
            suspicious_requests += 1
            host_suspicious[parsed["host"]] += 1
            suspicious_path_counter[parsed["normalized_path"]] += 1
        else:
            unknown_requests += 1

    if cached_snapshot and cached_snapshot["source_mode"] == source_mode:
        sessions = cached_snapshot["sessions"]
    else:
        sessions = build_sessions(recent_entries)
        _store_session_snapshot(
            window_hours,
            sessions=sessions,
            source_mode=source_mode,
            earliest_entry_at=earliest_entry_at,
        )
    likely_human_states = {"human_confirmed", "likely_human"}
    automated_states = AUTOMATED_OR_SCRIPT_STATES

    unique_people = {session["person_key"] for session in sessions}
    real_people = {
        session["person_key"]
        for session in sessions
        if session["classification_state"] in likely_human_states
    }
    automated_people = {
        session["person_key"]
        for session in sessions
        if session["classification_state"] in automated_states
    }
    live_people = {
        session["person_key"]
        for session in sessions
        if session["active_now"] and session["classification_state"] not in automated_states
    }
    returning_people = {
        session["person_key"]
        for session in sessions
        if session["returning_visitor"] and session["classification_state"] not in automated_states
    }
    active_projects = {
        session["project_slug"]
        for session in sessions
        if session["active_now"] and session["classification_state"] not in automated_states
    }

    for session in sessions:
        project_session_counter[session["project_slug"]] += 1

        if session["engaged_seconds"] > 0:
            project_engaged_counter[session["project_slug"]] += 1

        if session["suspicious_score"] >= 40:
            project_suspicious_counter[session["project_slug"]] += 1

        if session["classification_state"] == "human_confirmed":
            project_human_confirmed_counter[session["project_slug"]] += 1

        geo_key_area = (session["country"], session["area"])
        geo_key_city = (session["country"], session["area"], session["city"])

        country_sessions[session["country"]] += 1
        if session["area"]:
            area_sessions[geo_key_area] += 1
        if session["city"]:
            city_sessions[geo_key_city] += 1

        host_top_entry[(session["host"], session["entry_page"])] += 1
        host_top_exit[(session["host"], session["exit_page"])] += 1
        host_session_seconds[session["host"]] += session["total_seconds"]
        host_session_counts[session["host"]] += 1

    projects: list[dict[str, Any]] = []

    for project in PROJECTS:
        slug = project["slug"]
        if project_request_counter[slug] == 0 and project_session_counter[slug] == 0:
            continue

        projects.append(
            {
                "slug": slug,
                "name": project["name"],
                "category": project["category"],
                "requests": project_request_counter[slug],
                "sessions": project_session_counter[slug],
                "engaged_sessions": project_engaged_counter[slug],
                "human_confirmed_sessions": project_human_confirmed_counter[slug],
                "suspicious": project_suspicious_counter[slug],
            }
        )

    projects.sort(key=lambda row: row["requests"], reverse=True)

    hosts: list[dict[str, Any]] = []

    for host, request_count in host_request_counter.most_common(TOP_LIMIT):
        entry_candidates = [
            (path, count)
            for (known_host, path), count in host_top_entry.items()
            if known_host == host
        ]
        exit_candidates = [
            (path, count)
            for (known_host, path), count in host_top_exit.items()
            if known_host == host
        ]

        top_entry_page = max(entry_candidates, key=lambda item: item[1])[0] if entry_candidates else "/"
        top_exit_page = max(exit_candidates, key=lambda item: item[1])[0] if exit_candidates else "/"
        avg_session_seconds = int(host_session_seconds[host] / host_session_counts[host]) if host_session_counts[host] else 0

        hosts.append(
            {
                "host": host,
                "project_slug": project_for_host(host)["slug"],
                "requests": request_count,
                "unique_visitors": len(host_visitors[host]),
                "sessions": host_session_counts[host],
                "human_requests": host_humans[host],
                "bot_requests": host_bots[host],
                "suspicious_requests": host_suspicious[host],
                "top_entry_page": top_entry_page,
                "top_exit_page": top_exit_page,
                "avg_session_seconds": avg_session_seconds,
            }
        )

    top_pages = build_path_stats(recent_entries)
    prioritized_sessions = _chronological_sessions_desc(sessions, limit=10)

    country_rows = [
        {
            "country": country,
            "sessions": count,
            "requests": sum(1 for entry in recent_entries if get_geo_details(entry["ip"])["country"] == country),
        }
        for country, count in country_sessions.most_common(TOP_LIMIT)
    ]

    area_rows = [
        {"country": country, "area": area, "sessions": count}
        for (country, area), count in area_sessions.most_common(TOP_LIMIT)
    ]

    city_rows = [
        {"country": country, "area": area, "city": city, "sessions": count}
        for (country, area, city), count in city_sessions.most_common(TOP_LIMIT)
    ]

    suspicious_top_ips: list[dict[str, Any]] = []

    for ip, count in top_ip_counter.most_common(TOP_LIMIT):
        category = top_ip_category.get(ip, "unknown")
        if category not in {"suspicious", "bot"}:
            continue

        suspicious_top_ips.append(
            {
                "ip": ip,
                "country": get_geo_details(ip)["country"],
                "count": count,
                "category": category,
                "last_seen": top_ip_last_seen.get(ip),
            }
        )

    alerts: list[dict[str, Any]] = []

    if suspicious_requests:
        hot_host = host_suspicious.most_common(1)[0] if host_suspicious else None
        if hot_host:
            alerts.append(
                {
                    "severity": "high",
                    "title": f"Probe pressure on {hot_host[0]}",
                    "count": hot_host[1],
                }
            )

    if bot_requests:
        noisy_host = host_bots.most_common(1)[0] if host_bots else None
        if noisy_host:
            alerts.append(
                {
                    "severity": "medium",
                    "title": f"Bot-heavy traffic on {noisy_host[0]}",
                    "count": noisy_host[1],
                }
            )

    if len(LOG_PATHS) == 1:
        alerts.append(
            {
                "severity": "low",
                "title": f"Reading local log file {LOG_PATH}",
                "count": total_requests,
            }
        )
    else:
        alerts.append(
            {
                "severity": "low",
                "title": f"Reading {len(LOG_PATHS)} local log files",
                "count": total_requests,
            }
        )

    avg_session_seconds = int(sum(session["total_seconds"] for session in sessions) / len(sessions)) if sessions else 0
    avg_page_seconds = int(sum(page["avg_seconds"] for page in top_pages) / len(top_pages)) if top_pages else 0

    notes = [
        "Traffic service has been split into focused modules.",
        "This view is built from log lines, not seeded demo data.",
        (
            f"Current source log: {LOG_PATH}"
            if len(LOG_PATHS) == 1
            else f"Current source logs: {', '.join(str(path) for path in LOG_PATHS)}"
        ),
        f"Host allowlist live: {len(ALLOWED_HOSTS)} approved hosts.",
    ]

    from app.services.traffic.geo import geoip_status

    geo_status = geoip_status()
    if geo_status["available"]:
        notes.append(f"GeoIP reader loaded: {geo_status['path']}")
    else:
        notes.append(f"GeoIP unavailable: {geo_status['reason']} ({geo_status['path']})")

    if persistence_enabled():
        notes.append(f"Durable traffic store active: {PERSIST_DB_PATH}")
    else:
        notes.append("Durable traffic store disabled: Traffic is reading the live log tail only.")

    notes.append("Route classification is live: page, api, probe, asset.")
    notes.append("Live visitor tower and human series endpoints are now available.")

    note: str | None = None
    if source_mode != "durable_store":
        note = "Durable storage is unavailable, so this overview is currently reading the live log tail."
    elif range_key == "all":
        if earliest_entry_at:
            note = (
                "All-time currently means everything Traffic has stored for the observatory since "
                f"{_format_alberta_timestamp(earliest_entry_at)}."
            )
        else:
            note = "All-time view is ready, but Traffic has not stored any observable traffic yet."
    elif earliest_entry_at and requested_start and earliest_entry_at > requested_start:
        note = (
            f"Durable storage for the observatory currently begins at "
            f"{_format_alberta_timestamp(earliest_entry_at)}, so this {range_config['label'].lower()} "
            "view starts there."
        )

    return {
        "ok": True,
        "generated_at": iso_now(),
        "range_key": range_key,
        "range_label": range_config["label"],
        "window_hours": window_hours,
        "window": range_config["label"],
        "coverage_mode": source_mode,
        "coverage_started_at": earliest_entry_at.isoformat() if earliest_entry_at else None,
        "coverage_started_alberta": (
            _format_alberta_timestamp(earliest_entry_at) if earliest_entry_at else None
        ),
        "note": note,
        "totals": {
            "requests": total_requests,
            "humans": human_requests,
            "bots": bot_requests,
            "suspicious": suspicious_requests,
            "unknown": unknown_requests,
            "unique_visitors": len(unique_visitors),
            "total_visitors": len(unique_people),
            "real_humans": len(real_people),
            "suspected_bots": len(automated_people),
            "live_now": len(live_people),
            "returning_visitors": len(returning_people),
            "projects_active": len(active_projects),
            "sessions": len(sessions),
            "engaged_sessions": sum(1 for session in sessions if session["engaged_seconds"] > 0),
            "avg_session_seconds": avg_session_seconds,
            "avg_page_seconds": avg_page_seconds,
        },
        "projects": projects,
        "hosts": hosts,
        "suspicious": {
            "top_paths": [
                {"path": path, "count": count}
                for path, count in suspicious_path_counter.most_common(TOP_LIMIT)
            ],
            "top_ips": suspicious_top_ips,
        },
        "recent_sessions": prioritized_sessions,
        "top_pages": top_pages,
        "geo": {
            "countries": country_rows,
            "areas": area_rows,
            "cities": city_rows,
        },
        "alerts": alerts[:3],
        "notes": notes,
    }


def build_live_visitors(
    *,
    limit: int = LIVE_TILE_LIMIT,
    history_limit: int = VISITS_HISTORY_LIMIT,
    window_hours: int = 24,
) -> dict[str, Any]:
    snapshot = _build_session_snapshot(window_hours=window_hours)
    sessions = snapshot["sessions"]
    # Keep enough non-human/uncertain page-shaped sessions visible for operator review.
    # A one-page cloud/browser visitor should not vanish just because the main people feed is capped.
    auxiliary_limit = max(100, limit)

    tower_candidates = [
        session
        for session in sessions
        if session["classification_state"] in HUMAN_VISIBLE_STATES
        and (session["page_count"] > 0 or session["route_kind"] == "page")
    ]
    browser_script_candidates = [
        session
        for session in sessions
        if session["classification_state"] in {"browser_script", "script_burst"}
        and (session["page_count"] > 0 or session["route_kind"] == "page")
    ]
    automation_candidates = [
        session
        for session in sessions
        if session.get("known_automation")
        and (session["page_count"] > 0 or session["route_kind"] == "page")
    ]
    security_candidates = [
        session
        for session in sessions
        if session["classification_state"] == "suspicious"
        and (session["page_count"] > 0 or session["route_kind"] == "page")
    ]

    tower = sorted(tower_candidates, key=live_session_sort_key)[:limit]
    browser_script_preview = sorted(browser_script_candidates, key=live_session_sort_key)[:auxiliary_limit]
    automation_preview = sorted(automation_candidates, key=live_session_sort_key)[:auxiliary_limit]
    security_preview = sorted(security_candidates, key=live_session_sort_key)[:auxiliary_limit]

    history_candidates = sorted(tower_candidates, key=lambda item: item["ended_at"], reverse=True)
    # history_candidates is sorted newest-first by ended_at.
    # Keep that order so recent sessions stay at the top of the live stream.
    history_items = history_candidates[limit : limit + history_limit]
    stream_items = history_candidates[: limit + history_limit]

    review_candidates = sorted(
        browser_script_candidates + automation_candidates + security_candidates,
        key=live_session_sort_key,
    )[:auxiliary_limit]

    recent_page_review_candidates = sorted(
        [
            session
            for session in sessions
            if session.get("route_kind") == "page"
            and session.get("project_slug")
            and not (
                session.get("primary_category") == "security"
                or int(session.get("suspicious_score") or 0) >= 70
            )
        ],
        key=lambda item: item.get("ended_at") or "",
        reverse=True,
    )[: max(250, limit)]

    project_counts: list[dict[str, Any]] = []
    for project in PROJECTS:
        slug = project["slug"]
        project_sessions = [session for session in tower_candidates if session["project_slug"] == slug]
        if not project_sessions:
            continue

        project_counts.append(
            {
                "slug": slug,
                "name": project["name"],
                "human_confirmed": sum(1 for session in project_sessions if session["classification_state"] == "human_confirmed"),
                "likely_human": sum(1 for session in project_sessions if session["classification_state"] == "likely_human"),
                "candidate": sum(1 for session in project_sessions if session["classification_state"] == "candidate"),
                "browser_script": sum(1 for session in project_sessions if session["classification_state"] == "browser_script"),
                "active_now": sum(1 for session in project_sessions if session["active_now"]),
            }
        )

    project_counts.sort(key=lambda row: (row["human_confirmed"], row["likely_human"], row["active_now"]), reverse=True)

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "tower_limit": limit,
        "history_count": max(0, len(history_candidates) - limit),
        "stream_total": len(history_candidates),
        "stream_items": stream_items,
        "browser_script_count": len(browser_script_candidates),
        "browser_script_preview": browser_script_preview,
        "automation_count": len(automation_candidates),
        "automation_preview": automation_preview,
        "security_count": len(security_candidates),
        "security_preview": security_preview,
        "review_count": len(browser_script_candidates) + len(automation_candidates) + len(security_candidates),
        "review_preview": review_candidates,
        "recent_page_review_count": len(recent_page_review_candidates),
        "recent_page_review": recent_page_review_candidates,
        "available_projects": _project_options(),
        "project_counts": project_counts,
        "top_25": tower,
        "history_preview": history_items,
    }


def _chronological_sessions_desc(
    sessions: list[dict[str, Any]],
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    items = sorted(sessions, key=lambda item: item["ended_at"], reverse=True)
    if limit is None:
        return items
    return items[:limit]


def _browser_family(browser: str) -> str:
    lowered = (browser or "").strip().lower()
    if lowered in {"chrome", "edge", "firefox", "safari"}:
        return lowered
    if lowered.startswith("chrome"):
        return "chrome"
    if lowered.startswith("firefox"):
        return "firefox"
    if lowered.startswith("safari"):
        return "safari"
    if lowered.startswith("edge"):
        return "edge"
    return lowered


def _session_windows_close(
    session_a: dict[str, Any],
    session_b: dict[str, Any],
    *,
    window_hours: int = 18,
) -> bool:
    a_start = datetime.fromisoformat(session_a["first_seen_at"])
    a_end = datetime.fromisoformat(session_a["last_seen_at"])
    b_start = datetime.fromisoformat(session_b["first_seen_at"])
    b_end = datetime.fromisoformat(session_b["last_seen_at"])

    latest_start = max(a_start, b_start)
    earliest_end = min(a_end, b_end)
    if latest_start <= earliest_end:
        return True

    gap_seconds = min(
        abs((b_start - a_end).total_seconds()),
        abs((a_start - b_end).total_seconds()),
    )
    return gap_seconds <= window_hours * 3600


def _build_linked_visitor_profiles(
    *,
    all_sessions: list[dict[str, Any]],
    visitor_sessions: list[dict[str, Any]],
    visitor_id: str,
) -> list[dict[str, Any]]:
    if not visitor_sessions:
        return []

    latest = max(visitor_sessions, key=lambda session: session["last_seen_at"])
    target_project_slugs = {session["project_slug"] for session in visitor_sessions}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for session in all_sessions:
        if session.get("visitor_profile_id") == visitor_id:
            continue
        if session["ip"] != latest["ip"]:
            continue
        if session["known_automation"] or session["classification_state"] not in LINKABLE_VISITOR_STATES:
            continue
        if session["country_code"] != latest["country_code"]:
            continue
        if session["area"] != latest["area"] or session["city"] != latest["city"]:
            continue

        same_browser_family = _browser_family(session["browser"]) == _browser_family(latest["browser"])
        shared_project = session["project_slug"] in target_project_slugs
        nearby_window = any(
            _session_windows_close(session, target_session) for target_session in visitor_sessions
        )

        if not (same_browser_family or (shared_project and nearby_window)):
            continue

        grouped[session["visitor_profile_id"]].append(session)

    linked_profiles: list[dict[str, Any]] = []
    for profile_id, sessions in grouped.items():
        newest = max(sessions, key=lambda session: session["last_seen_at"])
        oldest = min(sessions, key=lambda session: session["first_seen_at"])
        projects = ordered_unique([session["project_name"] for session in sessions])
        same_browser_family = any(
            _browser_family(session["browser"]) == _browser_family(latest["browser"])
            for session in sessions
        )
        shared_projects = ordered_unique(
            [
                session["project_name"]
                for session in sessions
                if session["project_slug"] in target_project_slugs
            ]
        )
        nearby_window = any(
            any(_session_windows_close(session, target_session) for target_session in visitor_sessions)
            for session in sessions
        )

        reason_bits: list[str] = []
        if same_browser_family:
            reason_bits.append("same browser family")
        if shared_projects:
            reason_bits.append(
                "shared project "
                + (shared_projects[0] if len(shared_projects) == 1 else f"{shared_projects[0]} +{len(shared_projects) - 1}")
            )
        if nearby_window:
            reason_bits.append("nearby activity window")

        linked_profiles.append(
            {
                "id": profile_id,
                "alias": newest["visitor_alias"],
                "ip": newest["ip"],
                "browser": newest["browser"],
                "device": newest["device"],
                "os": newest["os"],
                "country": newest["country"],
                "country_code": newest["country_code"],
                "area": newest["area"],
                "city": newest["city"],
                "first_seen_at": oldest["first_seen_at"],
                "last_seen_at": newest["last_seen_at"],
                "first_seen_alberta": oldest["first_seen_alberta"],
                "last_seen_alberta": newest["last_seen_alberta"],
                "total_sessions": len(sessions),
                "projects_visited": len({session["project_slug"] for session in sessions}),
                "project_names": projects,
                "reason": ", ".join(reason_bits) if reason_bits else "same source context",
            }
        )

    linked_profiles.sort(key=lambda item: item["last_seen_at"], reverse=True)
    return linked_profiles[:LINKED_VISITOR_LIMIT]


def _project_live_feed_sessions(
    sessions: list[dict[str, Any]],
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    automated_states = AUTOMATED_OR_SCRIPT_STATES
    visible_sessions = [
        session for session in sessions if session["classification_state"] not in automated_states
    ]
    return _chronological_sessions_desc(visible_sessions, limit=limit)


def build_visits_history(
    *,
    limit: int = 100,
    offset: int = 0,
    range_key: str = "all",
    classification: str | None = None,
    project_slugs: list[str] | None = None,
) -> dict[str, Any]:
    range_config = _range_config(range_key)
    window_hours = _window_hours_for_range(range_key)
    selected_project_slugs = set(project_slugs) if project_slugs is not None else None
    snapshot = _build_session_snapshot(window_hours=window_hours)
    source_mode = snapshot["source_mode"]
    sessions = snapshot["sessions"]

    filtered = sessions
    if classification == "known_automation":
        filtered = [session for session in filtered if session.get("known_automation")]
    elif classification == "other_bot":
        filtered = [
            session
            for session in filtered
            if session["classification_state"] == "bot" and not session.get("known_automation")
        ]
    elif classification:
        filtered = [session for session in filtered if session["classification_state"] == classification]
    if selected_project_slugs is not None:
        filtered = [
            session
            for session in filtered
            if session["project_slug"] in selected_project_slugs
        ]

    filtered = sorted(filtered, key=lambda item: item["ended_at"], reverse=True)
    total = len(filtered)
    items = filtered[offset : offset + limit]
    oldest_filtered = filtered[-1] if filtered else None
    requested_start = (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
        if window_hours is not None
        else None
    )

    note: str | None = None
    if source_mode != "durable_store":
        note = "Durable storage is unavailable, so this archive is currently reading the live log tail."
    elif oldest_filtered:
        if range_key == "all":
            note = (
                "All-time currently means everything Traffic has stored for these matching sessions since "
                f"{oldest_filtered['first_seen_alberta']}."
            )
        elif requested_start:
            oldest_started_at = datetime.fromisoformat(oldest_filtered["first_seen_at"])
            if oldest_started_at > requested_start:
                note = (
                    f"Durable storage for these matching sessions currently begins at "
                    f"{oldest_filtered['first_seen_alberta']}, so this {range_config['label'].lower()} "
                    "view starts there."
                )
    elif range_key == "all":
        note = "All-time archive is ready, but no sessions match the current filters yet."

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "range_key": range_key,
        "range_label": range_config["label"],
        "coverage_mode": source_mode,
        "coverage_started_at": oldest_filtered["first_seen_at"] if oldest_filtered else None,
        "coverage_started_alberta": oldest_filtered["first_seen_alberta"] if oldest_filtered else None,
        "note": note,
        "offset": offset,
        "limit": limit,
        "total": total,
        "available_projects": _project_options(),
        "items": items,
    }


def _align_bucket(value: datetime, bucket_minutes: int) -> datetime:
    aligned_timestamp = int(value.timestamp() // (bucket_minutes * 60)) * (bucket_minutes * 60)
    return datetime.fromtimestamp(aligned_timestamp, tz=value.tzinfo or timezone.utc)


def _range_config(range_key: str) -> dict[str, Any]:
    return PROJECT_GRAPH_RANGES.get(range_key, PROJECT_GRAPH_RANGES["24h"])


def _window_hours_for_range(range_key: str) -> int | None:
    return _range_config(range_key)["window_hours"]


def _format_alberta_timestamp(value: datetime) -> str:
    return value.astimezone(ALBERTA_ZONE).strftime("%Y-%m-%d %I:%M %p")


def _bucket_minutes_for_span(start: datetime, end: datetime) -> int:
    span_hours = max((end - start).total_seconds() / 3600, 0.5)
    if span_hours <= 36:
        return 30
    if span_hours <= 72:
        return 60
    if span_hours <= 24 * 10:
        return 180
    if span_hours <= 24 * 40:
        return 720
    return 1440


def _bucket_label(bucket: datetime, bucket_minutes: int) -> str:
    local_bucket = bucket.astimezone(ALBERTA_ZONE)
    if bucket_minutes >= 1440:
        return local_bucket.strftime("%b %d")
    if bucket_minutes >= 60:
        return local_bucket.strftime("%b %d %I %p")
    return local_bucket.strftime("%I:%M %p")


def _project_graph_payload(
    *,
    project_slug: str,
    range_key: str = "24h",
    bucket_minutes_override: int | None = None,
) -> dict[str, Any]:
    range_config = PROJECT_GRAPH_RANGES.get(range_key, PROJECT_GRAPH_RANGES["24h"])
    window_hours = range_config["window_hours"]
    snapshot = _build_session_snapshot(
        window_hours=window_hours,
        project_slugs={project_slug},
    )
    source_mode = snapshot["source_mode"]
    sessions = snapshot["sessions"]

    now = datetime.now(timezone.utc)
    earliest_entry_at = snapshot.get("earliest_entry_at")
    requested_start = (
        now - timedelta(hours=window_hours) if window_hours is not None else None
    )

    if requested_start is None:
        effective_start = earliest_entry_at or (now - timedelta(hours=24))
    elif earliest_entry_at and earliest_entry_at > requested_start:
        effective_start = earliest_entry_at
    else:
        effective_start = requested_start

    bucket_minutes = bucket_minutes_override or _bucket_minutes_for_span(effective_start, now)
    first_bucket = _align_bucket(effective_start, bucket_minutes)
    last_bucket = _align_bucket(now, bucket_minutes)

    bucket_list: list[datetime] = []
    cursor = first_bucket
    while cursor <= last_bucket:
        bucket_list.append(cursor)
        cursor += timedelta(minutes=bucket_minutes)

    series_counter = Counter()
    for session in sessions:
        if session["classification_state"] != "human_confirmed":
            continue

        started_at = datetime.fromisoformat(session["started_at"])
        bucket = _align_bucket(started_at, bucket_minutes)
        if first_bucket <= bucket <= last_bucket:
            series_counter[bucket.isoformat()] += 1

    note: str | None = None
    if range_key == "all":
        if earliest_entry_at:
            note = (
                "All-time currently means everything Traffic has stored for this project since "
                f"{_format_alberta_timestamp(earliest_entry_at)}."
            )
        elif source_mode == "durable_store":
            note = "All-time view is ready, but this project has no stored visits yet."
    elif earliest_entry_at and requested_start and earliest_entry_at > requested_start:
        note = (
            f"Durable storage for this project currently begins at "
            f"{_format_alberta_timestamp(earliest_entry_at)}, so this {range_config['label'].lower()} "
            "view starts there."
        )

    if source_mode != "durable_store":
        note = "Durable storage is unavailable, so this graph is currently reading the live log tail."

    return {
        "label": "Confirmed human arrivals",
        "series_kind": "confirmed_human_arrivals",
        "range_key": range_key,
        "range_label": range_config["label"],
        "window_hours": window_hours,
        "bucket_minutes": bucket_minutes,
        "coverage_mode": source_mode,
        "coverage_started_at": earliest_entry_at.isoformat() if earliest_entry_at else None,
        "coverage_started_alberta": (
            _format_alberta_timestamp(earliest_entry_at) if earliest_entry_at else None
        ),
        "note": note,
        "points": [
            {
                "bucket_start": bucket.isoformat(),
                "label": _bucket_label(bucket, bucket_minutes),
                "visitors": series_counter.get(bucket.isoformat(), 0),
            }
            for bucket in bucket_list
        ],
    }


def build_project_human_series(
    *,
    range_key: str = "24h",
    bucket_minutes_override: int | None = None,
) -> dict[str, Any]:
    range_config = PROJECT_GRAPH_RANGES.get(range_key, PROJECT_GRAPH_RANGES["24h"])
    window_hours = range_config["window_hours"]
    snapshot = _build_session_snapshot(window_hours=window_hours)
    source_mode = snapshot["source_mode"]
    sessions = snapshot["sessions"]
    now = datetime.now(timezone.utc)
    earliest_entry_at = snapshot.get("earliest_entry_at")
    requested_start = (
        now - timedelta(hours=window_hours) if window_hours is not None else None
    )

    if requested_start is None:
        effective_start = earliest_entry_at or (now - timedelta(hours=24))
    elif earliest_entry_at and earliest_entry_at > requested_start:
        effective_start = earliest_entry_at
    else:
        effective_start = requested_start

    bucket_minutes = bucket_minutes_override or _bucket_minutes_for_span(effective_start, now)
    first_bucket = _align_bucket(effective_start, bucket_minutes)
    last_bucket = _align_bucket(now, bucket_minutes)

    bucket_list: list[datetime] = []
    cursor = first_bucket
    while cursor <= last_bucket:
        bucket_list.append(cursor)
        cursor += timedelta(minutes=bucket_minutes)

    points_by_project: dict[str, Counter] = defaultdict(Counter)
    live_counts = Counter()

    for session in sessions:
        if session["classification_state"] != "human_confirmed":
            continue

        started_at = datetime.fromisoformat(session["started_at"])
        bucket = _align_bucket(started_at, bucket_minutes)
        if bucket < first_bucket or bucket > last_bucket:
            continue

        points_by_project[session["project_slug"]][bucket.isoformat()] += 1

        if session["active_now"]:
            live_counts[session["project_slug"]] += 1

    projects_output: list[dict[str, Any]] = []

    for project in PROJECTS:
        slug = project["slug"]

        points = []
        for bucket in bucket_list:
            bucket_iso = bucket.isoformat()
            points.append(
                {
                    "bucket_start": bucket_iso,
                    "label": bucket.astimezone(ALBERTA_ZONE).strftime("%I:%M %p"),
                    "visitors": points_by_project[slug].get(bucket_iso, 0),
                }
            )

        if any(point["visitors"] > 0 for point in points) or live_counts[slug] > 0:
            projects_output.append(
                {
                    "slug": slug,
                    "name": project["name"],
                    "live_humans": live_counts[slug],
                    "points": points,
                }
            )

    note: str | None = None
    if range_key == "all":
        if earliest_entry_at:
            note = (
                "All-time currently means everything Traffic has stored for the observatory since "
                f"{_format_alberta_timestamp(earliest_entry_at)}."
            )
        elif source_mode == "durable_store":
            note = "All-time view is ready, but Traffic has not stored any human sessions yet."
    elif earliest_entry_at and requested_start and earliest_entry_at > requested_start:
        note = (
            f"Durable storage for the observatory currently begins at "
            f"{_format_alberta_timestamp(earliest_entry_at)}, so this {range_config['label'].lower()} "
            "view starts there."
        )

    if source_mode != "durable_store":
        note = (
            "Durable storage is unavailable, so these graphs are currently reading the live log tail."
        )

    return {
        "ok": True,
        "generated_at": iso_now(),
        "range_key": range_key,
        "range_label": range_config["label"],
        "window_hours": window_hours,
        "bucket_minutes": bucket_minutes,
        "coverage_mode": source_mode,
        "coverage_started_at": earliest_entry_at.isoformat() if earliest_entry_at else None,
        "coverage_started_alberta": (
            _format_alberta_timestamp(earliest_entry_at) if earliest_entry_at else None
        ),
        "note": note,
        "series_kind": "confirmed_human_arrivals",
        "projects": projects_output,
    }


def build_project_graph(
    *,
    project_slug: str,
    range_key: str = "24h",
) -> dict[str, Any]:
    project = next((item for item in PROJECTS if item["slug"] == project_slug), None)
    if not project:
        return {
            "ok": False,
            "generated_at": iso_now(),
            "project_slug": project_slug,
            "range_key": range_key,
        }

    return {
        "ok": True,
        "generated_at": iso_now(),
        "project": {
            "slug": project["slug"],
            "name": project["name"],
        },
        "graph": _project_graph_payload(
            project_slug=project["slug"],
            range_key=range_key,
        ),
    }


def build_project_detail(
    *,
    project_slug: str,
    window_hours: int = 24,
    bucket_minutes: int = SERIES_BUCKET_MINUTES,
    include_deep: bool = True,
) -> dict[str, Any]:
    project = next((item for item in PROJECTS if item["slug"] == project_slug), None)
    if not project:
        return {
            "ok": False,
            "generated_at": iso_now(),
            "window_hours": window_hours,
            "project_slug": project_slug,
        }

    recent_entries = [
        entry
        for entry in collect_recent_entries(window_hours=window_hours)
        if project_for_host(entry["host"])["slug"] == project_slug
    ]
    sessions = _build_session_snapshot(
        window_hours=window_hours,
        project_slugs={project_slug},
    )["sessions"]

    likely_human_states = {"human_confirmed", "likely_human"}
    automated_states = AUTOMATED_OR_SCRIPT_STATES

    unique_people = {session["person_key"] for session in sessions}
    real_humans = {
        session["person_key"]
        for session in sessions
        if session["classification_state"] in likely_human_states
    }
    suspected_bots = {
        session["person_key"]
        for session in sessions
        if session["classification_state"] in automated_states
    }
    live_now = {
        session["person_key"]
        for session in sessions
        if session["active_now"] and session["classification_state"] not in automated_states
    }
    returning_visitors = {
        session["person_key"]
        for session in sessions
        if session["returning_visitor"] and session["classification_state"] not in automated_states
    }

    host_request_counter = Counter()
    host_visitors = defaultdict(set)
    host_top_entry = Counter()
    host_top_exit = Counter()
    host_session_seconds = Counter()
    host_session_counts = Counter()
    suspicious_path_counter = Counter()
    top_ip_counter = Counter()
    top_ip_category: dict[str, str] = {}
    top_ip_last_seen: dict[str, str] = {}

    for entry in recent_entries:
        host_request_counter[entry["host"]] += 1
        host_visitors[entry["host"]].add(entry["ip"])

        if entry["category"] == "suspicious":
            suspicious_path_counter[entry["normalized_path"]] += 1

        top_ip_counter[entry["ip"]] += 1
        top_ip_category[entry["ip"]] = entry["category"]
        top_ip_last_seen[entry["ip"]] = entry["timestamp_iso"]

    country_sessions = Counter()
    area_sessions = Counter()
    city_sessions = Counter()

    for session in sessions:
        country_sessions[session["country"]] += 1
        if session["area"]:
            area_sessions[(session["country"], session["area"])] += 1
        if session["city"]:
            city_sessions[(session["country"], session["area"], session["city"])] += 1

        host_top_entry[(session["host"], session["entry_page"])] += 1
        host_top_exit[(session["host"], session["exit_page"])] += 1
        host_session_seconds[session["host"]] += session["total_seconds"]
        host_session_counts[session["host"]] += 1

    hosts: list[dict[str, Any]] = []
    for host, request_count in host_request_counter.most_common(TOP_LIMIT):
        entry_candidates = [
            (path, count)
            for (known_host, path), count in host_top_entry.items()
            if known_host == host
        ]
        exit_candidates = [
            (path, count)
            for (known_host, path), count in host_top_exit.items()
            if known_host == host
        ]

        avg_session_seconds = int(host_session_seconds[host] / host_session_counts[host]) if host_session_counts[host] else 0

        hosts.append(
            {
                "host": host,
                "project_slug": project_slug,
                "requests": request_count,
                "unique_visitors": len(host_visitors[host]),
                "sessions": host_session_counts[host],
                "top_entry_page": max(entry_candidates, key=lambda item: item[1])[0] if entry_candidates else "/",
                "top_exit_page": max(exit_candidates, key=lambda item: item[1])[0] if exit_candidates else "/",
                "avg_session_seconds": avg_session_seconds,
            }
        )

    top_pages = build_path_stats(recent_entries)
    live_feed = _project_live_feed_sessions(sessions, limit=10)
    recent_sessions = _chronological_sessions_desc(sessions, limit=10)
    top_humans = sorted(
        [
            session
            for session in sessions
            if session["classification_state"] in likely_human_states
            and not session.get("known_automation")
        ],
        key=live_session_sort_key,
    )[:8]
    top_suspicious_sessions = sorted(
        [
            session
            for session in sessions
            if session["classification_state"] == "suspicious" or session["route_kind"] == "probe"
        ],
        key=lambda session: (
            session["suspicious_score"],
            1 if session["active_now"] else 0,
            session["ended_at"],
        ),
        reverse=True,
    )[:8]
    graph = _project_graph_payload(
        project_slug=project["slug"],
        range_key="24h",
        bucket_minutes_override=bucket_minutes,
    )
    if include_deep:
        top_pages = build_path_stats(recent_entries)
        country_rows = [
            {
                "country": country,
                "sessions": count,
                "requests": sum(
                    1 for entry in recent_entries if get_geo_details(entry["ip"])["country"] == country
                ),
            }
            for country, count in country_sessions.most_common(TOP_LIMIT)
        ]
        area_rows = [
            {"country": country, "area": area, "sessions": count}
            for (country, area), count in area_sessions.most_common(TOP_LIMIT)
        ]
        city_rows = [
            {"country": country, "area": area, "city": city, "sessions": count}
            for (country, area, city), count in city_sessions.most_common(TOP_LIMIT)
        ]

        suspicious_top_ips: list[dict[str, Any]] = []
        for ip, count in top_ip_counter.most_common(TOP_LIMIT):
            category = top_ip_category.get(ip, "unknown")
            if category not in {"suspicious", "bot"}:
                continue

            suspicious_top_ips.append(
                {
                    "ip": ip,
                    "country": get_geo_details(ip)["country"],
                    "count": count,
                    "category": category,
                    "last_seen": top_ip_last_seen.get(ip),
                }
            )
        hosts_output = hosts
        suspicious_output = {
            "top_paths": [
                {"path": path, "count": count}
                for path, count in suspicious_path_counter.most_common(TOP_LIMIT)
            ],
            "top_ips": suspicious_top_ips,
        }
    else:
        top_pages = []
        country_rows = []
        area_rows = []
        city_rows = []
        hosts_output = []
        suspicious_output = {
            "top_paths": [],
            "top_ips": [],
        }

    avg_session_seconds = int(sum(session["total_seconds"] for session in sessions) / len(sessions)) if sessions else 0

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "bucket_minutes": graph["bucket_minutes"],
        "deep_detail_included": include_deep,
        "project": {
            "slug": project["slug"],
            "name": project["name"],
            "category": project["category"],
            "requests": len(recent_entries),
            "sessions": len(sessions),
            "real_humans": len(real_humans),
            "suspected_bots": len(suspected_bots),
            "live_now": len(live_now),
            "returning_visitors": len(returning_visitors),
            "engaged_sessions": sum(1 for session in sessions if session["engaged_seconds"] > 0),
            "avg_session_seconds": avg_session_seconds,
            "unique_visitors": len(unique_people),
        },
        "graph": graph,
        "live_feed": live_feed,
        "recent_sessions": recent_sessions,
        "top_humans": top_humans,
        "top_suspicious_sessions": top_suspicious_sessions,
        "hosts": hosts_output,
        "top_pages": top_pages,
        "geo": {
            "countries": country_rows,
            "areas": area_rows,
            "cities": city_rows,
        },
        "suspicious": suspicious_output,
    }


def build_project_live_feed(
    *,
    project_slug: str,
    window_hours: int = 24,
    limit: int = 10,
) -> dict[str, Any]:
    project = next((item for item in PROJECTS if item["slug"] == project_slug), None)
    if not project:
        return {
            "ok": False,
            "generated_at": iso_now(),
            "window_hours": window_hours,
            "project_slug": project_slug,
        }

    snapshot = _build_session_snapshot(
        window_hours=window_hours,
        project_slugs={project_slug},
    )
    sessions = snapshot["sessions"]

    live_feed = _project_live_feed_sessions(sessions, limit=limit)

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "project": {
            "slug": project["slug"],
            "name": project["name"],
        },
        "visible_count": len(live_feed),
        "live_feed": live_feed,
    }


def build_visitor_profile(
    *,
    visitor_id: str,
    range_key: str = "all",
) -> dict[str, Any]:
    range_config = _range_config(range_key)
    window_hours = _window_hours_for_range(range_key)
    snapshot = _build_session_snapshot(window_hours=window_hours)
    source_mode = snapshot["source_mode"]
    sessions = snapshot["sessions"]
    visitor_sessions = [
        session for session in sessions if session.get("visitor_profile_id") == visitor_id
    ]

    if not visitor_sessions:
        return {
            "ok": False,
            "generated_at": iso_now(),
            "window_hours": window_hours,
            "range_key": range_key,
            "visitor_id": visitor_id,
        }

    newest_first = _chronological_sessions_desc(visitor_sessions)
    latest = max(visitor_sessions, key=lambda session: session["last_seen_at"])
    oldest = min(visitor_sessions, key=lambda session: session["first_seen_at"])
    recent_entries, _ = collect_recent_entries_with_source(window_hours=window_hours)
    linked_profiles = _build_linked_visitor_profiles(
        all_sessions=sessions,
        visitor_sessions=visitor_sessions,
        visitor_id=visitor_id,
    )
    requested_start = (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
        if window_hours is not None
        else None
    )
    coverage_started_at = datetime.fromisoformat(oldest["first_seen_at"])

    note: str | None = None
    if range_key == "all":
        note = (
            "All-time currently means everything Traffic has stored for this visitor since "
            f"{oldest['first_seen_alberta']}."
        )
    elif requested_start and coverage_started_at > requested_start:
        note = (
            f"Durable storage for this visitor currently begins at {oldest['first_seen_alberta']}, "
            f"so this {range_config['label'].lower()} view starts there."
        )

    if source_mode != "durable_store":
        note = "Durable storage is unavailable, so this visitor profile is currently reading the live log tail."

    project_counts = Counter(session["project_slug"] for session in newest_first)
    project_names = {
        session["project_slug"]: session["project_name"] for session in newest_first
    }
    project_oldest_session = {
        slug: min(
            (
                session
                for session in newest_first
                if session["project_slug"] == slug
            ),
            key=lambda session: session["first_seen_at"],
            default=latest,
        )
        for slug in project_counts
    }
    project_latest_session = {
        slug: max(
            (
                session
                for session in newest_first
                if session["project_slug"] == slug
            ),
            key=lambda session: session["last_seen_at"],
            default=latest,
        )
        for slug in project_counts
    }
    visitor_session_map = {
        session["session_id"]: session for session in visitor_sessions
    }
    enriched_by_session_id: dict[str, dict[str, Any]] = {}

    for session_events in split_session_events(recent_entries):
        session_id = session_id_for_events(session_events)
        matched_session = visitor_session_map.get(session_id)
        if not matched_session:
            continue

        full_page_sequence = page_sequence_for_events(session_events)
        enriched_by_session_id[session_id] = {
            "entry_page": full_page_sequence[0]
            if full_page_sequence
            else matched_session["entry_page"],
            "current_page": full_page_sequence[-1]
            if full_page_sequence
            else matched_session["current_page"],
            "exit_page": full_page_sequence[-1]
            if full_page_sequence
            else matched_session["exit_page"],
            "next_page": full_page_sequence[1]
            if len(full_page_sequence) > 1
            else matched_session["next_page"],
            "page_sequence": full_page_sequence,
            "page_count": len(ordered_unique(full_page_sequence))
            if full_page_sequence
            else matched_session["page_count"],
            "activity_sequence": activity_sequence_for_events(session_events),
        }

    profile_sessions = []
    for session in newest_first[:VISITOR_SESSION_LIMIT]:
        profile_sessions.append(
            {
                **session,
                **enriched_by_session_id.get(session["session_id"], {}),
            }
        )

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "range_key": range_key,
        "range_label": range_config["label"],
        "coverage_mode": source_mode,
        "coverage_started_at": oldest["first_seen_at"],
        "coverage_started_alberta": oldest["first_seen_alberta"],
        "note": note,
        "session_limit": VISITOR_SESSION_LIMIT,
        "visitor": {
            "id": visitor_id,
            "alias": latest["visitor_alias"],
            "person_key": latest["person_key"],
            "ip": latest["ip"],
            "country": latest["country"],
            "country_code": latest["country_code"],
            "area": latest["area"],
            "city": latest["city"],
            "device": latest["device"],
            "os": latest["os"],
            "browser": latest["browser"],
            "first_seen_at": oldest["first_seen_at"],
            "last_seen_at": latest["last_seen_at"],
            "first_seen_alberta": oldest["first_seen_alberta"],
            "last_seen_alberta": latest["last_seen_alberta"],
            "projects_visited": len(project_counts),
            "total_sessions": len(newest_first),
            "active_now": any(session["active_now"] for session in newest_first),
            "linked_profiles_count": len(linked_profiles),
        },
        "projects": [
            {
                "slug": slug,
                "name": project_names[slug],
                "visits": count,
                "first_seen_at": project_oldest_session[slug]["first_seen_at"],
                "first_seen_alberta": project_oldest_session[slug]["first_seen_alberta"],
                "last_seen_at": project_latest_session[slug]["last_seen_at"],
                "last_seen_alberta": project_latest_session[slug]["last_seen_alberta"],
            }
            for slug, count in project_counts.most_common()
        ],
        "linked_profiles": linked_profiles,
        "sessions": profile_sessions,
    }
