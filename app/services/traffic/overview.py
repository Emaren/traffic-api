from __future__ import annotations

import json
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
from app.services.traffic.persistence import _connect, _ensure_schema, load_recent_entries, persistence_enabled
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
    "12h": {"label": "12 Hours", "window_hours": 12},
    "24h": {"label": "24 Hours", "window_hours": 24},
    "7d": {"label": "1 Week", "window_hours": 24 * 7},
    "30d": {"label": "1 Month", "window_hours": 24 * 30},
    "all": {"label": "All Time", "window_hours": None},
}
SESSION_SNAPSHOT_CACHE_TTL_SECONDS = 90.0
SESSION_SNAPSHOT_CACHE_STALE_SECONDS = 600.0
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
HOT_SESSION_SOURCE_MAX_ROWS = 120_000


def _hot_session_source_max_rows(window_hours: int | None) -> int | None:
    # The durable SQLite store can contain millions of rows in 24h during scanner floods.
    # Live dashboards need recent operator intelligence, not a full-table rebuild.
    # Exact long-range totals should come from rollups, not this hot session builder.
    return HOT_SESSION_SOURCE_MAX_ROWS



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
        max_rows=_hot_session_source_max_rows(window_hours),
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
    # Keep boot memory bounded. A 24h warm cache makes the live cockpit fast,
    # while all-time snapshots can be rebuilt lazily only when an operator asks for them.
    _refresh_session_snapshot_async(window_hours=24)


def clear_session_snapshot_cache() -> None:
    with _SESSION_SNAPSHOT_CACHE_LOCK:
        _SESSION_SNAPSHOT_CACHE.clear()
        _SESSION_SNAPSHOT_CACHE_REFRESHING.clear()
        _SESSION_SNAPSHOT_CACHE_EVENTS.clear()


def _project_options() -> list[dict[str, str]]:
    return [{"slug": project["slug"], "name": project["name"]} for project in PROJECTS]


def build_overview(range_key: str = "12h") -> dict[str, Any]:
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



SECURITY_PREVIEW_CLUSTER_MIN_SESSIONS = 3


LIVE_SESSION_RESPONSE_KEYS = {
    "session_id",
    "visitor_profile_id",
    "visitor_alias",
    "project_slug",
    "project_name",
    "project_category",
    "host",
    "ip",
    "started_at",
    "ended_at",
    "first_seen_at",
    "last_seen_at",
    "last_page_request_at",
    "first_seen_alberta",
    "last_seen_alberta",
    "country",
    "country_code",
    "area",
    "city",
    "geo_resolved",
    "device",
    "os",
    "browser",
    "known_automation",
    "automation_family",
    "known_visitor_label",
    "known_visitor_detail",
    "known_visitor_kind",
    "known_visitor_confirmed",
    "route_bundle_spam",
    "is_burst_cluster",
    "burst_member_count",
    "burst_ip_count",
    "burst_path_count",
    "burst_window_seconds",
    "burst_ip_prefix",
    "referrer",
    "source",
    "entry_page",
    "current_page",
    "exit_page",
    "next_page",
    "page_sequence",
    "page_count",
    "event_count",
    "total_seconds",
    "engaged_seconds",
    "active_now",
    "suspicious_score",
    "primary_category",
    "route_kind",
    "classification_state",
    "verdict_label",
    "classification_summary",
    "classification_reasons",
    "classification_reason_labels",
    "human_confirmed",
    "visits_in_window",
    "project_visits_in_window",
    "total_project_visits",
    "times_returned_in_project",
    "projects_visited_in_window",
    "returning_visitor",
    "live_priority",
}

LIVE_SESSION_ARRAY_LIMITS = {
    "page_sequence": 6,
    "classification_reasons": 5,
    "classification_reason_labels": 5,
}


def _compact_live_session(session: dict[str, Any]) -> dict[str, Any]:
    compact = {
        key: session.get(key)
        for key in LIVE_SESSION_RESPONSE_KEYS
        if key in session
    }

    for key, limit in LIVE_SESSION_ARRAY_LIMITS.items():
        value = compact.get(key)
        if isinstance(value, list):
            compact[key] = value[:limit]

    if "page_sequence" not in compact or compact["page_sequence"] is None:
        compact["page_sequence"] = []

    summary = compact.get("classification_summary")
    if isinstance(summary, str) and len(summary) > 420:
        compact["classification_summary"] = summary[:417].rstrip() + "..."

    return compact



PAGE_BURST_MIN_SESSIONS = 4
PAGE_BURST_MAX_WINDOW_SECONDS = 20 * 60


def _parse_session_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _ipv4_24_prefix(ip: Any) -> str:
    value = str(ip or "").strip()
    parts = value.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return ".".join(parts[:3]) + ".*"
    if ":" in value:
        # Rough IPv6 grouping. Good enough for burst display containment.
        return ":".join(value.split(":")[:4]) + "::/64"
    return value or "unknown"


def _page_burst_bucket(session: dict[str, Any], minutes: int = 20) -> str:
    value = (
        _parse_session_time(session.get("started_at"))
        or _parse_session_time(session.get("first_seen_at"))
        or _parse_session_time(session.get("ended_at"))
        or _parse_session_time(session.get("last_seen_at"))
    )
    if not value:
        return "unknown"
    minute = (value.minute // minutes) * minutes
    bucket = value.replace(minute=minute, second=0, microsecond=0)
    return bucket.isoformat()


def _page_burst_paths(session: dict[str, Any]) -> list[str]:
    values = [
        *(session.get("page_sequence") or []),
        session.get("entry_page") or "",
        session.get("current_page") or "",
        session.get("exit_page") or "",
        session.get("next_page") or "",
    ]
    seen: set[str] = set()
    paths: list[str] = []
    for value in values:
        route = str(value or "").strip()
        if route and route not in seen:
            seen.add(route)
            paths.append(route)
    return paths


def _is_page_burst_candidate(session: dict[str, Any]) -> bool:
    # Never collapse operator-confirmed people. False negatives are acceptable;
    # hiding a real human is not.
    if session.get("classification_state") == "human_confirmed":
        return False
    if session.get("known_visitor_confirmed"):
        return False
    if session.get("human_confirmed"):
        return False

    # Active or returning people deserve visibility until proven otherwise.
    if session.get("active_now"):
        return False
    if session.get("returning_visitor") or int(session.get("total_project_visits") or 0) > 1:
        return False

    if session.get("known_automation"):
        return False
    if session.get("is_burst_cluster"):
        return False
    if session.get("route_kind") != "page":
        return False
    if not session.get("project_slug"):
        return False

    # Long, engaged, multi-page sessions are more likely worth showing individually.
    page_count = int(session.get("page_count") or 0)
    total_seconds = int(session.get("total_seconds") or 0)
    if page_count >= 3 and total_seconds >= 90:
        return False

    return True


def _collapse_page_burst_sessions(
    sessions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    groups: dict[tuple[str, str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for session in sessions:
        if not _is_page_burst_candidate(session):
            continue

        key = (
            str(session.get("project_slug") or ""),
            str(session.get("country_code") or session.get("country") or ""),
            str(session.get("area") or ""),
            str(session.get("city") or ""),
            _ipv4_24_prefix(session.get("ip")),
            _page_burst_bucket(session),
        )
        groups[key].append(session)

    clusters: list[dict[str, Any]] = []
    suppressed_ids: set[str] = set()

    for key, group in groups.items():
        if len(group) < PAGE_BURST_MIN_SESSIONS:
            continue

        ordered = sorted(group, key=lambda item: item.get("ended_at") or item.get("last_seen_at") or "")
        first = ordered[0]
        latest = ordered[-1]

        first_at = _parse_session_time(first.get("started_at") or first.get("first_seen_at") or first.get("ended_at"))
        latest_at = _parse_session_time(latest.get("ended_at") or latest.get("last_seen_at") or latest.get("started_at"))
        if first_at and latest_at:
            span_seconds = abs(int((latest_at - first_at).total_seconds()))
            if span_seconds > PAGE_BURST_MAX_WINDOW_SECONDS:
                continue
        else:
            span_seconds = 0

        ips = sorted({str(item.get("ip") or "") for item in group if item.get("ip")})
        paths = [path for item in group for path in _page_burst_paths(item)]
        path_counts = Counter(paths)
        top_paths = [path for path, _count in path_counts.most_common(8)]

        # Require either IP fanout or route fanout. This avoids crushing ordinary visitors.
        if len(ips) < 4 and len(top_paths) < 3:
            continue

        for item in group:
            sid = str(item.get("session_id") or "")
            if sid:
                suppressed_ids.add(sid)

        primary_path = top_paths[0] if top_paths else latest.get("entry_page") or latest.get("current_page") or "(unknown)"
        project_slug, country, area, city, prefix, bucket = key

        cluster = dict(latest)
        cluster.update(
            {
                "session_id": "page-burst-cluster|"
                + "|".join(
                    str(part).replace("|", "-")
                    for part in (project_slug, country, area, city, prefix, bucket)
                ),
                "visitor_alias": f"{city or area or country or 'Unknown'} page burst",
                "ip": f"{len(ips)} IPs",
                "entry_page": primary_path,
                "current_page": primary_path,
                "exit_page": primary_path,
                "next_page": "",
                "page_sequence": top_paths,
                "classification_state": "browser_script",
                "verdict_label": "Page Burst",
                "human_confidence": 15,
                "suspicious_score": max(55, max(int(item.get("suspicious_score") or 0) for item in group)),
                "classification_reasons": ["same_city_ip_prefix_route_burst", "operator_safe_collapse"],
                "classification_reason_labels": [
                    "Same-city page burst",
                    f"{len(group)} sessions",
                    f"{len(ips)} IPs",
                    f"{len(top_paths)} routes",
                ],
                "classification_summary": (
                    f"Traffic collapsed {len(group)} short one-off page sessions from "
                    f"{len(ips)} IPs in {city or area or country or 'one area'} into one burst. "
                    "Confirmed humans, known identities, active visitors, and returning visitors are protected."
                ),
                "known_automation": False,
                "is_burst_cluster": True,
                "burst_member_count": len(group),
                "burst_ip_count": len(ips),
                "burst_path_count": len(top_paths),
                "burst_window_seconds": span_seconds,
                "burst_ip_prefix": prefix,
                "burst_paths": top_paths,
                "burst_sample_ips": ips[:8],
            }
        )
        clusters.append(cluster)

    return sorted(clusters, key=live_session_sort_key), suppressed_ids




def _session_path_values(session: dict[str, Any]) -> list[str]:
    values = [
        *(session.get("page_sequence") or []),
        session.get("entry_page") or "",
        session.get("current_page") or "",
        session.get("exit_page") or "",
        *(session.get("burst_paths") or []),
    ]
    seen: set[str] = set()
    paths: list[str] = []
    for value in values:
        path = str(value or "").strip()
        if path and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _is_chain_signal_session(session: dict[str, Any]) -> bool:
    joined = " ".join(path.lower() for path in _session_path_values(session))
    return (
        "/rest-mainnet" in joined
        or "/rpc-mainnet" in joined
        or "/cosmos/" in joined
        or "/tendermint/" in joined
        or "/blocks/latest" in joined
        or "/node_info" in joined
        or "/tx_search" in joined
        or "/txs/" in joined
        or "valoper" in joined
        or "validators" in joined
    )


def _is_user_app_activity_session(session: dict[str, Any]) -> bool:
    joined = " ".join(path.lower() for path in _session_path_values(session))

    if _is_chain_signal_session(session):
        return False
    if session.get("known_automation"):
        return False
    if session.get("primary_category") == "security":
        return False
    if session.get("classification_state") in {"bot", "suspicious"}:
        return False

    has_staking_page = "/staking" in joined
    has_staking_api = "/api/staking/" in joined
    has_strong_staking_action = (
        "/api/staking/stake" in joined
        or "/api/staking/me" in joined
        or "/api/staking/config" in joined
        or "/api/staking/activity" in joined
    )

    # AoE2WAR logged-in/browser app activity often lands as API-only sessions.
    # Treat user pings, contact-emaren, requests, and live-games polling as app
    # activity when they are not known automation/security/chain sessions.
    has_aoe2_identity_api = (
        "/api/user/ping" in joined
        or "/api/contact-emaren" in joined
    )
    has_aoe2_app_api = (
        "/api/live-games" in joined
        or "/api/requests" in joined
        or "/api/contact-emaren" in joined
        or "/api/user/ping" in joined
    )
    aoe2_app_api_count = sum(
        1
        for marker in (
            "/api/live-games",
            "/api/requests",
            "/api/contact-emaren",
            "/api/user/ping",
        )
        if marker in joined
    )

    return (
        has_staking_page
        or has_staking_api
        or has_strong_staking_action
        or has_aoe2_identity_api
        or aoe2_app_api_count >= 2
        or (has_aoe2_app_api and session.get("active_now"))
    )


def _promote_chain_signal(session: dict[str, Any]) -> dict[str, Any]:
    promoted = dict(session)
    promoted["verdict_label"] = "Chain Signal"
    promoted["classification_reason_labels"] = [
        "Chain infrastructure signal",
        *(promoted.get("classification_reason_labels") or []),
    ][:8]
    promoted["classification_summary"] = (
        "Traffic separated this as chain infrastructure/API activity. "
        "Treat as validator, explorer, wallet, indexer, or node-client signal — not audience."
    )
    return promoted


def _promote_user_app_activity(session: dict[str, Any]) -> dict[str, Any]:
    promoted = dict(session)
    promoted["classification_state"] = (
        "human_confirmed"
        if session.get("human_confirmed") or session.get("known_visitor_confirmed")
        else "likely_human"
    )
    promoted["verdict_label"] = "App Activity"
    promoted["human_confidence"] = max(70, int(session.get("human_confidence") or 0))
    promoted["suspicious_score"] = min(35, int(session.get("suspicious_score") or 0))

    joined = " ".join(path.lower() for path in _session_path_values(session))
    activity_label = (
        "Staking app activity"
        if "/staking" in joined or "/api/staking/" in joined
        else "AoE2 app activity"
    )
    activity_reason = (
        "staking_app_activity"
        if activity_label == "Staking app activity"
        else "aoe2_app_activity"
    )

    labels = list(promoted.get("classification_reason_labels") or [])
    labels = [label for label in labels if label not in {"Staking app activity", "AoE2 app activity"}]
    labels.insert(0, activity_label)
    promoted["classification_reason_labels"] = labels[:8]

    reasons = list(promoted.get("classification_reasons") or [])
    reasons = [reason for reason in reasons if reason not in {"staking_app_activity", "aoe2_app_activity"}]
    reasons.insert(0, activity_reason)
    promoted["classification_reasons"] = reasons[:8]

    promoted["classification_summary"] = (
        "Traffic promoted this session because it touched user-facing app routes "
        "instead of raw chain infrastructure. Treat as app/user activity, not chain polling."
    )
    return promoted


def _security_preview_paths(session: dict[str, Any]) -> list[str]:
    values = [
        *(session.get("page_sequence") or []),
        session.get("entry_page") or "",
        session.get("current_page") or "",
        session.get("exit_page") or "",
        *(session.get("burst_paths") or []),
    ]
    seen: set[str] = set()
    paths: list[str] = []
    for value in values:
        path = str(value or "").strip()
        if path and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _security_preview_family(session: dict[str, Any]) -> str:
    joined = " ".join(path.lower() for path in _security_preview_paths(session))

    if "wp-admin" in joined or "wp-login" in joined or "wp-config" in joined or "xmlrpc" in joined:
        return "WordPress probe"
    if "phpinfo" in joined or "pinfo.php" in joined or "php_info" in joined or "server_info" in joined:
        return "PHP info probe"
    if ".env" in joined or "credentials" in joined or "serviceaccount" in joined or "service-account" in joined:
        return "secret-file probe"
    if ".git" in joined:
        return "Git metadata probe"
    if (
        "web.config" in joined
        or "database.php" in joined
        or "settings.php" in joined
        or "functions.php" in joined
        or "parameters.yml" in joined
        or "application.yml" in joined
        or "config.php" in joined
        or "/index.php" in joined
        or "/test.php" in joined
        or "/db.php" in joined
        or "docker-compose" in joined
    ):
        return "config-file probe"

    return "probe swarm"


def _collapse_security_preview(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    singles: list[dict[str, Any]] = []

    for session in sessions:
        if session.get("route_kind") != "probe" and session.get("classification_state") != "suspicious":
            singles.append(session)
            continue

        family = _security_preview_family(session)
        key = (
            session.get("country_code") or session.get("country") or "",
            session.get("area") or "",
            session.get("city") or "",
            family,
        )
        groups[key].append(session)

    collapsed: list[dict[str, Any]] = []

    for (_country, _area, _city, family), group in groups.items():
        ips = sorted({str(item.get("ip") or "") for item in group if item.get("ip")})
        hosts = sorted({str(item.get("host") or "") for item in group if item.get("host")})

        if len(group) < SECURITY_PREVIEW_CLUSTER_MIN_SESSIONS and len(ips) < 3:
            singles.extend(group)
            continue

        ordered = sorted(group, key=lambda item: item.get("ended_at") or "")
        first = ordered[0]
        latest = ordered[-1]

        path_counts = Counter(path for item in group for path in _security_preview_paths(item))
        top_paths = [path for path, _count in path_counts.most_common(12)]
        primary_path = top_paths[0] if top_paths else latest.get("entry_page") or latest.get("current_page") or "(unknown)"

        cluster = dict(latest)
        cluster.update(
            {
                "session_id": "security-preview-cluster|"
                + "|".join(
                    str(part).replace("|", "-")
                    for part in (
                        latest.get("country_code") or latest.get("country") or "unknown",
                        latest.get("area") or "unknown",
                        latest.get("city") or "unknown",
                        family,
                    )
                ),
                "visitor_alias": f"{latest.get('city') or latest.get('country') or 'Unknown'} {family}",
                "entry_page": primary_path,
                "current_page": primary_path,
                "exit_page": primary_path,
                "page_sequence": top_paths,
                "route_kind": "probe",
                "classification_state": "suspicious",
                "verdict_label": "Suspicious",
                "human_confidence": 0,
                "suspicious_score": max(90, max(int(item.get("suspicious_score") or 0) for item in group)),
                "classification_reasons": ["probe_route", "security_probe_swarm"],
                "classification_reason_labels": [
                    "Security probe swarm",
                    f"{len(group)} sessions",
                    f"{len(ips)} IPs",
                    f"{len(hosts)} hosts",
                ],
                "classification_summary": (
                    f"Traffic collapsed {len(group)} suspicious {family.lower()} sessions "
                    f"from {len(ips)} IPs across {len(hosts)} hosts. "
                    "Treat this as scanner traffic, not separate people."
                ),
                "is_burst_cluster": True,
                "burst_member_count": len(group),
                "burst_ip_count": len(ips),
                "burst_path_count": len(top_paths),
                "burst_paths": top_paths,
                "burst_sample_ips": ips[:12],
            }
        )
        collapsed.append(cluster)

    return sorted(singles + collapsed, key=live_session_sort_key)[:len(sessions)]


def build_live_visitors(
    *,
    limit: int = LIVE_TILE_LIMIT,
    history_limit: int = VISITS_HISTORY_LIMIT,
    window_hours: int = 24,
) -> dict[str, Any]:
    # Hard cap live dashboard payloads. The browser may ask for a huge feed while
    # reconnecting, but the API must stay small enough to keep nginx and uvicorn alive.
    limit = max(1, min(int(limit or LIVE_TILE_LIMIT), 24))
    history_limit = 0

    snapshot = _build_session_snapshot(window_hours=window_hours)
    sessions = snapshot["sessions"]

    page_burst_clusters, page_burst_member_ids = _collapse_page_burst_sessions(sessions)

    page_burst_neighborhood_keys = {
        (
            str(cluster.get("project_slug") or ""),
            str(cluster.get("country_code") or cluster.get("country") or ""),
            str(cluster.get("area") or ""),
            str(cluster.get("city") or ""),
            str(cluster.get("burst_ip_prefix") or ""),
        )
        for cluster in page_burst_clusters
    }

    def protected_from_page_burst_quarantine(session: dict[str, Any]) -> bool:
        # Tony rule: do not hide real humans. Confirmed/known/active/returning/engaged
        # sessions stay visible even if they share a noisy neighborhood.
        if session.get("classification_state") == "human_confirmed":
            return True
        if session.get("known_visitor_confirmed") or session.get("human_confirmed"):
            return True
        if session.get("active_now"):
            return True
        if session.get("returning_visitor") or int(session.get("total_project_visits") or 0) > 1:
            return True

        engaged_seconds = int(session.get("engaged_seconds") or 0)

        # In a burst neighborhood, route count and total_seconds can be fake depth
        # caused by scripted URL fanout. Only real browser engagement gets protected.
        return engaged_seconds >= 45

    def in_page_burst_neighborhood(session: dict[str, Any]) -> bool:
        if protected_from_page_burst_quarantine(session):
            return False
        if session.get("route_kind") != "page":
            return False

        key = (
            str(session.get("project_slug") or ""),
            str(session.get("country_code") or session.get("country") or ""),
            str(session.get("area") or ""),
            str(session.get("city") or ""),
            _ipv4_24_prefix(session.get("ip")),
        )
        return key in page_burst_neighborhood_keys

    def not_page_burst_member(session: dict[str, Any]) -> bool:
        return (
            session.get("session_id") not in page_burst_member_ids
            and not in_page_burst_neighborhood(session)
        )

    # Keep enough non-human/uncertain page-shaped sessions visible for operator review
    # without shipping a megabyte-scale JSON payload on every live refresh.
    auxiliary_limit = 8

    tower_candidates = [
        session
        for session in sessions
        if session["classification_state"] in HUMAN_VISIBLE_STATES
        and session["route_kind"] == "page"
        and session.get("session_id") not in page_burst_member_ids
        and not _is_chain_signal_session(session)
    ]

    app_activity_candidates = [
        _promote_user_app_activity(session)
        for session in sessions
        if _is_user_app_activity_session(session)
        and session.get("session_id") not in page_burst_member_ids
    ]

    existing_tower_ids = {session.get("session_id") for session in tower_candidates}
    tower_candidates.extend(
        session
        for session in app_activity_candidates
        if session.get("session_id") not in existing_tower_ids
    )
    browser_script_candidates = [
        *page_burst_clusters,
        *[
            session
            for session in sessions
            if session["classification_state"] in {"browser_script", "script_burst"}
            and session.get("session_id") not in page_burst_member_ids
            and (session["page_count"] > 0 or session["route_kind"] == "page")
        ],
    ]
    automation_candidates = [
        session
        for session in sessions
        if session.get("known_automation")
        and not _is_chain_signal_session(session)
        and not _is_user_app_activity_session(session)
        and (session["page_count"] > 0 or session["route_kind"] == "page")
    ]
    security_candidates = [
        session
        for session in sessions
        if session["classification_state"] == "suspicious"
        and not _is_chain_signal_session(session)
        and not _is_user_app_activity_session(session)
        and (session["page_count"] > 0 or session["route_kind"] == "page")
    ]

    chain_signal_candidates = [
        _promote_chain_signal(session)
        for session in sessions
        if _is_chain_signal_session(session)
        and session.get("session_id") not in page_burst_member_ids
    ]

    tower_candidates = [session for session in tower_candidates if not_page_burst_member(session)]
    browser_script_candidates = [
        session
        for session in browser_script_candidates
        if not _is_chain_signal_session(session)
        and not _is_user_app_activity_session(session)
        and not_page_burst_member(session)
    ]
    automation_candidates = [session for session in automation_candidates if not_page_burst_member(session)]
    security_candidates = [session for session in security_candidates if not_page_burst_member(session)]
    chain_signal_candidates = [session for session in chain_signal_candidates if not_page_burst_member(session)]

    tower = sorted(tower_candidates, key=live_session_sort_key)[:limit]
    browser_script_preview = sorted(browser_script_candidates, key=live_session_sort_key)[:auxiliary_limit]
    automation_preview = sorted(automation_candidates, key=live_session_sort_key)[:auxiliary_limit]
    security_preview = _collapse_security_preview(sorted(security_candidates, key=live_session_sort_key)[:auxiliary_limit])
    chain_signal_preview = sorted(chain_signal_candidates, key=live_session_sort_key)[:auxiliary_limit]
    app_activity_preview = sorted(app_activity_candidates, key=live_session_sort_key)[:auxiliary_limit]

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
            and session.get("session_id") not in page_burst_member_ids
            and not (
                session.get("primary_category") == "security"
                or int(session.get("suspicious_score") or 0) >= 70
            )
        ],
        key=lambda item: item.get("ended_at") or "",
        reverse=True,
    )[:auxiliary_limit]

    recent_page_review_candidates = [
        session
        for session in recent_page_review_candidates
        if not session.get("known_automation")
        and session.get("classification_state") in HUMAN_VISIBLE_STATES
        and not _is_chain_signal_session(session)
        and not _is_user_app_activity_session(session)
        and session.get("classification_state") not in {"bot", "browser_script", "script_burst", "suspicious"}
    ]

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
        "stream_items": [_compact_live_session(session) for session in stream_items if not_page_burst_member(session)],
        "browser_script_count": len(browser_script_candidates),
        "browser_script_preview": [_compact_live_session(session) for session in browser_script_preview],
        "automation_count": len(automation_candidates),
        "automation_preview": [_compact_live_session(session) for session in automation_preview],
        "security_count": len(security_candidates),
        "security_preview": [_compact_live_session(session) for session in security_preview],
        "chain_signal_count": len(chain_signal_candidates),
        "chain_signal_preview": [_compact_live_session(session) for session in chain_signal_preview],
        "app_activity_count": len(app_activity_candidates),
        "app_activity_preview": [_compact_live_session(session) for session in app_activity_preview],
        "review_count": len(browser_script_candidates) + len(automation_candidates) + len(security_candidates),
        "review_preview": [],
        "recent_page_review_count": len(recent_page_review_candidates),
        "recent_page_review": [_compact_live_session(session) for session in recent_page_review_candidates if not_page_burst_member(session)],
        "available_projects": _project_options(),
        "project_counts": project_counts,
        "top_25": [],
        "history_preview": [],
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


def _load_session_archive_history(
    *,
    limit: int,
    offset: int,
    range_key: str,
    range_config: dict[str, Any],
    selected_project_slugs: set[str] | None,
) -> dict[str, Any] | None:
    if range_key != "all":
        return None
    if selected_project_slugs is None:
        return None
    if not selected_project_slugs:
        return None
    if not persistence_enabled():
        return None

    placeholders = ",".join("?" for _ in selected_project_slugs)
    project_params = tuple(sorted(selected_project_slugs))

    base_where = f"""
        project_slug IN ({placeholders})
        AND classification_state IN ('human_confirmed', 'likely_human')
        AND route_kind = 'page'
        AND suspicious_score < 35
        AND known_automation = 0
    """

    try:
        with _connect() as connection:
            _ensure_schema(connection)

            table_exists = connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'traffic_session_archive'
                """
            ).fetchone()
            if not table_exists:
                return None

            total_row = connection.execute(
                f"SELECT COUNT(*) AS total FROM traffic_session_archive WHERE {base_where}",
                project_params,
            ).fetchone()
            total = int(total_row["total"] if total_row else 0)
            if total <= 0:
                return None

            oldest_row = connection.execute(
                f"""
                SELECT payload_json
                FROM traffic_session_archive
                WHERE {base_where}
                ORDER BY first_seen_at ASC
                LIMIT 1
                """,
                project_params,
            ).fetchone()

            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM traffic_session_archive
                WHERE {base_where}
                ORDER BY ended_at DESC
                LIMIT ? OFFSET ?
                """,
                project_params + (limit, offset),
            ).fetchall()
    except Exception:
        return None

    items: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            continue
        if isinstance(payload, dict):
            items.append(_compact_live_session(payload))

    oldest_payload: dict[str, Any] | None = None
    if oldest_row:
        try:
            loaded = json.loads(oldest_row["payload_json"])
            if isinstance(loaded, dict):
                oldest_payload = loaded
        except Exception:
            oldest_payload = None

    note = "All-time is reading Traffic's persisted session archive for these matching sessions."
    if oldest_payload:
        note = (
            "All-time is reading Traffic's persisted session archive for these matching sessions since "
            f"{oldest_payload.get('first_seen_alberta')}."
        )

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": None,
        "range_key": range_key,
        "range_label": range_config["label"],
        "coverage_mode": "session_archive",
        "coverage_started_at": oldest_payload.get("first_seen_at") if oldest_payload else None,
        "coverage_started_alberta": oldest_payload.get("first_seen_alberta") if oldest_payload else None,
        "note": note,
        "offset": offset,
        "limit": limit,
        "total": total,
        "available_projects": _project_options(),
        "items": items,
    }


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

    if classification == "human_visible":
        archived_history = _load_session_archive_history(
            limit=limit,
            offset=offset,
            range_key=range_key,
            range_config=range_config,
            selected_project_slugs=selected_project_slugs,
        )
        if archived_history is not None:
            return archived_history

    snapshot = _build_session_snapshot(
        window_hours=window_hours,
        project_slugs=selected_project_slugs,
    )
    source_mode = snapshot["source_mode"]
    sessions = snapshot["sessions"]

    filtered = sessions
    def _safe_human_history_session(session):
        if session["classification_state"] not in {"human_confirmed", "likely_human"}:
            return False
        if session.get("route_kind") != "page":
            return False
        if session.get("suspicious_score", 0) >= 35:
            return False

        pages = [
            session.get("entry_page") or "",
            session.get("exit_page") or "",
            session.get("current_page") or "",
        ]
        pages.extend(session.get("page_sequence") or [])
        haystack = " ".join(str(page).lower() for page in pages)

        probe_fragments = (
            "/wp-",
            "wp-json",
            "wp-admin",
            "gravitysmtp",
            "debug",
            "console",
            "server.log",
            ".env",
            ".git",
            ".svn",
            "docker-compose",
            ".drone",
            ".buildkite",
            "kubernetes.yml",
            "database.ini",
            "composer.",
            "phpinfo",
            "phpunit",
            "login.action",
            "/nodesync",
            "/exec",
            "/shell",
            "/cgi-bin",
            ".yarnrc",
        )

        return not any(fragment in haystack for fragment in probe_fragments)

    if classification == "human_visible":
        filtered = [session for session in filtered if _safe_human_history_session(session)]
    elif classification == "known_automation":
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


def _is_human_signal_session(session: dict[str, Any]) -> bool:
    state = session.get("classification_state")

    if session.get("known_automation"):
        return False
    if session.get("is_burst_cluster"):
        return False
    if session.get("route_kind") != "page":
        return False
    if state in AUTOMATED_OR_SCRIPT_STATES or state in {"bot", "browser_script", "script_burst", "suspicious"}:
        return False

    if state == "human_confirmed" or session.get("human_confirmed"):
        return True
    if session.get("known_visitor_confirmed"):
        return True
    if session.get("active_now"):
        return True
    if session.get("returning_visitor") or int(session.get("total_project_visits") or 0) > 1:
        return True

    engaged_seconds = int(session.get("engaged_seconds") or 0)
    total_seconds = int(session.get("total_seconds") or 0)
    page_count = int(session.get("page_count") or 0)

    if state == "likely_human":
        return engaged_seconds > 0 or page_count <= 6 or total_seconds >= 30

    if state == "candidate":
        return engaged_seconds >= 10 or (page_count <= 4 and total_seconds >= 20)

    return False


def _human_signal_graph_sessions(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    page_burst_clusters, page_burst_member_ids = _collapse_page_burst_sessions(sessions)

    neighborhood_keys = {
        (
            str(cluster.get("project_slug") or ""),
            str(cluster.get("country_code") or cluster.get("country") or ""),
            str(cluster.get("area") or ""),
            str(cluster.get("city") or ""),
            str(cluster.get("burst_ip_prefix") or ""),
        )
        for cluster in page_burst_clusters
    }

    output: list[dict[str, Any]] = []

    for session in sessions:
        if not _is_human_signal_session(session):
            continue

        if session.get("session_id") in page_burst_member_ids:
            continue

        protected = (
            session.get("classification_state") == "human_confirmed"
            or session.get("known_visitor_confirmed")
            or session.get("human_confirmed")
            or session.get("active_now")
            or session.get("returning_visitor")
            or int(session.get("total_project_visits") or 0) > 1
            or int(session.get("engaged_seconds") or 0) >= 45
        )

        neighborhood_key = (
            str(session.get("project_slug") or ""),
            str(session.get("country_code") or session.get("country") or ""),
            str(session.get("area") or ""),
            str(session.get("city") or ""),
            _ipv4_24_prefix(session.get("ip")),
        )

        if not protected and neighborhood_key in neighborhood_keys:
            continue

        output.append(session)

    return output



def _range_config(range_key: str) -> dict[str, Any]:
    return PROJECT_GRAPH_RANGES.get(range_key, PROJECT_GRAPH_RANGES["12h"])


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



def _project_graph_all_time_rollup_payload(*, project_slug: str) -> dict[str, Any]:
    project = next((item for item in PROJECTS if item["slug"] == project_slug), None)
    if not project:
        return {
            "label": "All-time human-shaped arrivals",
            "series_kind": "all_time_human_shaped_arrivals",
            "range_key": "all",
            "range_label": "All Time",
            "window_hours": None,
            "bucket_minutes": 1440,
            "coverage_mode": "durable_store",
            "coverage_started_at": None,
            "coverage_started_alberta": None,
            "note": "Unknown project.",
            "points": [],
        }

    hosts = [str(host) for host in project.get("hosts", []) if host]
    if not hosts:
        return {
            "label": "All-time human-shaped arrivals",
            "series_kind": "all_time_human_shaped_arrivals",
            "range_key": "all",
            "range_label": "All Time",
            "window_hours": None,
            "bucket_minutes": 1440,
            "coverage_mode": "durable_store",
            "coverage_started_at": None,
            "coverage_started_alberta": None,
            "note": "This project has no configured hosts.",
            "points": [],
        }

    def empty_payload(note: str) -> dict[str, Any]:
        return {
            "label": "All-time human-shaped arrivals",
            "series_kind": "all_time_human_shaped_arrivals",
            "range_key": "all",
            "range_label": "All Time",
            "window_hours": None,
            "bucket_minutes": 1440,
            "coverage_mode": "durable_store",
            "coverage_started_at": None,
            "coverage_started_alberta": None,
            "note": note,
            "points": [],
        }

    placeholders = ",".join("?" for _ in hosts)
    now = iso_now()

    # Materialize daily rollups. This is intentionally broader and faster than the full
    # live classifier: distinct IPs hitting browser-shaped, human-facing page routes per day.
    # The all-time endpoint then reads the compact rollup table instead of scanning raw logs.
    rebuild_query = f"""
        INSERT OR REPLACE INTO traffic_project_daily_rollups (
            project_slug,
            bucket_day,
            visitors,
            events,
            updated_at
        )
        SELECT
            ? AS project_slug,
            substr(timestamp, 1, 10) AS bucket_day,
            COUNT(DISTINCT ip) AS visitors,
            COUNT(*) AS events,
            ? AS updated_at
        FROM traffic_entries
        WHERE host IN ({placeholders})
          AND status BETWEEN 200 AND 399
          AND method = 'GET'
          AND ua LIKE '%Mozilla%'
          AND normalized_path NOT LIKE '/api/%'
          AND normalized_path NOT LIKE '/rpc-%'
          AND normalized_path NOT LIKE '/rest-%'
          AND normalized_path NOT LIKE '/_next/%'
          AND normalized_path NOT LIKE '/wp-%'
          AND normalized_path NOT LIKE '/wp/%'
          AND normalized_path NOT IN (
            '/robots.txt',
            '/favicon.ico',
            '/manifest.webmanifest',
            '/admin-manifest.webmanifest'
          )
        GROUP BY substr(timestamp, 1, 10)
    """

    earliest_query = f"""
        SELECT MIN(timestamp) AS earliest_seen
        FROM traffic_entries
        WHERE host IN ({placeholders})
    """

    try:
        with _connect() as connection:
            _ensure_schema(connection)

            existing_count = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM traffic_project_daily_rollups
                WHERE project_slug = ?
                """,
                (project_slug,),
            ).fetchone()["count"]

            if not existing_count:
                return empty_payload(
                    "All-time strict human-signal rollup has not been materialized yet. "
                    "Run scripts/rebuild_project_daily_rollups.py to rebuild historical graph data."
                )

            earliest_row = connection.execute(earliest_query, hosts).fetchone()
            earliest_seen = earliest_row["earliest_seen"] if earliest_row else None

            rows = connection.execute(
                """
                SELECT bucket_day, visitors, events
                FROM traffic_project_daily_rollups
                WHERE project_slug = ?
                ORDER BY bucket_day ASC
                """,
                (project_slug,),
            ).fetchall()
    except Exception as exc:
        return empty_payload(f"All-time rollup failed: {exc}")

    earliest_dt: datetime | None = None
    if earliest_seen:
        try:
            earliest_dt = datetime.fromisoformat(str(earliest_seen).replace("Z", "+00:00"))
            if earliest_dt.tzinfo is None:
                earliest_dt = earliest_dt.replace(tzinfo=timezone.utc)
            earliest_dt = earliest_dt.astimezone(timezone.utc)
        except Exception:
            earliest_dt = None

    points = []
    for row in rows:
        day = str(row["bucket_day"])
        try:
            bucket = datetime.fromisoformat(f"{day}T00:00:00+00:00")
        except Exception:
            continue

        points.append(
            {
                "bucket_start": bucket.isoformat(),
                "label": bucket.astimezone(ALBERTA_ZONE).strftime("%b %d"),
                "visitors": int(row["visitors"] or 0),
                "events": int(row["events"] or 0),
            }
        )

    note = (
        "All Time uses a materialized strict historical human-signal rollup. "
        "It suppresses proxy fanout, route sweeps, chain RPC, REST, API, assets, WordPress probes, "
        "and obvious non-page noise so the graph does not inflate bot swarms as audience."
    )

    return {
        "label": "All-time human-shaped arrivals",
        "series_kind": "all_time_human_shaped_arrivals",
        "range_key": "all",
        "range_label": "All Time",
        "window_hours": None,
        "bucket_minutes": 1440,
        "coverage_mode": "durable_store",
        "coverage_started_at": earliest_dt.isoformat() if earliest_dt else None,
        "coverage_started_alberta": (
            _format_alberta_timestamp(earliest_dt) if earliest_dt else None
        ),
        "note": note,
        "points": points,
    }


def _project_graph_payload(
    *,
    project_slug: str,
    range_key: str = "12h",
    bucket_minutes_override: int | None = None,
) -> dict[str, Any]:
    if range_key == "all":
        return _project_graph_all_time_rollup_payload(project_slug=project_slug)

    range_config = PROJECT_GRAPH_RANGES.get(range_key, PROJECT_GRAPH_RANGES["12h"])
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

    # Keep recent project graphs on a fixed visual canvas. Without this,
    # the 24h graph shrinks when durable coverage starts inside the range.
    if range_key in {"12h", "24h"} and window_hours:
        expected_bucket_count = int((window_hours * 60) / bucket_minutes)
        first_bucket = last_bucket - timedelta(
            minutes=bucket_minutes * max(expected_bucket_count - 1, 0)
        )

    bucket_list: list[datetime] = []
    cursor = first_bucket
    while cursor <= last_bucket:
        bucket_list.append(cursor)
        cursor += timedelta(minutes=bucket_minutes)

    series_counter = Counter()
    for session in _human_signal_graph_sessions(sessions):
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
        if range_key in {"12h", "24h"}:
            note = (
                f"Durable storage for this project currently begins at "
                f"{_format_alberta_timestamp(earliest_entry_at)}; earlier buckets are shown as zero."
            )
        else:
            note = (
                f"Durable storage for this project currently begins at "
                f"{_format_alberta_timestamp(earliest_entry_at)}, so this {range_config['label'].lower()} "
                "view starts there."
            )

    if source_mode != "durable_store":
        note = "Durable storage is unavailable, so this graph is currently reading the live log tail."

    return {
        "label": "Human-signal arrivals",
        "series_kind": "human_signal_arrivals",
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
    range_key: str = "12h",
    bucket_minutes_override: int | None = None,
) -> dict[str, Any]:
    range_config = PROJECT_GRAPH_RANGES.get(range_key, PROJECT_GRAPH_RANGES["12h"])
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

    # Keep recent live dashboard graphs on a fixed visual canvas. Without this,
    # the 24h graph shrinks when durable coverage starts inside the range.
    if range_key in {"12h", "24h"} and window_hours:
        expected_bucket_count = int((window_hours * 60) / bucket_minutes)
        first_bucket = last_bucket - timedelta(
            minutes=bucket_minutes * max(expected_bucket_count - 1, 0)
        )

    bucket_list: list[datetime] = []
    cursor = first_bucket
    while cursor <= last_bucket:
        bucket_list.append(cursor)
        cursor += timedelta(minutes=bucket_minutes)

    points_by_project: dict[str, Counter] = defaultdict(Counter)
    live_counts = Counter()

    for session in _human_signal_graph_sessions(sessions):
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
        "series_kind": "human_signal_arrivals",
        "projects": projects_output,
    }


def build_project_graph(
    *,
    project_slug: str,
    range_key: str = "12h",
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
