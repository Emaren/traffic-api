from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.services.traffic.classify import classify_request, detect_route_kind
from app.services.traffic.config import (
    INTERNAL_IGNORE_PATHS,
    LIVE_TILE_LIMIT,
    LOG_PATH,
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

from zoneinfo import ZoneInfo

ALBERTA_ZONE = ZoneInfo(ALBERTA_TZ_NAME)
PROJECT_GRAPH_RANGES: dict[str, dict[str, Any]] = {
    "24h": {"label": "24 Hours", "window_hours": 24},
    "7d": {"label": "1 Week", "window_hours": 24 * 7},
    "30d": {"label": "1 Month", "window_hours": 24 * 30},
    "all": {"label": "All Time", "window_hours": None},
}


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
) -> tuple[list[dict[str, Any]], str]:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
        if window_hours is not None
        else None
    )
    recent_entries: list[dict[str, Any]] = []
    persisted_entries = load_recent_entries(window_hours=window_hours)
    source_mode = "durable_store" if persisted_entries is not None else "log_tail"

    if persisted_entries is None:
        lines = read_recent_log_lines(LOG_PATH, TAIL_LINES)

        source_entries: list[dict[str, Any]] = []
        for line in lines:
            parsed = parse_log_line(line)
            if parsed:
                source_entries.append(parsed)
    else:
        source_entries = persisted_entries

    for parsed in source_entries:
        if not is_allowed_host(parsed["host"]):
            continue

        if cutoff is not None and parsed["timestamp"] < cutoff:
            continue

        parsed["category"] = classify_request(parsed["ua"], parsed["normalized_path"])
        parsed["route_kind"] = detect_route_kind(parsed["normalized_path"])

        if should_ignore_entry(parsed):
            continue

        recent_entries.append(parsed)

    return recent_entries, source_mode


def build_overview(range_key: str = "24h") -> dict[str, Any]:
    range_config = _range_config(range_key)
    window_hours = _window_hours_for_range(range_key)
    recent_entries, source_mode = collect_recent_entries_with_source(window_hours=window_hours)
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

    sessions = build_sessions(recent_entries)
    likely_human_states = {"human_confirmed", "likely_human"}
    automated_states = {"bot", "suspicious"}

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

    alerts.append(
        {
            "severity": "low",
            "title": f"Reading local log file {LOG_PATH}",
            "count": total_requests,
        }
    )

    avg_session_seconds = int(sum(session["total_seconds"] for session in sessions) / len(sessions)) if sessions else 0
    avg_page_seconds = int(sum(page["avg_seconds"] for page in top_pages) / len(top_pages)) if top_pages else 0

    notes = [
        "Traffic service has been split into focused modules.",
        "This view is built from log lines, not seeded demo data.",
        f"Current source log: {LOG_PATH}",
        f"Host allowlist live: {len(ALLOWED_HOSTS)} approved hosts.",
    ]

    from app.services.traffic.config import GEOIP_DB_PATH

    if GEOIP_DB_PATH.exists():
        notes.append(f"GeoIP DB loaded: {GEOIP_DB_PATH}")
    else:
        notes.append(f"GeoIP DB missing: {GEOIP_DB_PATH}")

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
    sessions = build_sessions(collect_recent_entries(window_hours=window_hours))

    tower_candidates = [
        session
        for session in sessions
        if session["classification_state"] not in {"bot", "suspicious"}
        and (session["page_count"] > 0 or session["route_kind"] == "page")
    ]

    tower = sorted(tower_candidates, key=live_session_sort_key)[:limit]

    history_candidates = sorted(tower_candidates, key=lambda item: item["ended_at"], reverse=True)
    history_items = history_candidates[limit : limit + history_limit]
    stream_items = list(reversed(history_candidates[: limit + history_limit]))

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


def _project_live_feed_sessions(
    sessions: list[dict[str, Any]],
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    automated_states = {"bot", "suspicious"}
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
    project: str | None = None,
) -> dict[str, Any]:
    range_config = _range_config(range_key)
    window_hours = _window_hours_for_range(range_key)
    entries, source_mode = collect_recent_entries_with_source(window_hours=window_hours)
    sessions = build_sessions(entries)

    filtered = sessions
    if classification:
        filtered = [session for session in filtered if session["classification_state"] == classification]
    if project:
        filtered = [session for session in filtered if session["project_slug"] == project]

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
    recent_entries, source_mode = collect_recent_entries_with_source(window_hours=window_hours)
    project_entries = [
        entry
        for entry in recent_entries
        if project_for_host(entry["host"])["slug"] == project_slug
    ]
    sessions = build_sessions(project_entries)

    now = datetime.now(timezone.utc)
    earliest_entry_at = project_entries[0]["timestamp"] if project_entries else None
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
        "label": "New likely-human visitors",
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
    recent_entries, source_mode = collect_recent_entries_with_source(window_hours=window_hours)
    now = datetime.now(timezone.utc)
    earliest_entry_at = recent_entries[0]["timestamp"] if recent_entries else None
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

    sessions = build_sessions(recent_entries)

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
        "series_kind": "new_human_visitors",
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
    sessions = build_sessions(recent_entries)

    likely_human_states = {"human_confirmed", "likely_human"}
    automated_states = {"bot", "suspicious"}

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
    graph = _project_graph_payload(
        project_slug=project["slug"],
        range_key="24h",
        bucket_minutes_override=bucket_minutes,
    )

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

    avg_session_seconds = int(sum(session["total_seconds"] for session in sessions) / len(sessions)) if sessions else 0

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "bucket_minutes": graph["bucket_minutes"],
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
        "hosts": hosts,
        "top_pages": top_pages,
        "geo": {
            "countries": country_rows,
            "areas": area_rows,
            "cities": city_rows,
        },
        "suspicious": {
            "top_paths": [
                {"path": path, "count": count}
                for path, count in suspicious_path_counter.most_common(TOP_LIMIT)
            ],
            "top_ips": suspicious_top_ips,
        },
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

    recent_entries = [
        entry
        for entry in collect_recent_entries(window_hours=window_hours)
        if project_for_host(entry["host"])["slug"] == project_slug
    ]
    sessions = build_sessions(recent_entries)

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
    recent_entries, source_mode = collect_recent_entries_with_source(window_hours=window_hours)
    sessions = build_sessions(recent_entries)
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
    latest = newest_first[0]
    oldest = newest_first[-1]
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
    project_last_seen = {
        session["project_slug"]: session["last_seen_at"] for session in newest_first
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
        },
        "projects": [
            {
                "slug": slug,
                "name": project_names[slug],
                "visits": count,
                "last_seen_at": project_last_seen[slug],
            }
            for slug, count in project_counts.most_common()
        ],
        "sessions": profile_sessions,
    }
