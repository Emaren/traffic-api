from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.services.traffic.classify import classify_request, detect_route_kind
from app.services.traffic.config import (
    INTERNAL_IGNORE_PATHS,
    LIVE_TILE_LIMIT,
    LOG_PATH,
    SERIES_BUCKET_MINUTES,
    TAIL_LINES,
    TOP_LIMIT,
    VISITS_HISTORY_LIMIT,
    PROJECTS,
    ALBERTA_TZ_NAME,
)
from app.services.traffic.geo import get_geo_details
from app.services.traffic.normalize import ALLOWED_HOSTS, is_allowed_host, project_for_host
from app.services.traffic.parse import iso_now, parse_log_line, read_recent_log_lines
from app.services.traffic.sessions import build_path_stats, build_sessions, live_session_sort_key, session_sort_key

from zoneinfo import ZoneInfo

ALBERTA_ZONE = ZoneInfo(ALBERTA_TZ_NAME)


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


def collect_recent_entries(window_hours: int = 24) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    lines = read_recent_log_lines(LOG_PATH, TAIL_LINES)

    recent_entries: list[dict[str, Any]] = []

    for line in lines:
        parsed = parse_log_line(line)
        if not parsed:
            continue

        if not is_allowed_host(parsed["host"]):
            continue

        if parsed["timestamp"] < cutoff:
            continue

        parsed["category"] = classify_request(parsed["ua"], parsed["normalized_path"])
        parsed["route_kind"] = detect_route_kind(parsed["normalized_path"])

        if should_ignore_entry(parsed):
            continue

        recent_entries.append(parsed)

    return recent_entries


def build_overview(window_hours: int = 24) -> dict[str, Any]:
    recent_entries = collect_recent_entries(window_hours=window_hours)

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
    prioritized_sessions = sorted(sessions, key=session_sort_key)[:10]

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

    notes.append("Route classification is live: page, api, probe, asset.")
    notes.append("Live visitor tower and human series endpoints are now available.")

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window": f"{window_hours}h",
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
        "project_counts": project_counts,
        "top_25": tower,
        "history_preview": history_items,
    }


def build_visits_history(
    *,
    limit: int = 100,
    offset: int = 0,
    window_hours: int = 24,
    classification: str | None = None,
    project: str | None = None,
) -> dict[str, Any]:
    sessions = build_sessions(collect_recent_entries(window_hours=window_hours))

    filtered = sessions
    if classification:
        filtered = [session for session in filtered if session["classification_state"] == classification]
    if project:
        filtered = [session for session in filtered if session["project_slug"] == project]

    filtered = sorted(filtered, key=lambda item: item["ended_at"], reverse=True)
    total = len(filtered)
    items = filtered[offset : offset + limit]

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "offset": offset,
        "limit": limit,
        "total": total,
        "items": items,
    }


def _align_bucket(value: datetime, bucket_minutes: int) -> datetime:
    minute = (value.minute // bucket_minutes) * bucket_minutes
    return value.replace(minute=minute, second=0, microsecond=0)


def build_project_human_series(
    *,
    window_hours: int = 24,
    bucket_minutes: int = SERIES_BUCKET_MINUTES,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    first_bucket = _align_bucket(window_start, bucket_minutes)
    last_bucket = _align_bucket(now, bucket_minutes)

    bucket_list: list[datetime] = []
    cursor = first_bucket
    while cursor <= last_bucket:
        bucket_list.append(cursor)
        cursor += timedelta(minutes=bucket_minutes)

    sessions = build_sessions(collect_recent_entries(window_hours=window_hours))

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

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window_hours": window_hours,
        "bucket_minutes": bucket_minutes,
        "series_kind": "new_human_visitors",
        "projects": projects_output,
    }
