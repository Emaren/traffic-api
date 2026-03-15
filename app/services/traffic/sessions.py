from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

from app.services.traffic.classify import (
    classification_state_for_confidence,
    compute_human_confidence,
    compute_live_priority,
    compute_quality_score,
    detect_browser,
    detect_device_type,
    detect_os,
    detect_route_kind,
    is_trackable_path,
    quality_label_for_score,
)
from app.services.traffic.config import (
    ACTIVE_GAP_CAP_SECONDS,
    ALBERTA_TZ_NAME,
    LIVE_ACTIVE_SECONDS,
    SESSION_GAP_MINUTES,
    VISITOR_SESSION_LIMIT,
    UNKNOWN_HOST,
    UNKNOWN_REFERRER,
)
from app.services.traffic.geo import get_geo_details
from app.services.traffic.normalize import is_internal_referrer, project_for_host
from app.services.traffic.parse import parse_iso_timestamp, safe_int

ALBERTA_ZONE = ZoneInfo(ALBERTA_TZ_NAME)


def ordered_unique(values: list[str]) -> list[str]:
    seen = set()
    output = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)

    return output


def compress_consecutive(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if not output or output[-1] != value:
            output.append(value)
    return output


def to_alberta_display(value: datetime) -> str:
    return value.astimezone(ALBERTA_ZONE).strftime("%Y-%m-%d %I:%M:%S %p")


def detect_source_medium_campaign(entry: dict[str, Any]) -> tuple[str, str, str]:
    raw_path = entry.get("raw_path") or ""

    try:
        parsed = urlsplit(raw_path)
        query = parse_qs(parsed.query)
    except Exception:
        query = {}

    if query.get("utm_source"):
        source = query["utm_source"][0]
        medium = query.get("utm_medium", ["campaign"])[0]
        campaign = query.get("utm_campaign", [""])[0]
        return source, medium, campaign

    host = entry.get("host") or UNKNOWN_HOST
    referrer = entry.get("referrer_host") or UNKNOWN_REFERRER

    if referrer in {UNKNOWN_REFERRER, "", UNKNOWN_HOST}:
        return "direct", "unknown", ""

    if is_internal_referrer(host, referrer):
        return "internal", "navigation", ""

    if "google." in referrer:
        return "google", "organic", ""
    if "bing." in referrer:
        return "bing", "organic", ""
    if "x.com" in referrer or "twitter.com" in referrer:
        return "x", "social", ""
    if "facebook." in referrer:
        return "facebook", "social", ""
    if "mail" in referrer:
        return "email", "campaign", ""

    return referrer, "referral", ""


def build_single_session(events: list[dict[str, Any]], now: datetime | None = None) -> dict[str, Any]:
    if now is None:
        now = datetime.now(timezone.utc)

    first = events[0]
    last = events[-1]

    trackable_events = [event for event in events if is_trackable_path(event["normalized_path"])]
    page_events = [event for event in trackable_events if detect_route_kind(event["normalized_path"]) == "page"]

    page_sequence = compress_consecutive(
        [event["normalized_path"] for event in (page_events if page_events else trackable_events)]
    )[:50]
    ordered_paths = ordered_unique(page_sequence)[:20]

    entry_page = page_sequence[0] if page_sequence else first["normalized_path"]
    current_page = page_sequence[-1] if page_sequence else last["normalized_path"]
    exit_page = current_page

    category_counter = Counter(event["category"] for event in events)
    route_counter = Counter(detect_route_kind(event["normalized_path"]) for event in trackable_events)

    suspicious_score = min(
        100,
        category_counter.get("suspicious", 0) * 35 + category_counter.get("bot", 0) * 8,
    )

    engaged_seconds = 0
    total_seconds = 0

    for previous, current in zip(events, events[1:]):
        gap = int((current["timestamp"] - previous["timestamp"]).total_seconds())
        if gap <= 0:
            continue

        total_seconds += gap
        if previous["category"] == "human":
            engaged_seconds += min(gap, ACTIVE_GAP_CAP_SECONDS)

    geo = get_geo_details(first["ip"])
    source, medium, campaign = detect_source_medium_campaign(first)
    project = project_for_host(first["host"])

    primary_category = category_counter.most_common(1)[0][0] if category_counter else "unknown"
    route_kind = route_counter.most_common(1)[0][0] if route_counter else detect_route_kind(first["normalized_path"])

    quality_score = compute_quality_score(
        primary_category=primary_category,
        route_kind=route_kind,
        page_count=len(ordered_paths),
        event_count=len(events),
        total_seconds=total_seconds,
        engaged_seconds=engaged_seconds,
        suspicious_score=suspicious_score,
        source=source,
        medium=medium,
    )

    human_confidence, classification_reasons = compute_human_confidence(
        primary_category=primary_category,
        route_kind=route_kind,
        page_count=len(ordered_paths),
        event_count=len(events),
        total_seconds=total_seconds,
        engaged_seconds=engaged_seconds,
        suspicious_score=suspicious_score,
        source=source,
    )

    classification_state = classification_state_for_confidence(
        primary_category=primary_category,
        route_kind=route_kind,
        human_confidence=human_confidence,
        suspicious_score=suspicious_score,
    )

    idle_seconds = max(0, int((now - last["timestamp"]).total_seconds()))
    active_now = idle_seconds <= LIVE_ACTIVE_SECONDS

    live_priority = compute_live_priority(
        human_confidence=human_confidence,
        engaged_seconds=engaged_seconds,
        page_count=len(ordered_paths),
        event_count=len(events),
        idle_seconds=idle_seconds,
        suspicious_score=suspicious_score,
        active_now=active_now,
    )

    ua_lower = (first["ua"] or "").lower()

    return {
        "session_id": f"{first['host']}|{first['ip']}|{first['timestamp_iso']}",
        "visitor_key": f"{first['host']}|{first['ip']}|{ua_lower}",
        "project_slug": project["slug"],
        "project_name": project["name"],
        "project_category": project["category"],
        "host": first["host"],
        "ip": first["ip"],
        "started_at": first["timestamp_iso"],
        "ended_at": last["timestamp_iso"],
        "first_seen_at": first["timestamp_iso"],
        "last_seen_at": last["timestamp_iso"],
        "last_page_request_at": last["timestamp_iso"],
        "first_seen_alberta": to_alberta_display(first["timestamp"]),
        "last_seen_alberta": to_alberta_display(last["timestamp"]),
        "country": geo["country"],
        "area": geo["area"],
        "city": geo["city"],
        "device": detect_device_type(first["ua"]),
        "os": detect_os(first["ua"]),
        "browser": detect_browser(first["ua"]),
        "referrer": first["referrer_host"],
        "source": source,
        "medium": medium,
        "campaign": campaign,
        "entry_page": entry_page,
        "current_page": current_page,
        "exit_page": exit_page,
        "next_page": page_sequence[1] if len(page_sequence) > 1 else "",
        "page_sequence": page_sequence,
        "page_count": len(ordered_paths),
        "event_count": len(events),
        "total_seconds": total_seconds,
        "engaged_seconds": engaged_seconds,
        "idle_seconds": idle_seconds,
        "active_now": active_now,
        "suspicious_score": suspicious_score,
        "primary_category": primary_category,
        "route_kind": route_kind,
        "quality_score": quality_score,
        "quality_label": quality_label_for_score(quality_score),
        "human_confidence": human_confidence,
        "classification_state": classification_state,
        "classification_reasons": classification_reasons,
        "human_confirmed": classification_state == "human_confirmed",
        "live_priority": live_priority,
    }


def build_sessions(recent_entries: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for entry in recent_entries:
        host = entry["host"]
        if host == UNKNOWN_HOST:
            continue

        visitor_key = (host, entry["ip"], (entry["ua"] or "").lower())
        grouped[visitor_key].append(entry)

    session_gap_seconds = SESSION_GAP_MINUTES * 60
    sessions: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    for events in grouped.values():
        ordered_events = sorted(events, key=lambda item: item["timestamp"])
        current_session: list[dict[str, Any]] = []

        for event in ordered_events:
            if not current_session:
                current_session = [event]
                continue

            gap = int((event["timestamp"] - current_session[-1]["timestamp"]).total_seconds())
            if gap > session_gap_seconds:
                sessions.append(build_single_session(current_session, now=now))
                current_session = [event]
            else:
                current_session.append(event)

        if current_session:
            sessions.append(build_single_session(current_session, now=now))

    sessions.sort(key=lambda item: item["ended_at"], reverse=True)

    if limit is None:
        return sessions
    return sessions[:limit]


def build_path_stats(recent_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from collections import Counter, defaultdict

    views = Counter()
    entries = Counter()
    exits = Counter()
    next_paths: dict[str, Counter] = defaultdict(Counter)
    duration_totals = Counter()
    duration_counts = Counter()
    route_kind_by_path: dict[str, str] = {}

    by_session_key: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for entry in recent_entries:
        key = (entry["host"], entry["ip"], (entry["ua"] or "").lower())
        by_session_key[key].append(entry)

    for session_entries in by_session_key.values():
        ordered_events = sorted(session_entries, key=lambda item: item["timestamp"])
        trackable_events = [event for event in ordered_events if is_trackable_path(event["normalized_path"])]

        if not trackable_events:
            continue

        entries[trackable_events[0]["normalized_path"]] += 1
        exits[trackable_events[-1]["normalized_path"]] += 1

        for event in trackable_events:
            path = event["normalized_path"]
            views[path] += 1
            route_kind_by_path[path] = detect_route_kind(path)

        for previous, current in zip(trackable_events, trackable_events[1:]):
            gap = int((current["timestamp"] - previous["timestamp"]).total_seconds())
            prev_path = previous["normalized_path"]
            next_path = current["normalized_path"]

            if gap > 0:
                duration_totals[prev_path] += min(gap, ACTIVE_GAP_CAP_SECONDS)
                duration_counts[prev_path] += 1

            next_paths[prev_path][next_path] += 1

    output: list[dict[str, Any]] = []

    from app.services.traffic.config import TOP_LIMIT

    for path, view_count in views.most_common(TOP_LIMIT):
        avg_seconds = int(duration_totals[path] / duration_counts[path]) if duration_counts[path] else 0
        output.append(
            {
                "path": path,
                "route_kind": route_kind_by_path.get(path, detect_route_kind(path)),
                "entries": entries[path],
                "views": view_count,
                "exits": exits[path],
                "avg_seconds": avg_seconds,
                "top_next_paths": [
                    {"path": next_path, "count": count}
                    for next_path, count in next_paths[path].most_common(3)
                ],
            }
        )

    return output


def session_bucket(session: dict[str, Any]) -> int:
    state = session.get("classification_state", "candidate")
    route_kind = session.get("route_kind", "unknown")
    quality_score = safe_int(session.get("quality_score"), 0)

    if state == "human_confirmed" and route_kind == "page" and quality_score >= 55:
        return 0
    if state == "likely_human" and route_kind == "page":
        return 1
    if state == "human_confirmed" and route_kind == "api":
        return 2
    if state == "candidate" and route_kind == "page":
        return 3
    if state == "bot":
        return 5
    if state == "suspicious" or route_kind == "probe":
        return 6
    return 4


def session_sort_key(session: dict[str, Any]) -> tuple[int, int, int, float]:
    parsed = parse_iso_timestamp(session.get("ended_at"))
    ts = parsed.timestamp() if parsed else 0.0
    quality_score = safe_int(session.get("quality_score"), 0)
    suspicious_score = safe_int(session.get("suspicious_score"), 0)
    human_confidence = safe_int(session.get("human_confidence"), 0)

    return (
        session_bucket(session),
        -quality_score,
        -human_confidence,
        suspicious_score,
        -ts,
    )


def live_session_sort_key(session: dict[str, Any]) -> tuple[int, int, float]:
    parsed = parse_iso_timestamp(session.get("ended_at"))
    ts = parsed.timestamp() if parsed else 0.0
    live_priority = safe_int(session.get("live_priority"), 0)
    human_confidence = safe_int(session.get("human_confidence"), 0)

    return (-live_priority, -human_confidence, -ts)
