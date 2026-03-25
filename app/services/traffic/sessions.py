from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import re
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

REASON_LABELS = {
    "browser_ua": "Browser fingerprint looks like a real person",
    "unknown_ua": "User agent is unfamiliar, so confidence is limited",
    "bot_signal": "User agent matches a known bot or monitoring pattern",
    "suspicious_signal": "Request pattern looks hostile or scripted",
    "page_route": "Visited real pages, not just background endpoints",
    "api_route": "Mostly touched API endpoints in this session",
    "probe_route": "Hit probing or exploit-style paths",
    "asset_only": "Mostly requested static assets",
    "multi_page": "Moved through multiple pages",
    "single_page": "Only touched one page",
    "repeat_activity": "Showed repeated activity during the session",
    "engaged": "Stayed active long enough to look intentional",
    "brief_engagement": "Showed short but real engagement",
    "internal_referrer": "Arrived from one of your own properties",
    "external_source": "Arrived from an outside source",
    "direct": "Arrived directly or from a bookmark",
    "high_suspicion": "Triggered strong suspicious-traffic signals",
    "low_suspicion": "Triggered mild suspicious-traffic signals",
    "api_only": "Did not show a clear page-view trail",
    "bounce": "One quick hit with no follow-up",
}


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


def person_key_for_session(ip: str, ua: str | None) -> str:
    return f"{ip}|{(ua or '').lower()}"


def humanize_reason(reason: str) -> str:
    return REASON_LABELS.get(reason, reason.replace("_", " "))


def label_classification_state(state: str) -> str:
    labels = {
        "human_confirmed": "Likely Human",
        "likely_human": "Probably Human",
        "candidate": "Unclear",
        "bot": "Known Bot",
        "suspicious": "Suspicious",
        "archived": "Archived",
    }
    return labels.get(state, state.replace("_", " ").title())


def summarize_classification(state: str, human_confidence: int, suspicious_score: int) -> str:
    if state == "human_confirmed":
        return f"Strong human signals with {human_confidence}% confidence from browser behavior, page flow, and dwell time."
    if state == "likely_human":
        return f"Probably a real person with {human_confidence}% confidence, but the session trail is a little thinner."
    if state == "candidate":
        return "Some human signals are present, but the evidence is mixed and needs more activity."
    if state == "bot":
        return "Looks automated because the session matches known bot patterns and shows little real engagement."
    if state == "suspicious":
        return f"Needs attention because the session carries {suspicious_score} suspicion points from hostile or scripted behavior."
    return "This session needs more context before Traffic can explain it cleanly."


def data_confidence_profile(quality_score: int) -> tuple[str, str]:
    if quality_score >= 80:
        return "High", "Browser, route, and timing data are strong enough to trust."
    if quality_score >= 55:
        return "Good", "There is enough session detail here to analyze it confidently."
    if quality_score >= 30:
        return "Limited", "Some useful signals exist, but the trail is still thin."
    return "Low", "Traffic has very little reliable detail for this session."


def attention_profile(
    *,
    active_now: bool,
    engaged_seconds: int,
    page_count: int,
    returning_visitor: bool,
    suspicious_score: int,
) -> tuple[str, str]:
    if suspicious_score >= 40:
        return "Investigate", "Aggressive or exploit-like behavior makes this session worth a closer look."

    reasons: list[str] = []
    if active_now:
        reasons.append("it is active right now")
    if returning_visitor:
        reasons.append("this looks like a returning visitor in the current window")
    if engaged_seconds >= 180:
        reasons.append("dwell time is strong")
    elif engaged_seconds >= 45:
        reasons.append("engagement is building")
    if page_count >= 5:
        reasons.append("the journey is deep")
    elif page_count >= 3:
        reasons.append("the journey spans multiple pages")

    if active_now and (engaged_seconds >= 180 or page_count >= 5 or returning_visitor):
        return "High", "Worth watching because " + ", ".join(reasons[:2]) + "."
    if active_now or engaged_seconds >= 60 or page_count >= 3 or returning_visitor:
        return "Medium", "Worth keeping in view because " + ", ".join(reasons[:2]) + "."
    return "Low", "Useful for context, but this session is not drawing strong attention yet."


def visitor_alias(person_key: str, country: str, area: str, city: str) -> str:
    anchor = city or area or country or "Unknown"
    cleaned = re.sub(r"[^A-Za-z0-9]+", " ", anchor).strip()
    prefix = "".join(part.capitalize() for part in cleaned.split()) or "Unknown"
    ip = person_key.split("|", 1)[0]
    if "." in ip:
        parts = ip.split(".")
        suffix = "-".join(parts[-2:]) if len(parts) >= 2 else ip.replace(".", "-")
    elif ":" in ip:
        segments = [segment for segment in ip.split(":") if segment]
        suffix = "-".join(segments[-2:]) if segments else "ipv6"
    else:
        suffix = hashlib.sha1(person_key.encode("utf-8")).hexdigest()[:6]

    return f"{prefix}-{suffix}"


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
    if page_events:
        route_kind = "page"
    else:
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

    person_key = person_key_for_session(first["ip"], first["ua"])

    return {
        "session_id": f"{first['host']}|{first['ip']}|{first['timestamp_iso']}",
        "visitor_key": f"{first['host']}|{first['ip']}|{ua_lower}",
        "person_key": person_key,
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
        "country_code": geo.get("country_code", ""),
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


def enrich_sessions(sessions: list[dict[str, Any]]) -> None:
    person_counts = Counter(session["person_key"] for session in sessions)
    project_counts = Counter((session["person_key"], session["project_slug"]) for session in sessions)
    person_projects: dict[str, set[str]] = defaultdict(set)

    for session in sessions:
        person_projects[session["person_key"]].add(session["project_slug"])

    for session in sessions:
        person_key = session["person_key"]
        visits_in_window = person_counts[person_key]
        returning = visits_in_window > 1
        attention_label, attention_summary = attention_profile(
            active_now=session["active_now"],
            engaged_seconds=session["engaged_seconds"],
            page_count=session["page_count"],
            returning_visitor=returning,
            suspicious_score=session["suspicious_score"],
        )
        data_label, data_summary = data_confidence_profile(session["quality_score"])

        session["visitor_alias"] = visitor_alias(
            person_key=person_key,
            country=session["country"],
            area=session["area"],
            city=session["city"],
        )
        session["visits_in_window"] = visits_in_window
        session["project_visits_in_window"] = project_counts[(person_key, session["project_slug"])]
        session["projects_visited_in_window"] = len(person_projects[person_key])
        session["returning_visitor"] = returning
        session["verdict_label"] = label_classification_state(session["classification_state"])
        session["classification_reason_labels"] = [
            humanize_reason(reason) for reason in session["classification_reasons"]
        ]
        session["classification_summary"] = summarize_classification(
            session["classification_state"],
            session["human_confidence"],
            session["suspicious_score"],
        )
        session["data_confidence_label"] = data_label
        session["data_confidence_summary"] = data_summary
        session["attention_label"] = attention_label
        session["attention_summary"] = attention_summary


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

    enrich_sessions(sessions)
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
