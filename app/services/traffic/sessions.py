from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

from app.services.traffic.classify import (
    automation_family,
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
    PLAYER_PAGE_PATH_PREFIXES,
    SESSION_GAP_MINUTES,
    THIN_DIRECT_BROWSER_MAX_ENGAGED_SECONDS,
    THIN_DIRECT_BROWSER_MAX_EVENTS,
    THIN_DIRECT_BROWSER_MAX_PAGES,
    THIN_DIRECT_BROWSER_MAX_TOTAL_SECONDS,
    VISITOR_SESSION_LIMIT,
    UNKNOWN_HOST,
    UNKNOWN_REFERRER,
)
from app.services.traffic.geo import get_geo_details
from app.services.traffic.normalize import is_internal_referrer, project_for_host
from app.services.traffic.parse import parse_iso_timestamp, safe_int

ALBERTA_ZONE = ZoneInfo(ALBERTA_TZ_NAME)
PREFETCH_BURST_WINDOW_SECONDS = 2
PREFETCH_BURST_MIN_UNIQUE_PAGES = 4
ROTATING_UA_ROUTE_SPAM_MIN_REQUESTS = 24
ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_UAS = 4
ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_PATHS = 4
ROTATING_UA_ROUTE_SPAM_MAX_UNIQUE_PATHS = 8
ROTATING_UA_ROUTE_SPAM_DIRECT_RATIO = 0.9

DISTRIBUTED_BURST_WINDOW_SECONDS = 60
DISTRIBUTED_BURST_MIN_SESSIONS = 3
DISTRIBUTED_BURST_MIN_IPS = 3
DISTRIBUTED_BURST_MIN_PATHS = 2
DISTRIBUTED_BURST_MAX_EVENTS_PER_SESSION = 2
DISTRIBUTED_BURST_MAX_PAGES_PER_SESSION = 1

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
    "ua_rotation": "One IP rapidly rotated through multiple browser fingerprints",
    "route_bundle_spam": "One IP is cycling through a synthetic framework route bundle",
    "thin_direct_browser": "Thin direct browser session with too little depth to trust",
    "player_page_hop": "Jumped through narrow player pages in a scraper-like pattern",
    "geo_unknown": "Geo lookup could not resolve a trustworthy location",
    "browser_script_pattern": "Browser-shaped session matches a script or scraper pattern",
    "distributed_ip_burst": "Many near-identical one-hit browser sessions arrived from different IPs at the same time",
    "one_hit_fanout": "Each member looked like a thin one-hit route probe rather than a real journey",
}




def _path_matches_prefixes(path: str, prefixes: tuple[str, ...]) -> bool:
    lowered = (path or "").lower()
    return any(lowered.startswith(prefix) for prefix in prefixes)


def _looks_like_player_page_hop(page_sequence: list[str]) -> bool:
    return bool(page_sequence) and all(
        _path_matches_prefixes(path, PLAYER_PAGE_PATH_PREFIXES) for path in page_sequence
    )


def _looks_like_browser_script_session(
    *,
    primary_category: str,
    route_kind: str,
    source: str,
    page_sequence: list[str],
    page_count: int,
    event_count: int,
    engaged_seconds: int,
    total_seconds: int,
    known_automation: bool,
    active_now: bool,
) -> bool:
    if known_automation:
        return False
    if primary_category != "human" or route_kind != "page":
        return False
    if source != "direct":
        return False
    if page_count > THIN_DIRECT_BROWSER_MAX_PAGES or event_count > THIN_DIRECT_BROWSER_MAX_EVENTS:
        return False
    if active_now:
        return False

    thin_timing = (
        engaged_seconds <= THIN_DIRECT_BROWSER_MAX_ENGAGED_SECONDS
        and total_seconds <= THIN_DIRECT_BROWSER_MAX_TOTAL_SECONDS
    )
    return thin_timing or _looks_like_player_page_hop(page_sequence)


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


def event_order_key(event: dict[str, Any]) -> tuple[datetime, int]:
    return event["timestamp"], safe_int(event.get("line_offset"), 0)


def sort_session_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=event_order_key)


def session_id_for_events(events: list[dict[str, Any]]) -> str:
    first = events[0]
    return f"{first['host']}|{first['ip']}|{first['timestamp_iso']}"


def split_session_events(recent_entries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for entry in recent_entries:
        host = entry["host"]
        if host == UNKNOWN_HOST:
            continue

        visitor_key = (host, entry["ip"], (entry["ua"] or "").lower())
        grouped[visitor_key].append(entry)

    session_gap_seconds = SESSION_GAP_MINUTES * 60
    session_groups: list[list[dict[str, Any]]] = []

    for events in grouped.values():
        ordered_events = sort_session_events(events)
        current_session: list[dict[str, Any]] = []

        for event in ordered_events:
            if not current_session:
                current_session = [event]
                continue

            gap = int((event["timestamp"] - current_session[-1]["timestamp"]).total_seconds())
            if gap > session_gap_seconds:
                session_groups.append(current_session)
                current_session = [event]
            else:
                current_session.append(event)

        if current_session:
            session_groups.append(current_session)

    return session_groups


def path_events_for_session(
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ordered_events = sort_session_events(events)
    trackable_events = [event for event in ordered_events if is_trackable_path(event["normalized_path"])]
    page_events = [
        event for event in trackable_events if detect_route_kind(event["normalized_path"]) == "page"
    ]
    return trackable_events, page_events


def _looks_like_prefetch_page_burst(page_events: list[dict[str, Any]]) -> bool:
    if len(page_events) < PREFETCH_BURST_MIN_UNIQUE_PAGES:
        return False

    first = page_events[0]
    last = page_events[-1]
    if int((last["timestamp"] - first["timestamp"]).total_seconds()) > PREFETCH_BURST_WINDOW_SECONDS:
        return False

    unique_paths = ordered_unique([event["normalized_path"] for event in page_events])
    if len(unique_paths) < PREFETCH_BURST_MIN_UNIQUE_PAGES:
        return False

    host = first["host"]
    internalish_count = 0
    for event in page_events:
        referrer_host = event.get("referrer_host") or UNKNOWN_REFERRER
        if referrer_host in {"", UNKNOWN_REFERRER, UNKNOWN_HOST, host} or is_internal_referrer(
            host, referrer_host
        ):
            internalish_count += 1

    return internalish_count >= len(page_events) - 1


def compact_page_events_for_session(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _trackable_events, page_events = path_events_for_session(events)
    if not page_events:
        return []

    compacted: list[dict[str, Any]] = []
    cluster: list[dict[str, Any]] = []

    for event in page_events:
        if not cluster:
            cluster = [event]
            continue

        gap = int((event["timestamp"] - cluster[0]["timestamp"]).total_seconds())
        if gap <= PREFETCH_BURST_WINDOW_SECONDS:
            cluster.append(event)
            continue

        compacted.extend([cluster[0]] if _looks_like_prefetch_page_burst(cluster) else cluster)
        cluster = [event]

    if cluster:
        compacted.extend([cluster[0]] if _looks_like_prefetch_page_burst(cluster) else cluster)

    return compacted


def _is_framework_route_bundle_path(path: str) -> bool:
    return path == "/" or path == "/app" or path.startswith("/_next") or path == "/api" or path.startswith("/api/")


def _ip_burst_family(ip: str) -> str:
    if "." in ip:
        parts = ip.split(".")
        if len(parts) >= 1 and parts[0].isdigit():
            return f"{parts[0]}.x.x.x"
    if ":" in ip:
        return ip.split(":", 1)[0] + "::/16"
    return "unknown"


def _session_burst_bucket(session: dict[str, Any]) -> int:
    parsed = parse_iso_timestamp(session.get("started_at"))
    if parsed is None:
        parsed = datetime.now(timezone.utc)
    return int(parsed.timestamp() // DISTRIBUTED_BURST_WINDOW_SECONDS)


def _is_distributed_burst_candidate(session: dict[str, Any]) -> bool:
    if session.get("known_automation"):
        return False
    if session.get("classification_state") not in {"candidate", "browser_script", "likely_human"}:
        return False
    if session.get("route_kind") not in {"page", "api"}:
        return False
    if session.get("source") not in {"direct", "internal", ""}:
        return False
    if safe_int(session.get("event_count"), 0) > DISTRIBUTED_BURST_MAX_EVENTS_PER_SESSION:
        return False
    if safe_int(session.get("page_count"), 0) > DISTRIBUTED_BURST_MAX_PAGES_PER_SESSION:
        return False
    if safe_int(session.get("total_seconds"), 0) > 5:
        return False
    if not session.get("country") or session.get("country") == "Unknown":
        return False
    if session.get("browser") == "Unknown":
        return False
    return True


def _build_distributed_burst_session(group: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(group, key=lambda item: item["started_at"])
    first = ordered[0]
    last = max(ordered, key=lambda item: item["ended_at"])
    ips = ordered_unique([session["ip"] for session in ordered if session.get("ip")])
    paths = ordered_unique(
        [
            path
            for session in ordered
            for path in (session.get("page_sequence") or [session.get("entry_page", "")])
            if path
        ]
    )
    families = sorted({_ip_burst_family(ip) for ip in ips})
    starts = [parse_iso_timestamp(session["started_at"]) for session in ordered]
    ends = [parse_iso_timestamp(session["ended_at"]) for session in ordered]
    valid_starts = [value for value in starts if value is not None]
    valid_ends = [value for value in ends if value is not None]
    first_dt = min(valid_starts) if valid_starts else datetime.now(timezone.utc)
    last_dt = max(valid_ends) if valid_ends else first_dt
    window_seconds = max(0, int((last_dt - first_dt).total_seconds()))

    country = first.get("country") or "Unknown"
    city_counts = Counter(session.get("city") or "" for session in ordered if session.get("city"))
    area_counts = Counter(session.get("area") or "" for session in ordered if session.get("area"))
    city = city_counts.most_common(1)[0][0] if city_counts else first.get("city", "")
    area = area_counts.most_common(1)[0][0] if area_counts else first.get("area", "")

    signature = "|".join(
        [
            "script_burst",
            first.get("project_slug", ""),
            first.get("country_code") or country,
            first.get("device", ""),
            first.get("os", ""),
            first.get("browser", ""),
            str(_session_burst_bucket(first)),
            ",".join(families),
        ]
    )
    profile_id = visitor_profile_id_for_person(signature)
    path_count = len(paths)

    return {
        **first,
        "session_id": f"burst|{profile_id}|{first_dt.isoformat()}",
        "visitor_key": signature,
        "person_key": signature,
        "visitor_profile_id": profile_id,
        "ip": f"{len(ips)} IPs",
        "started_at": first_dt.isoformat(),
        "ended_at": last_dt.isoformat(),
        "first_seen_at": first_dt.isoformat(),
        "last_seen_at": last_dt.isoformat(),
        "last_page_request_at": last_dt.isoformat(),
        "first_seen_alberta": to_alberta_display(first_dt),
        "last_seen_alberta": to_alberta_display(last_dt),
        "country": country,
        "country_code": first.get("country_code", ""),
        "area": area,
        "city": city,
        "geo_resolved": True,
        "entry_page": paths[0] if paths else first.get("entry_page", ""),
        "current_page": paths[-1] if paths else first.get("current_page", ""),
        "exit_page": paths[-1] if paths else first.get("exit_page", ""),
        "next_page": paths[1] if len(paths) > 1 else "",
        "page_sequence": paths[:20],
        "page_count": path_count,
        "event_count": sum(safe_int(session.get("event_count"), 0) for session in ordered),
        "total_seconds": window_seconds,
        "engaged_seconds": 0,
        "idle_seconds": min(safe_int(session.get("idle_seconds"), 0) for session in ordered),
        "active_now": any(bool(session.get("active_now")) for session in ordered),
        "suspicious_score": 88,
        "primary_category": "suspicious",
        "route_kind": "page",
        "quality_score": 8,
        "quality_label": "weak",
        "human_confidence": 0,
        "classification_state": "script_burst",
        "classification_reasons": ["distributed_ip_burst", "one_hit_fanout", "thin_direct_browser"],
        "human_confirmed": False,
        "live_priority": 120,
        "is_burst_cluster": True,
        "burst_member_count": len(ordered),
        "burst_ip_count": len(ips),
        "burst_path_count": path_count,
        "burst_window_seconds": window_seconds,
        "burst_ip_families": families,
        "burst_sample_ips": ips[:12],
        "burst_paths": paths[:20],
        "network_ua_count": len({session.get("browser", "") for session in ordered}),
        "network_path_count": path_count,
        "route_bundle_spam": False,
    }




def _is_known_singapore_43_fanout(session: dict[str, Any]) -> bool:
    ip = str(session.get("ip") or "")
    if not (ip.startswith("43.172.") or ip.startswith("43.173.")):
        return False
    if (session.get("country_code") or session.get("country")) not in {"SG", "Singapore"}:
        return False
    if session.get("project_slug") != "aoe2hdbets":
        return False
    if session.get("device") != "desktop":
        return False
    if session.get("os") != "Windows":
        return False
    if session.get("browser") != "Chrome":
        return False
    if session.get("source") not in {"direct", "internal", ""}:
        return False
    if safe_int(session.get("event_count"), 0) > 2:
        return False
    if safe_int(session.get("page_count"), 0) > 1:
        return False
    if safe_int(session.get("visits_in_window"), 0) > 1:
        return False
    if safe_int(session.get("total_seconds"), 0) > 8:
        return False

    path = str(session.get("entry_page") or session.get("current_page") or "")
    noisy_paths = (
        "/api/",
        "/game-stats/",
        "/wolo",
        "/watch",
        "/bets",
        "/live-games",
        "/requests",
        "/api/auth/session",
    )
    return path == "/" or any(path.startswith(prefix) for prefix in noisy_paths)



def collapse_distributed_bursts(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str, str, int, str], list[dict[str, Any]]] = defaultdict(list)

    for session in sessions:
        if not _is_distributed_burst_candidate(session):
            continue

        key = (
            session.get("project_slug", ""),
            session.get("country_code") or session.get("country", ""),
            session.get("device", ""),
            session.get("os", ""),
            session.get("browser", ""),
            session.get("source", ""),
            _session_burst_bucket(session),
            _ip_burst_family(session.get("ip", "")),
        )
        grouped[key].append(session)

    collapsed_session_ids: set[str] = set()
    burst_sessions: list[dict[str, Any]] = []

    for group in grouped.values():
        if len(group) < DISTRIBUTED_BURST_MIN_SESSIONS:
            continue

        ips = {session.get("ip") for session in group if session.get("ip")}
        paths = {
            path
            for session in group
            for path in (session.get("page_sequence") or [session.get("entry_page", "")])
            if path
        }
        starts = [parse_iso_timestamp(session["started_at"]) for session in group]
        valid_starts = [value for value in starts if value is not None]

        if len(ips) < DISTRIBUTED_BURST_MIN_IPS:
            continue
        if len(paths) < DISTRIBUTED_BURST_MIN_PATHS:
            continue
        if valid_starts and int((max(valid_starts) - min(valid_starts)).total_seconds()) > DISTRIBUTED_BURST_WINDOW_SECONDS:
            continue

        for session in group:
            collapsed_session_ids.add(session["session_id"])
        burst_sessions.append(_build_distributed_burst_session(group))

    if not collapsed_session_ids:
        return sessions

    return [
        session
        for session in sessions
        if session["session_id"] not in collapsed_session_ids
    ] + burst_sessions


def build_ip_behavior_map(recent_entries: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for entry in recent_entries:
        host = entry["host"]
        if host == UNKNOWN_HOST:
            continue
        grouped[(host, entry["ip"])].append(entry)

    behavior_map: dict[tuple[str, str], dict[str, Any]] = {}
    for key, entries in grouped.items():
        ordered_entries = sort_session_events(entries)
        unique_uas = {
            (entry.get("ua") or "").lower()
            for entry in ordered_entries
            if (entry.get("ua") or "").strip()
        }
        unique_paths = ordered_unique([entry["normalized_path"] for entry in ordered_entries])
        direct_referrers = sum(
            1
            for entry in ordered_entries
            if (entry.get("referrer_host") or UNKNOWN_REFERRER) in {UNKNOWN_REFERRER, "", UNKNOWN_HOST}
        )
        route_bundle_spam = (
            len(ordered_entries) >= ROTATING_UA_ROUTE_SPAM_MIN_REQUESTS
            and len(unique_uas) >= ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_UAS
            and ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_PATHS
            <= len(unique_paths)
            <= ROTATING_UA_ROUTE_SPAM_MAX_UNIQUE_PATHS
            and all(_is_framework_route_bundle_path(path) for path in unique_paths)
            and direct_referrers / len(ordered_entries) >= ROTATING_UA_ROUTE_SPAM_DIRECT_RATIO
        )

        behavior_map[key] = {
            "request_count": len(ordered_entries),
            "unique_uas": len(unique_uas),
            "unique_paths": len(unique_paths),
            "route_bundle_paths": unique_paths,
            "route_bundle_spam": route_bundle_spam,
        }

    return behavior_map


def primary_navigation_event_ids_for_session(events: list[dict[str, Any]]) -> set[str]:
    trackable_events, page_events = path_events_for_session(events)
    source_events = compact_page_events_for_session(events) if page_events else trackable_events
    return {
        event["event_id"]
        for event in source_events
        if event.get("event_id")
    }


def page_sequence_for_events(events: list[dict[str, Any]]) -> list[str]:
    trackable_events, page_events = path_events_for_session(events)
    source_events = compact_page_events_for_session(events) if page_events else trackable_events
    return compress_consecutive([event["normalized_path"] for event in source_events])


def activity_sequence_for_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    trackable_events, _page_events = path_events_for_session(events)
    activity_sequence: list[dict[str, Any]] = []

    for index, event in enumerate(trackable_events):
        path = event["normalized_path"]
        route_kind = detect_route_kind(path)
        activity_sequence.append(
            {
                "id": hashlib.sha1(
                    f"{event['timestamp_iso']}|{path}|{route_kind}|{index}".encode("utf-8")
                ).hexdigest()[:16],
                "path": path,
                "route_kind": route_kind,
                "category": event["category"],
                "timestamp": event["timestamp_iso"],
                "timestamp_alberta": to_alberta_display(event["timestamp"]),
            }
        )

    return activity_sequence


def to_alberta_display(value: datetime) -> str:
    return value.astimezone(ALBERTA_ZONE).strftime("%Y-%m-%d %I:%M:%S %p")


def person_key_for_session(ip: str, ua: str | None) -> str:
    return f"{ip}|{(ua or '').lower()}"


def visitor_profile_id_for_person(person_key: str) -> str:
    return hashlib.sha1(person_key.encode("utf-8")).hexdigest()[:16]


def humanize_reason(reason: str) -> str:
    return REASON_LABELS.get(reason, reason.replace("_", " "))


def label_classification_state(state: str) -> str:
    labels = {
        "human_confirmed": "Confirmed Human",
        "likely_human": "Likely Human",
        "browser_script": "Browser Script",
        "script_burst": "Script Burst",
        "candidate": "Unclear",
        "bot": "Known Bot",
        "suspicious": "Suspicious",
        "archived": "Archived",
    }
    return labels.get(state, state.replace("_", " ").title())


def summarize_classification(state: str, human_confidence: int, suspicious_score: int) -> str:
    if state == "human_confirmed":
        return f"Traffic has strong enough depth, timing, and page-flow signals to treat this as a confirmed human session ({human_confidence}% confidence)."
    if state == "likely_human":
        return f"This still leans human at {human_confidence}% confidence, but the trail is not strong enough to call confirmed yet."
    if state == "browser_script":
        return "This looks browser-shaped, but the session is too thin or too patterned to trust as a real person. Treat it like likely scripted browsing."
    if state == "script_burst":
        return "Traffic collapsed a burst of near-identical one-hit browser sessions from many IPs into one script-burst card. Treat it as scripted or proxy fan-out, not separate people."
    if state == "candidate":
        return "Some human signals are present, but the evidence is mixed and Traffic is keeping the verdict conservative."
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


def build_single_session(
    events: list[dict[str, Any]],
    now: datetime | None = None,
    ip_behavior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if now is None:
        now = datetime.now(timezone.utc)
    if ip_behavior is None:
        ip_behavior = {}

    ordered_events = sort_session_events(events)
    first = ordered_events[0]
    last = ordered_events[-1]

    trackable_events, page_events = path_events_for_session(ordered_events)

    page_sequence = page_sequence_for_events(ordered_events)
    ordered_paths = ordered_unique(page_sequence)

    entry_page = page_sequence[0] if page_sequence else first["normalized_path"]
    current_page = page_sequence[-1] if page_sequence else last["normalized_path"]
    exit_page = current_page

    category_counter = Counter(event["category"] for event in events)
    route_counter = Counter(detect_route_kind(event["normalized_path"]) for event in trackable_events)

    suspicious_score = min(
        100,
        category_counter.get("suspicious", 0) * 35 + category_counter.get("bot", 0) * 8,
    )
    if ip_behavior.get("route_bundle_spam"):
        suspicious_score = max(suspicious_score, 92)

    engaged_seconds = 0
    total_seconds = 0

    for previous, current in zip(ordered_events, ordered_events[1:]):
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

    normalized_paths = {event["normalized_path"] for event in ordered_events}
    has_llama_chat_flow = (
        first["host"] == "llama-chat.tokentap.ca"
        and primary_category == "human"
        and suspicious_score == 0
        and "/" in page_sequence
        and any(
            path == "/api/chat/agents"
            or path == "/api/chat/send"
            or path.startswith("/api/chat/messages/")
            for path in normalized_paths
        )
    )
    if has_llama_chat_flow and len(events) >= 4:
        human_confidence = max(human_confidence, 82)
        for reason in ("llama_chat_flow", "meaningful_api_activity"):
            if reason not in classification_reasons:
                classification_reasons.append(reason)

    if ip_behavior.get("route_bundle_spam"):
        for reason in ("ua_rotation", "route_bundle_spam"):
            if reason not in classification_reasons:
                classification_reasons.append(reason)

    classification_state = classification_state_for_confidence(
        primary_category=primary_category,
        route_kind=route_kind,
        human_confidence=human_confidence,
        suspicious_score=suspicious_score,
    )

    idle_seconds = max(0, int((now - last["timestamp"]).total_seconds()))
    active_now = idle_seconds <= LIVE_ACTIVE_SECONDS

    known_automation = bool(automation_family(first["ua"]) or "")
    if not geo.get("geo_resolved", False):
        if "geo_unknown" not in classification_reasons:
            classification_reasons.append("geo_unknown")
        human_confidence = max(0, human_confidence - 4)

    looks_like_player_hop = _looks_like_player_page_hop(ordered_paths)
    if looks_like_player_hop and "player_page_hop" not in classification_reasons:
        classification_reasons.append("player_page_hop")
        human_confidence = max(0, human_confidence - 24)

    thin_browser_script = _looks_like_browser_script_session(
        primary_category=primary_category,
        route_kind=route_kind,
        source=source,
        page_sequence=ordered_paths,
        page_count=len(ordered_paths),
        event_count=len(events),
        engaged_seconds=engaged_seconds,
        total_seconds=total_seconds,
        known_automation=known_automation,
        active_now=active_now,
    )
    if thin_browser_script:
        for reason in ("thin_direct_browser", "browser_script_pattern"):
            if reason not in classification_reasons:
                classification_reasons.append(reason)
        human_confidence = max(0, human_confidence - 18)
        classification_state = "browser_script"
    else:
        classification_state = classification_state_for_confidence(
            primary_category=primary_category,
            route_kind=route_kind,
            human_confidence=human_confidence,
            suspicious_score=suspicious_score,
        )

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
    automation_label = automation_family(first["ua"]) or ""

    person_key = person_key_for_session(first["ip"], first["ua"])

    return {
        "session_id": session_id_for_events(events),
        "visitor_key": f"{first['host']}|{first['ip']}|{ua_lower}",
        "person_key": person_key,
        "visitor_profile_id": visitor_profile_id_for_person(person_key),
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
        "geo_resolved": bool(geo.get("geo_resolved", False)),
        "device": detect_device_type(first["ua"]),
        "os": detect_os(first["ua"]),
        "browser": detect_browser(first["ua"]),
        "known_automation": known_automation,
        "automation_family": automation_label,
        "route_bundle_spam": bool(ip_behavior.get("route_bundle_spam")),
        "network_ua_count": int(ip_behavior.get("unique_uas", 0)),
        "network_path_count": int(ip_behavior.get("unique_paths", 0)),
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
        "event_count": len(ordered_events),
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
        total_project_visits = project_counts[(person_key, session["project_slug"])]
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
        session["project_visits_in_window"] = total_project_visits
        session["total_project_visits"] = total_project_visits
        session["times_returned_in_project"] = max(total_project_visits - 1, 0)
        session["projects_visited_in_window"] = len(person_projects[person_key])
        session["returning_visitor"] = returning
        session["verdict_label"] = label_classification_state(session["classification_state"])
        session["classification_reason_labels"] = [
            humanize_reason(reason) for reason in session["classification_reasons"]
        ]
        if _is_known_singapore_43_fanout(session):
            session["classification_state"] = "browser_script"
            session["classification_reasons"] = ordered_unique(
                [*session.get("classification_reasons", []), "distributed_ip_burst", "one_hit_fanout", "thin_direct_browser"]
            )
            session["human_confidence"] = 0
            session["quality_score"] = min(safe_int(session.get("quality_score"), 0), 10)
            session["quality_label"] = "weak"
            session["primary_category"] = "suspicious"
            session["suspicious_score"] = max(safe_int(session.get("suspicious_score"), 0), 76)
            session["visitor_alias"] = f"Singapore43Script-{session.get('ip', '').split('.')[-1] or 'IP'}"
            session["classification_summary"] = (
                "This is a thin one-hit Windows Chrome session from the recurring Singapore 43.x fanout range. "
                "Treat it as scripted browsing unless it later shows real journey depth."
            )
            session["attention_label"] = "Script watch"
            session["attention_summary"] = "Known Singapore 43.x one-hit fanout pattern."
        elif session.get("is_burst_cluster") or session["classification_state"] == "script_burst":
            ip_count = safe_int(session.get("burst_ip_count"), 0)
            path_count = safe_int(session.get("burst_path_count"), 0)
            window_seconds = safe_int(session.get("burst_window_seconds"), 0)
            session["visitor_alias"] = (
                f"{(session.get('city') or session.get('area') or session.get('country') or 'Unknown').replace(' ', '')}"
                f"ScriptBurst-{ip_count}IPs"
            )
            session["classification_summary"] = (
                f"Collapsed {ip_count} near-identical one-hit browser sessions across "
                f"{path_count} routes inside {window_seconds}s. This is almost certainly scripted "
                "or proxy fan-out, not separate people."
            )
            session["attention_label"] = "Investigate"
            session["attention_summary"] = (
                "Traffic collapsed this swarm so it does not inflate the people feed."
            )
        elif session["known_automation"] and session["classification_state"] == "bot":
            family = session["automation_family"] or "Known automation"
            session["classification_summary"] = (
                f"Recognized {family} automation. This looks like a crawler, preview, or proxy "
                "fetch rather than a real person moving through the site."
            )
            session["attention_label"] = "Background"
            session["attention_summary"] = (
                f"{family} is known automation. Keep it available for context, but it usually "
                "does not need the same attention as suspicious traffic."
            )
        elif session.get("route_bundle_spam"):
            session["classification_summary"] = (
                f"One IP rotated through {session.get('network_ua_count', 0)} browser fingerprints "
                f"across a tiny repeated route bundle ({session.get('network_path_count', 0)} paths) "
                "with direct referrers, which strongly suggests scripted framework probing rather than a real visitor journey."
            )
            session["attention_label"] = "Investigate"
            session["attention_summary"] = (
                "This looks like coordinated scripted traffic from one source, not a person naturally browsing the site."
            )
        elif session["classification_state"] == "browser_script":
            session["classification_summary"] = summarize_classification(
                session["classification_state"],
                session["human_confidence"],
                session["suspicious_score"],
            )
            session["attention_label"] = "Watch"
            session["attention_summary"] = (
                "Traffic sees browser-shaped movement here, but the trail is too thin or too patterned to trust as a real visitor yet."
            )
        else:
            session["classification_summary"] = summarize_classification(
                session["classification_state"],
                session["human_confidence"],
                session["suspicious_score"],
            )
            session["attention_label"] = attention_label
            session["attention_summary"] = attention_summary
        session["data_confidence_label"] = data_label
        session["data_confidence_summary"] = data_summary


def build_sessions(recent_entries: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    ip_behavior_map = build_ip_behavior_map(recent_entries)

    for events in split_session_events(recent_entries):
        first = events[0]
        sessions.append(
            build_single_session(
                events,
                now=now,
                ip_behavior=ip_behavior_map.get((first["host"], first["ip"])),
            )
        )

    sessions = collapse_distributed_bursts(sessions)
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
        ordered_events = sort_session_events(session_entries)
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
    if state in {"browser_script", "script_burst"}:
        return 4
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
