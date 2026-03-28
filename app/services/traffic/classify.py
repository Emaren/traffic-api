from __future__ import annotations

from app.services.traffic.config import (
    API_ROUTE_PREFIXES,
    ASSET_EXTENSIONS,
    BOT_TERMS,
    BROWSER_TERMS,
    SUSPICIOUS_PATH_REGEXES,
    SUSPICIOUS_PATH_SNIPPETS,
    SUSPICIOUS_UA_TERMS,
)


def is_suspicious_path(path: str | None) -> bool:
    lowered = (path or "").lower()
    if any(snippet in lowered for snippet in SUSPICIOUS_PATH_SNIPPETS):
        return True
    return any(pattern.search(lowered) for pattern in SUSPICIOUS_PATH_REGEXES)


def detect_route_kind(path: str | None) -> str:
    lowered = (path or "").lower()

    if lowered in {"", "(unknown)"}:
        return "unknown"
    if is_suspicious_path(lowered):
        return "probe"
    if any(lowered.startswith(prefix) for prefix in API_ROUTE_PREFIXES):
        return "api"
    if any(lowered.endswith(ext) for ext in ASSET_EXTENSIONS):
        return "asset"
    return "page"


def is_trackable_path(path: str | None) -> bool:
    return detect_route_kind(path) in {"page", "api", "probe"}


def classify_request(ua: str | None, path: str | None) -> str:
    lowered_ua = (ua or "").lower()

    if is_suspicious_path(path):
        return "suspicious"
    if any(term in lowered_ua for term in BOT_TERMS):
        return "bot"
    if any(term in lowered_ua for term in SUSPICIOUS_UA_TERMS):
        return "suspicious"
    if any(term in lowered_ua for term in BROWSER_TERMS):
        return "human"
    return "unknown"


def detect_device_type(ua: str | None) -> str:
    lowered = (ua or "").lower()

    if any(term in lowered for term in BOT_TERMS + SUSPICIOUS_UA_TERMS):
        return "script"
    if "ipad" in lowered or "tablet" in lowered:
        return "tablet"
    if any(term in lowered for term in ("iphone", "android", "mobile")):
        return "mobile"
    return "desktop"


def detect_os(ua: str | None) -> str:
    lowered = (ua or "").lower()

    if "iphone" in lowered or "ipad" in lowered or "ios" in lowered:
        return "iOS"
    if "android" in lowered:
        return "Android"
    if "windows" in lowered:
        return "Windows"
    if "mac os x" in lowered or "macintosh" in lowered:
        return "macOS"
    if "linux" in lowered:
        return "Linux"
    return "Unknown"


def detect_browser(ua: str | None) -> str:
    lowered = (ua or "").lower()

    if "googleother" in lowered:
        return "GoogleOther"
    if "googlebot" in lowered:
        return "Googlebot"
    if "edg/" in lowered or " edge" in lowered:
        return "Edge"
    if "chrome/" in lowered and "chromium" not in lowered and "edg/" not in lowered:
        return "Chrome"
    if "firefox/" in lowered:
        return "Firefox"
    if "safari/" in lowered and "chrome/" not in lowered:
        return "Safari"
    if "curl" in lowered:
        return "curl"
    if "wget" in lowered:
        return "wget"
    if "twitterbot" in lowered:
        return "Twitterbot"
    return "Unknown"


def compute_quality_score(
    *,
    primary_category: str,
    route_kind: str,
    page_count: int,
    event_count: int,
    total_seconds: int,
    engaged_seconds: int,
    suspicious_score: int,
    source: str,
    medium: str,
) -> int:
    score = 0

    if primary_category == "human":
        score += 35
    elif primary_category == "unknown":
        score += 8
    elif primary_category == "bot":
        score -= 18
    else:
        score -= 35

    if route_kind == "page":
        score += 28
    elif route_kind == "api":
        score += 6
    elif route_kind == "probe":
        score -= 40
    elif route_kind == "asset":
        score -= 25

    score += min(page_count * 4, 20)
    score += min(event_count * 2, 18)
    score += min(engaged_seconds // 30, 18)
    score += min(total_seconds // 60, 12)

    if source in {"google", "bing", "x", "facebook"}:
        score += 6
    elif medium in {"organic", "referral", "campaign", "email", "social"} and source not in {"direct", "internal"}:
        score += 4

    if source == "internal":
        score -= 8

    if page_count <= 1 and event_count <= 1 and engaged_seconds == 0:
        score -= 50

    if suspicious_score >= 40:
        score -= 35
    elif suspicious_score > 0:
        score -= 10

    return max(0, min(100, score))


def quality_label_for_score(score: int) -> str:
    if score >= 80:
        return "strong"
    if score >= 55:
        return "good"
    if score >= 30:
        return "thin"
    return "weak"


def compute_human_confidence(
    *,
    primary_category: str,
    route_kind: str,
    page_count: int,
    event_count: int,
    total_seconds: int,
    engaged_seconds: int,
    suspicious_score: int,
    source: str,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if primary_category == "human":
        score += 40
        reasons.append("browser_ua")
    elif primary_category == "unknown":
        score += 8
        reasons.append("unknown_ua")
    elif primary_category == "bot":
        score -= 40
        reasons.append("bot_signal")
    else:
        score -= 60
        reasons.append("suspicious_signal")

    if route_kind == "page":
        score += 20
        reasons.append("page_route")
    elif route_kind == "api":
        score += 4
        reasons.append("api_route")
    elif route_kind == "probe":
        score -= 70
        reasons.append("probe_route")
    elif route_kind == "asset":
        score -= 15
        reasons.append("asset_only")

    if page_count >= 3:
        score += 20
        reasons.append("multi_page")
    elif page_count == 2:
        score += 12
        reasons.append("multi_page")
    elif page_count == 1:
        score += 4
        reasons.append("single_page")

    if event_count >= 4:
        score += 10
        reasons.append("repeat_activity")
    elif event_count >= 2:
        score += 4
        reasons.append("repeat_activity")

    if engaged_seconds >= 20:
        score += 15
        reasons.append("engaged")
    elif engaged_seconds > 0:
        score += 6
        reasons.append("brief_engagement")

    if source == "internal":
        score -= 18
        reasons.append("internal_referrer")
    elif source in {"google", "bing", "x", "facebook"}:
        score += 6
        reasons.append("external_source")
    elif source == "direct":
        score += 4
        reasons.append("direct")

    if suspicious_score >= 40:
        score -= 60
        reasons.append("high_suspicion")
    elif suspicious_score > 0:
        score -= 18
        reasons.append("low_suspicion")

    if page_count == 0 and route_kind == "api":
        score -= 20
        reasons.append("api_only")

    if total_seconds == 0 and event_count <= 1:
        score -= 15
        reasons.append("bounce")

    return max(0, min(100, score)), reasons


def classification_state_for_confidence(
    *,
    primary_category: str,
    route_kind: str,
    human_confidence: int,
    suspicious_score: int,
) -> str:
    if primary_category == "suspicious" or route_kind == "probe" or suspicious_score >= 70:
        return "suspicious"
    if primary_category == "bot":
        return "bot"
    if human_confidence >= 75:
        return "human_confirmed"
    if human_confidence >= 45:
        return "likely_human"
    return "candidate"


def compute_live_priority(
    *,
    human_confidence: int,
    engaged_seconds: int,
    page_count: int,
    event_count: int,
    idle_seconds: int,
    suspicious_score: int,
    active_now: bool,
) -> int:
    priority = 0
    priority += human_confidence * 50
    priority += min(engaged_seconds, 600)
    priority += page_count * 20
    priority += event_count * 4
    priority -= suspicious_score * 5
    priority -= min(idle_seconds, 1800)

    if active_now:
        priority += 250

    return max(0, int(priority))
