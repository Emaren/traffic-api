from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse, urlsplit

try:
    from geoip2.database import Reader as GeoIPReader
    from geoip2.errors import AddressNotFoundError
except Exception:  # pragma: no cover
    GeoIPReader = None  # type: ignore[assignment]
    AddressNotFoundError = Exception  # type: ignore[assignment]

LOG_PATH = Path(os.getenv("TRAFFIC_LOG_PATH", "runtime/dev_access.log"))
GEOIP_DB_PATH = Path(os.getenv("TRAFFIC_GEOIP_DB_PATH", "runtime/geoip/GeoLite2-City.mmdb"))
TAIL_LINES = int(os.getenv("TRAFFIC_TAIL_LINES", "5000"))
SESSION_GAP_MINUTES = int(os.getenv("TRAFFIC_SESSION_GAP_MINUTES", "30"))
ACTIVE_GAP_CAP_SECONDS = int(os.getenv("TRAFFIC_SESSION_ACTIVE_GAP_CAP_SECONDS", "300"))
VISITOR_SESSION_LIMIT = int(os.getenv("TRAFFIC_VISITOR_SESSION_LIMIT", "50"))
TOP_LIMIT = int(os.getenv("TRAFFIC_TOP_LIMIT", "10"))

LEGACY_LOG_LINE_RE = re.compile(
    r'(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+\S+\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

BOT_TERMS = [
    "bot",
    "crawl",
    "crawler",
    "spider",
    "censys",
    "zgrab",
    "uptimerobot",
    "googlebot",
    "bingbot",
    "bingpreview",
    "duckduckbot",
    "facebookexternalhit",
    "slurp",
    "twitterbot",
]

SUSPICIOUS_UA_TERMS = [
    "curl",
    "wget",
    "python",
    "scrapy",
    "nikto",
    "sqlmap",
    "masscan",
    "go-http-client",
    "nmap",
    "scanner",
]

BROWSER_TERMS = [
    "mozilla",
    "chrome",
    "safari",
    "firefox",
    "edge",
    "opera",
]

SUSPICIOUS_PATH_SNIPPETS = [
    ".env",
    "wlwmanifest.xml",
    "xmlrpc.php",
    "wp-includes",
    "/wordpress",
    "/blog/wp-",
    "/storage/logs",
    "laravel",
    ".git",
    "phpmyadmin",
    "/boaform",
    "/cgi-bin",
    "/actuator",
    "production.key",
    "mail.log",
    "email.log",
    ".aws/",
    ".msmtprc",
    ".muttrc",
    ".directadmin",
    ".cpanel",
    ".plesk",
    "/wp-content/plugins/",
    "wp_filemanager.php",
    "/vendor/phpunit/",
    "/server-status",
    "/hnap1",
]

SUSPICIOUS_PATH_REGEXES = [
    re.compile(r"/wp-content/plugins/.+\.php(?:$|\?)", re.IGNORECASE),
    re.compile(r"/wp-admin(?:/|$)", re.IGNORECASE),
    re.compile(r"/wp-login\.php(?:$|\?)", re.IGNORECASE),
    re.compile(r"/xmlrpc\.php(?:$|\?)", re.IGNORECASE),
    re.compile(r"/phpmyadmin(?:/|$)", re.IGNORECASE),
    re.compile(r"/boaform/", re.IGNORECASE),
    re.compile(r"/cgi-bin/", re.IGNORECASE),
    re.compile(r"/vendor/phpunit/", re.IGNORECASE),
]

ASSET_EXTENSIONS = (
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".txt",
    ".xml",
    ".json",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".mp4",
    ".webm",
    ".mp3",
    ".wav",
)

API_ROUTE_PREFIXES = (
    "/api/",
    "/graphql",
    "/rpc",
    "/rest",
    "/_next/data/",
)

UNKNOWN_HOST = "(unknown host)"
UNKNOWN_REFERRER = "(direct)"

PROJECTS = [
    {
        "slug": "aoe2hdbets",
        "name": "AoE2HDBets",
        "category": "gaming",
        "hosts": ["aoe2hdbets.com", "www.aoe2hdbets.com"],
    },
    {
        "slug": "tokentap",
        "name": "TokenTap",
        "category": "loyalty",
        "hosts": ["tokentap.ca", "www.tokentap.ca"],
    },
    {
        "slug": "wheatandstone",
        "name": "Wheat & Stone",
        "category": "content",
        "hosts": ["wheatandstone.ca", "www.wheatandstone.ca"],
    },
    {
        "slug": "tmail",
        "name": "TMail",
        "category": "email",
        "hosts": ["tmail.tokentap.ca"],
    },
    {
        "slug": "pulse",
        "name": "Pulse",
        "category": "campaigns",
        "hosts": ["pulse.tokentap.ca"],
    },
    {
        "slug": "vps-sentry",
        "name": "VPSSentry",
        "category": "security",
        "hosts": ["vps-sentry.tokentap.ca"],
    },
    {
        "slug": "traffic",
        "name": "Traffic",
        "category": "analytics",
        "hosts": ["traffic.tokentap.ca"],
    },
]

PROJECT_INDEX = {host: project for project in PROJECTS for host in project["hosts"]}

DEFAULT_ALLOWED_HOSTS = (
    "traffic.tokentap.ca",
    "tokentap.ca",
    "www.tokentap.ca",
    "aoe2hdbets.com",
    "www.aoe2hdbets.com",
    "wheatandstone.ca",
    "www.wheatandstone.ca",
    "vps-sentry.tokentap.ca",
    "pulse.tokentap.ca",
    "tmail.tokentap.ca",
)


def parse_csv_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default

    values = []
    for item in raw.split(","):
        value = normalize_host(item.strip())
        if value and value != UNKNOWN_HOST:
            values.append(value)

    return tuple(values) if values else default


ALLOWED_HOSTS = set(parse_csv_env("TRAFFIC_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS))


def is_allowed_host(host: str | None) -> bool:
    normalized = normalize_host(host)
    if normalized == UNKNOWN_HOST:
        return False
    return normalized in ALLOWED_HOSTS

CANONICAL_HOST_MAP = {
    "www.aoe2hdbets.com": "aoe2hdbets.com",
    "www.tokentap.ca": "tokentap.ca",
    "www.wheatandstone.ca": "wheatandstone.ca",
}

INTERNAL_IGNORE_PATHS = {
    "/api/status",
    "/api/readyz",
    "/healthz",
}

DEV_GEO_OVERRIDES = {
    "216.127.43.12": {"country": "Canada", "area": "Alberta", "city": "Grande Prairie"},
    "216.127.43.99": {"country": "Canada", "area": "Alberta", "city": "Grande Prairie"},
    "142.114.91.44": {"country": "Canada", "area": "Alberta", "city": "Edmonton"},
    "72.21.81.200": {"country": "United States", "area": "Washington", "city": "Seattle"},
    "45.61.188.33": {"country": "United States", "area": "Texas", "city": "Dallas"},
    "185.12.44.91": {"country": "Germany", "area": "Hesse", "city": "Frankfurt"},
    "45.146.130.12": {"country": "Netherlands", "area": "North Holland", "city": "Amsterdam"},
    "103.77.204.9": {"country": "Singapore", "area": "Singapore", "city": "Singapore"},
}

_GEOIP_READER: Any | None = None
_GEOIP_READER_PATH: Path | None = None
_GEO_LOOKUP_CACHE: dict[str, dict[str, str]] = {}


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except Exception:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_log_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except Exception:
        return None


def normalize_host(value: str | None) -> str:
    if not value or value == "-":
        return UNKNOWN_HOST

    host = value.strip().lower()

    if "://" in host:
        try:
            parsed = urlparse(host)
            host = parsed.netloc or host
        except Exception:
            pass

    if host.endswith(":80"):
        host = host[:-3]
    elif host.endswith(":443"):
        host = host[:-4]

    host = CANONICAL_HOST_MAP.get(host, host)
    return host or UNKNOWN_HOST


def normalize_path(raw_path: str | None) -> str:
    if not raw_path:
        return "(unknown)"

    try:
        parsed = urlsplit(raw_path)
        return parsed.path or "/"
    except Exception:
        return raw_path or "(unknown)"


def normalize_referrer(referrer: str | None) -> str:
    if not referrer or referrer == "-":
        return UNKNOWN_REFERRER

    try:
        parsed = urlparse(referrer)
        return normalize_host(parsed.netloc or referrer)
    except Exception:
        return normalize_host(referrer)


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


def read_recent_log_lines(path: Path, tail_lines: int) -> list[str]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return list(deque(handle, maxlen=tail_lines))


def parse_json_log_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        return None

    try:
        payload = json.loads(stripped)
    except Exception:
        return None

    parsed_timestamp = parse_iso_timestamp(str(payload.get("ts") or ""))
    if not parsed_timestamp:
        return None

    method = str(payload.get("method") or "").upper() or "(unknown)"
    raw_path = str(payload.get("request_uri") or payload.get("uri") or "(unknown)")

    return {
        "ip": str(payload.get("remote_addr") or ""),
        "timestamp": parsed_timestamp,
        "timestamp_iso": parsed_timestamp.isoformat(),
        "request": str(payload.get("request") or ""),
        "method": method,
        "raw_path": raw_path,
        "normalized_path": normalize_path(raw_path),
        "status": safe_int(payload.get("status")),
        "referrer": str(payload.get("referrer") or "-"),
        "referrer_host": normalize_referrer(str(payload.get("referrer") or "-")),
        "ua": str(payload.get("user_agent") or ""),
        "host": normalize_host(str(payload.get("host") or payload.get("server_name") or UNKNOWN_HOST)),
        "raw": line.rstrip("\n"),
    }


def parse_legacy_log_line(line: str) -> dict[str, Any] | None:
    match = LEGACY_LOG_LINE_RE.match(line)
    if not match:
        return None

    parsed_timestamp = parse_log_timestamp(match.group("ts"))
    if not parsed_timestamp:
        return None

    request = match.group("request").strip()
    request_parts = request.split()
    method = request_parts[0].upper() if request_parts else "(unknown)"
    raw_path = request_parts[1] if len(request_parts) >= 2 else "(unknown)"

    return {
        "ip": match.group("ip"),
        "timestamp": parsed_timestamp,
        "timestamp_iso": parsed_timestamp.isoformat(),
        "request": request,
        "method": method,
        "raw_path": raw_path,
        "normalized_path": normalize_path(raw_path),
        "status": safe_int(match.group("status")),
        "referrer": match.group("referrer"),
        "referrer_host": normalize_referrer(match.group("referrer")),
        "ua": match.group("ua"),
        "host": UNKNOWN_HOST,
        "raw": line.rstrip("\n"),
    }


def parse_log_line(line: str) -> dict[str, Any] | None:
    return parse_json_log_line(line) or parse_legacy_log_line(line)


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
    if "googlebot" in lowered:
        return "Googlebot"
    if "twitterbot" in lowered:
        return "Twitterbot"
    return "Unknown"


def ordered_unique(values: list[str]) -> list[str]:
    seen = set()
    output = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)

    return output


def get_geo_reader() -> Any | None:
    global _GEOIP_READER, _GEOIP_READER_PATH

    if GeoIPReader is None:
        return None

    if _GEOIP_READER is not None and _GEOIP_READER_PATH == GEOIP_DB_PATH:
        return _GEOIP_READER

    if not GEOIP_DB_PATH.exists():
        return None

    try:
        if _GEOIP_READER is not None:
            try:
                _GEOIP_READER.close()
            except Exception:
                pass

        _GEOIP_READER = GeoIPReader(str(GEOIP_DB_PATH))
        _GEOIP_READER_PATH = GEOIP_DB_PATH
        return _GEOIP_READER
    except Exception:
        _GEOIP_READER = None
        _GEOIP_READER_PATH = None
        return None


def get_geo_details(ip: str) -> dict[str, str]:
    if ip in _GEO_LOOKUP_CACHE:
        return _GEO_LOOKUP_CACHE[ip]

    if ip in DEV_GEO_OVERRIDES:
        _GEO_LOOKUP_CACHE[ip] = DEV_GEO_OVERRIDES[ip]
        return DEV_GEO_OVERRIDES[ip]

    reader = get_geo_reader()
    if reader is not None:
        try:
            response = reader.city(ip)

            country = (
                response.country.name
                or response.registered_country.name
                or response.country.iso_code
                or response.registered_country.iso_code
                or "??"
            )

            area = ""
            if response.subdivisions and response.subdivisions.most_specific:
                area = (
                    response.subdivisions.most_specific.name
                    or response.subdivisions.most_specific.iso_code
                    or ""
                )

            city = response.city.name or ""

            result = {
                "country": country,
                "area": area,
                "city": city,
            }
            _GEO_LOOKUP_CACHE[ip] = result
            return result
        except AddressNotFoundError:
            pass
        except ValueError:
            pass
        except Exception:
            pass

    result = {"country": "??", "area": "", "city": ""}
    _GEO_LOOKUP_CACHE[ip] = result
    return result


def project_for_host(host: str) -> dict[str, Any]:
    normalized = normalize_host(host)

    if normalized in PROJECT_INDEX:
        return PROJECT_INDEX[normalized]

    for project in PROJECTS:
        for known_host in project["hosts"]:
            if normalized == known_host or normalized.endswith("." + known_host):
                return project

    return {"slug": "unknown", "name": "Unknown", "category": "unknown", "hosts": []}


def is_internal_referrer(host: str, referrer_host: str) -> bool:
    if referrer_host in {UNKNOWN_REFERRER, "", UNKNOWN_HOST}:
        return False

    normalized_host = normalize_host(host)
    normalized_referrer = normalize_host(referrer_host)

    if normalized_host == normalized_referrer:
        return True

    return project_for_host(normalized_host)["slug"] == project_for_host(normalized_referrer)["slug"]


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


def build_single_session(events: list[dict[str, Any]]) -> dict[str, Any]:
    first = events[0]
    last = events[-1]

    trackable_events = [event for event in events if is_trackable_path(event["normalized_path"])]
    ordered_paths = ordered_unique([event["normalized_path"] for event in trackable_events])[:20]

    entry_page = ordered_paths[0] if ordered_paths else first["normalized_path"]
    next_page = ordered_paths[1] if len(ordered_paths) > 1 else ""
    exit_page = ordered_paths[-1] if ordered_paths else last["normalized_path"]

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

    return {
        "session_id": f"{first['host']}|{first['ip']}|{first['timestamp_iso']}",
        "project_slug": project["slug"],
        "host": first["host"],
        "started_at": first["timestamp_iso"],
        "ended_at": last["timestamp_iso"],
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
        "next_page": next_page,
        "exit_page": exit_page,
        "page_count": len(ordered_paths),
        "event_count": len(events),
        "total_seconds": total_seconds,
        "engaged_seconds": engaged_seconds,
        "suspicious_score": suspicious_score,
        "primary_category": primary_category,
        "route_kind": route_kind,
        "quality_score": quality_score,
        "quality_label": quality_label_for_score(quality_score),
    }


def build_sessions(recent_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for entry in recent_entries:
        host = entry["host"]
        if host == UNKNOWN_HOST:
            continue

        visitor_key = (host, entry["ip"], (entry["ua"] or "").lower())
        grouped[visitor_key].append(entry)

    session_gap_seconds = SESSION_GAP_MINUTES * 60
    sessions = []

    for _, events in grouped.items():
        ordered_events = sorted(events, key=lambda item: item["timestamp"])
        current_session: list[dict[str, Any]] = []

        for event in ordered_events:
            if not current_session:
                current_session = [event]
                continue

            gap = int((event["timestamp"] - current_session[-1]["timestamp"]).total_seconds())
            if gap > session_gap_seconds:
                sessions.append(build_single_session(current_session))
                current_session = [event]
            else:
                current_session.append(event)

        if current_session:
            sessions.append(build_single_session(current_session))

    sessions.sort(key=lambda item: item["ended_at"], reverse=True)
    return sessions[:VISITOR_SESSION_LIMIT]


def build_path_stats(recent_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

    output = []

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
    primary_category = session.get("primary_category", "unknown")
    route_kind = session.get("route_kind", "unknown")
    quality_score = safe_int(session.get("quality_score"), 0)

    if primary_category == "human" and route_kind == "page" and quality_score >= 55:
        return 0
    if primary_category == "human" and route_kind == "page":
        return 1
    if primary_category == "human" and route_kind == "api":
        return 2
    if primary_category == "unknown" and route_kind == "page":
        return 3
    if route_kind == "probe":
        return 6
    if primary_category == "bot":
        return 5
    return 4


def session_sort_key(session: dict[str, Any]) -> tuple[int, int, float]:
    parsed = parse_iso_timestamp(session.get("ended_at"))
    ts = parsed.timestamp() if parsed else 0.0
    quality_score = safe_int(session.get("quality_score"), 0)
    suspicious_score = safe_int(session.get("suspicious_score"), 0)

    return (
        session_bucket(session),
        -quality_score,
        suspicious_score,
        -ts,
    )


def build_overview() -> dict[str, Any]:
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    lines = read_recent_log_lines(LOG_PATH, TAIL_LINES)

    recent_entries = []
    host_request_counter = Counter()
    project_request_counter = Counter()
    project_session_counter = Counter()
    project_engaged_counter = Counter()
    project_suspicious_counter = Counter()
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

    for line in lines:
        parsed = parse_log_line(line)
        if not parsed:
            continue

        if not is_allowed_host(parsed["host"]):
            continue

        if parsed["timestamp"] < day_ago:
            continue

        category = classify_request(parsed["ua"], parsed["normalized_path"])
        route_kind = detect_route_kind(parsed["normalized_path"])

        parsed["category"] = category
        parsed["route_kind"] = route_kind
        recent_entries.append(parsed)

        total_requests += 1
        unique_visitors.add((parsed["host"], parsed["ip"], (parsed["ua"] or "").lower()))
        host_request_counter[parsed["host"]] += 1
        host_visitors[parsed["host"]].add(parsed["ip"])

        project = project_for_host(parsed["host"])
        project_request_counter[project["slug"]] += 1

        top_ip_counter[parsed["ip"]] += 1
        top_ip_category[parsed["ip"]] = category
        top_ip_last_seen[parsed["ip"]] = parsed["timestamp_iso"]

        if category == "human":
            human_requests += 1
            host_humans[parsed["host"]] += 1
        elif category == "bot":
            bot_requests += 1
            host_bots[parsed["host"]] += 1
        elif category == "suspicious":
            suspicious_requests += 1
            host_suspicious[parsed["host"]] += 1
            suspicious_path_counter[parsed["normalized_path"]] += 1
        else:
            unknown_requests += 1

    sessions = build_sessions(recent_entries)

    for session in sessions:
        project_session_counter[session["project_slug"]] += 1

        if session["engaged_seconds"] > 0:
            project_engaged_counter[session["project_slug"]] += 1

        if session["suspicious_score"] >= 40:
            project_suspicious_counter[session["project_slug"]] += 1

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

    projects = []

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
                "suspicious": project_suspicious_counter[slug],
            }
        )

    projects.sort(key=lambda row: row["requests"], reverse=True)

    hosts = []

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

    suspicious_top_ips = []

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

    alerts = []

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

    avg_session_seconds = (
        int(sum(session["total_seconds"] for session in sessions) / len(sessions)) if sessions else 0
    )
    avg_page_seconds = (
        int(sum(page["avg_seconds"] for page in top_pages) / len(top_pages)) if top_pages else 0
    )

    notes = [
        "Phase 2 donor parser is live.",
        "This view is now built from log lines, not seeded demo data.",
        f"Current source log: {LOG_PATH}",
        f"Host allowlist live: {len(ALLOWED_HOSTS)} approved hosts.",
    ]

    if GEOIP_DB_PATH.exists():
        notes.append(f"GeoIP DB loaded: {GEOIP_DB_PATH}")
    else:
        notes.append(f"GeoIP DB missing: {GEOIP_DB_PATH}")

    notes.append("Route classification is live: page, api, probe, asset.")
    notes.append("Quality mode is live: exploit probes, internal referrers, session quality scoring.")

    return {
        "ok": True,
        "generated_at": iso_now(),
        "window": "24h",
        "totals": {
            "requests": total_requests,
            "humans": human_requests,
            "bots": bot_requests,
            "suspicious": suspicious_requests,
            "unknown": unknown_requests,
            "unique_visitors": len(unique_visitors),
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