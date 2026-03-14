from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI

app = FastAPI(title="Traffic API", version="0.1.0")


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_overview() -> dict[str, Any]:
    generated_at = iso_now()

    projects = [
        {
            "slug": "aoe2hdbets",
            "name": "AoE2HDBets",
            "category": "gaming",
            "requests": 6284,
            "sessions": 842,
            "engaged_sessions": 511,
            "suspicious": 143,
        },
        {
            "slug": "tokentap",
            "name": "TokenTap",
            "category": "loyalty",
            "requests": 2910,
            "sessions": 407,
            "engaged_sessions": 238,
            "suspicious": 61,
        },
        {
            "slug": "wheatandstone",
            "name": "Wheat & Stone",
            "category": "content",
            "requests": 1742,
            "sessions": 266,
            "engaged_sessions": 151,
            "suspicious": 22,
        },
        {
            "slug": "tmail",
            "name": "TMail",
            "category": "email",
            "requests": 961,
            "sessions": 133,
            "engaged_sessions": 74,
            "suspicious": 11,
        },
        {
            "slug": "pulse",
            "name": "Pulse",
            "category": "campaigns",
            "requests": 712,
            "sessions": 92,
            "engaged_sessions": 49,
            "suspicious": 8,
        },
        {
            "slug": "vps-sentry",
            "name": "VPSSentry",
            "category": "security",
            "requests": 1488,
            "sessions": 181,
            "engaged_sessions": 98,
            "suspicious": 117,
        },
        {
            "slug": "traffic",
            "name": "Traffic",
            "category": "analytics",
            "requests": 203,
            "sessions": 31,
            "engaged_sessions": 19,
            "suspicious": 2,
        },
    ]

    hosts = [
        {
            "host": "aoe2hdbets.com",
            "project_slug": "aoe2hdbets",
            "requests": 5400,
            "unique_visitors": 821,
            "sessions": 1008,
            "human_requests": 1234,
            "bot_requests": 4017,
            "suspicious_requests": 149,
            "top_entry_page": "/",
            "top_exit_page": "/watch",
            "avg_session_seconds": 174,
        },
        {
            "host": "tokentap.ca",
            "project_slug": "tokentap",
            "requests": 2910,
            "unique_visitors": 404,
            "sessions": 407,
            "human_requests": 1098,
            "bot_requests": 1751,
            "suspicious_requests": 61,
            "top_entry_page": "/",
            "top_exit_page": "/wallet",
            "avg_session_seconds": 162,
        },
        {
            "host": "wheatandstone.ca",
            "project_slug": "wheatandstone",
            "requests": 1742,
            "unique_visitors": 258,
            "sessions": 266,
            "human_requests": 901,
            "bot_requests": 819,
            "suspicious_requests": 22,
            "top_entry_page": "/",
            "top_exit_page": "/about",
            "avg_session_seconds": 211,
        },
        {
            "host": "tmail.tokentap.ca",
            "project_slug": "tmail",
            "requests": 961,
            "unique_visitors": 131,
            "sessions": 133,
            "human_requests": 523,
            "bot_requests": 427,
            "suspicious_requests": 11,
            "top_entry_page": "/",
            "top_exit_page": "/dashboard",
            "avg_session_seconds": 148,
        },
        {
            "host": "vps-sentry.tokentap.ca",
            "project_slug": "vps-sentry",
            "requests": 1488,
            "unique_visitors": 178,
            "sessions": 181,
            "human_requests": 622,
            "bot_requests": 749,
            "suspicious_requests": 117,
            "top_entry_page": "/",
            "top_exit_page": "/incidents",
            "avg_session_seconds": 133,
        },
    ]

    recent_sessions = [
        {
            "session_id": "sess_aoe2_001",
            "project_slug": "aoe2hdbets",
            "host": "aoe2hdbets.com",
            "started_at": generated_at,
            "ended_at": generated_at,
            "country": "Canada",
            "area": "Alberta",
            "city": "Grande Prairie",
            "device": "desktop",
            "os": "macOS",
            "browser": "Chrome",
            "referrer": "https://x.com/",
            "source": "x",
            "medium": "social",
            "campaign": "aoe2-launch-1",
            "entry_page": "/",
            "next_page": "/watch",
            "exit_page": "/profile",
            "page_count": 4,
            "event_count": 7,
            "total_seconds": 461,
            "engaged_seconds": 392,
            "suspicious_score": 0,
        },
        {
            "session_id": "sess_ws_002",
            "project_slug": "wheatandstone",
            "host": "wheatandstone.ca",
            "started_at": generated_at,
            "ended_at": generated_at,
            "country": "Canada",
            "area": "Alberta",
            "city": "Edmonton",
            "device": "mobile",
            "os": "iOS",
            "browser": "Safari",
            "referrer": "https://www.google.com/",
            "source": "google",
            "medium": "organic",
            "campaign": "",
            "entry_page": "/",
            "next_page": "/about",
            "exit_page": "/marketplace",
            "page_count": 3,
            "event_count": 4,
            "total_seconds": 244,
            "engaged_seconds": 196,
            "suspicious_score": 0,
        },
        {
            "session_id": "sess_tt_003",
            "project_slug": "tokentap",
            "host": "tokentap.ca",
            "started_at": generated_at,
            "ended_at": generated_at,
            "country": "United States",
            "area": "Texas",
            "city": "Dallas",
            "device": "desktop",
            "os": "Windows",
            "browser": "Edge",
            "referrer": "https://mail.google.com/",
            "source": "email",
            "medium": "campaign",
            "campaign": "spring-loyalty-pilot",
            "entry_page": "/",
            "next_page": "/wallet",
            "exit_page": "/businesses",
            "page_count": 5,
            "event_count": 8,
            "total_seconds": 508,
            "engaged_seconds": 433,
            "suspicious_score": 0,
        },
        {
            "session_id": "sess_vs_004",
            "project_slug": "vps-sentry",
            "host": "vps-sentry.tokentap.ca",
            "started_at": generated_at,
            "ended_at": generated_at,
            "country": "Germany",
            "area": "Hesse",
            "city": "Frankfurt",
            "device": "script",
            "os": "Unknown",
            "browser": "curl",
            "referrer": "",
            "source": "direct",
            "medium": "unknown",
            "campaign": "",
            "entry_page": "/.env",
            "next_page": "/wp-login.php",
            "exit_page": "/xmlrpc.php",
            "page_count": 3,
            "event_count": 3,
            "total_seconds": 9,
            "engaged_seconds": 0,
            "suspicious_score": 97,
        },
    ]

    top_pages = [
        {
            "path": "/",
            "entries": 961,
            "views": 1622,
            "exits": 174,
            "avg_seconds": 46,
            "top_next_paths": [
                {"path": "/watch", "count": 210},
                {"path": "/wallet", "count": 144},
            ],
        },
        {
            "path": "/watch",
            "entries": 220,
            "views": 488,
            "exits": 63,
            "avg_seconds": 83,
            "top_next_paths": [
                {"path": "/profile", "count": 91},
                {"path": "/replay", "count": 48},
            ],
        },
        {
            "path": "/wallet",
            "entries": 144,
            "views": 301,
            "exits": 58,
            "avg_seconds": 67,
            "top_next_paths": [
                {"path": "/businesses", "count": 77},
                {"path": "/wally", "count": 39},
            ],
        },
        {
            "path": "/about",
            "entries": 92,
            "views": 190,
            "exits": 29,
            "avg_seconds": 58,
            "top_next_paths": [
                {"path": "/marketplace", "count": 66},
            ],
        },
    ]

    alerts = [
        {
            "severity": "high",
            "title": "Probe spike on vps-sentry.tokentap.ca",
            "count": 43,
        },
        {
            "severity": "medium",
            "title": "Bot-heavy traffic on aoe2hdbets.com",
            "count": 18,
        },
        {
            "severity": "low",
            "title": "Traffic shell still serving seeded demo data",
            "count": 1,
        },
    ]

    return {
        "ok": True,
        "generated_at": generated_at,
        "window": "24h",
        "totals": {
            "requests": 14300,
            "humans": 4879,
            "bots": 8266,
            "suspicious": 364,
            "unknown": 791,
            "unique_visitors": 1923,
            "sessions": 2957,
            "engaged_sessions": 1740,
            "avg_session_seconds": 171,
            "avg_page_seconds": 59,
        },
        "projects": projects,
        "hosts": hosts,
        "suspicious": {
            "top_paths": [
                {"path": "/.env", "count": 87},
                {"path": "/wp-login.php", "count": 51},
                {"path": "/xmlrpc.php", "count": 43},
                {"path": "/.git/config", "count": 29},
                {"path": "/boaform/admin/formLogin", "count": 11},
            ],
            "top_ips": [
                {
                    "ip": "185.12.44.91",
                    "country": "Germany",
                    "count": 31,
                    "category": "suspicious",
                    "last_seen": generated_at,
                },
                {
                    "ip": "45.146.130.12",
                    "country": "Netherlands",
                    "count": 18,
                    "category": "suspicious",
                    "last_seen": generated_at,
                },
                {
                    "ip": "103.77.204.9",
                    "country": "Singapore",
                    "count": 12,
                    "category": "bot",
                    "last_seen": generated_at,
                },
            ],
        },
        "recent_sessions": recent_sessions,
        "top_pages": top_pages,
        "geo": {
            "countries": [
                {"country": "Canada", "sessions": 940, "requests": 4020},
                {"country": "United States", "sessions": 611, "requests": 2380},
                {"country": "Germany", "sessions": 84, "requests": 590},
                {"country": "United Kingdom", "sessions": 63, "requests": 310},
            ],
            "areas": [
                {"country": "Canada", "area": "Alberta", "sessions": 301},
                {"country": "Canada", "area": "Ontario", "sessions": 211},
                {"country": "United States", "area": "Texas", "sessions": 108},
                {"country": "United States", "area": "California", "sessions": 94},
            ],
            "cities": [
                {"country": "Canada", "area": "Alberta", "city": "Grande Prairie", "sessions": 92},
                {"country": "Canada", "area": "Alberta", "city": "Edmonton", "sessions": 87},
                {"country": "Canada", "area": "Alberta", "city": "Calgary", "sessions": 74},
                {"country": "United States", "area": "Texas", "city": "Dallas", "sessions": 38},
            ],
        },
        "alerts": alerts,
        "notes": [
            "Phase 1 shell is live.",
            "This payload is seeded demo data with the correct shape.",
            "Phase 2 swaps seeded data for donor logic and real log parsing.",
        ],
    }


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "traffic-api",
        "version": "0.1.0",
        "generated_at": iso_now(),
    }


@app.get("/api/summary")
async def summary() -> dict[str, Any]:
    return build_overview()


@app.get("/api/overview")
async def overview() -> dict[str, Any]:
    return build_overview()


@app.get("/api/projects")
async def projects() -> dict[str, Any]:
    overview = build_overview()
    return {
        "ok": True,
        "generated_at": overview["generated_at"],
        "projects": overview["projects"],
    }


@app.get("/api/hosts")
async def hosts() -> dict[str, Any]:
    overview = build_overview()
    return {
        "ok": True,
        "generated_at": overview["generated_at"],
        "hosts": overview["hosts"],
    }


@app.get("/api/threats")
async def threats() -> dict[str, Any]:
    overview = build_overview()
    return {
        "ok": True,
        "generated_at": overview["generated_at"],
        "summary": {
            "suspicious_requests": overview["totals"]["suspicious"],
            "suspicious_sessions": 116,
            "repeat_bad_ips": len(overview["suspicious"]["top_ips"]),
        },
        "top_paths": overview["suspicious"]["top_paths"],
        "top_ips": overview["suspicious"]["top_ips"],
        "top_hosts": [
            {"host": "vps-sentry.tokentap.ca", "count": 117},
            {"host": "aoe2hdbets.com", "count": 149},
            {"host": "tokentap.ca", "count": 61},
        ],
    }