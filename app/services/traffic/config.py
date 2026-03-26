from __future__ import annotations

import os
import re
from pathlib import Path

LOG_PATH = Path(os.getenv("TRAFFIC_LOG_PATH", "runtime/dev_access.log"))
GEOIP_DB_PATH = Path(os.getenv("TRAFFIC_GEOIP_DB_PATH", "runtime/geoip/GeoLite2-City.mmdb"))
PERSIST_ENABLED = os.getenv("TRAFFIC_PERSIST_ENABLED", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
PERSIST_DB_PATH = Path(
    os.getenv("TRAFFIC_PERSIST_DB_PATH", "db/traffic_history.sqlite3")
)
PERSIST_RETENTION_DAYS = int(os.getenv("TRAFFIC_PERSIST_RETENTION_DAYS", "120"))

TAIL_LINES = int(os.getenv("TRAFFIC_TAIL_LINES", "5000"))
SESSION_GAP_MINUTES = int(os.getenv("TRAFFIC_SESSION_GAP_MINUTES", "30"))
ACTIVE_GAP_CAP_SECONDS = int(os.getenv("TRAFFIC_SESSION_ACTIVE_GAP_CAP_SECONDS", "300"))
LIVE_ACTIVE_SECONDS = int(os.getenv("TRAFFIC_LIVE_ACTIVE_SECONDS", "180"))
VISITOR_SESSION_LIMIT = int(os.getenv("TRAFFIC_VISITOR_SESSION_LIMIT", "50"))
TOP_LIMIT = int(os.getenv("TRAFFIC_TOP_LIMIT", "10"))
LIVE_TILE_LIMIT = int(os.getenv("TRAFFIC_LIVE_TILE_LIMIT", "25"))
VISITS_HISTORY_LIMIT = int(os.getenv("TRAFFIC_VISITS_HISTORY_LIMIT", "250"))
SERIES_BUCKET_MINUTES = int(os.getenv("TRAFFIC_SERIES_BUCKET_MINUTES", "30"))
ALBERTA_TZ_NAME = os.getenv("TRAFFIC_ALBERTA_TZ", "America/Edmonton")
NOTIFICATION_LOOP_SECONDS = float(os.getenv("TRAFFIC_NOTIFICATION_LOOP_SECONDS", "2.0"))
NOTIFICATION_BATCH_LIMIT = int(os.getenv("TRAFFIC_NOTIFICATION_BATCH_LIMIT", "25"))
SITE_BASE_URL = os.getenv("TRAFFIC_SITE_BASE_URL", "https://traffic.tokentap.ca").rstrip("/")
ADMIN_API_KEY = os.getenv("TRAFFIC_ADMIN_API_KEY", "").strip()
WEB_PUSH_PRIVATE_KEY = os.getenv("TRAFFIC_WEB_PUSH_PRIVATE_KEY", "").strip()
WEB_PUSH_PUBLIC_KEY = os.getenv("TRAFFIC_WEB_PUSH_PUBLIC_KEY", "").strip()
WEB_PUSH_SUBJECT = os.getenv("TRAFFIC_WEB_PUSH_SUBJECT", SITE_BASE_URL).strip() or SITE_BASE_URL

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
    "216.127.43.12": {"country": "Canada", "country_code": "CA", "area": "Alberta", "city": "Grande Prairie"},
    "216.127.43.99": {"country": "Canada", "country_code": "CA", "area": "Alberta", "city": "Grande Prairie"},
    "142.114.91.44": {"country": "Canada", "country_code": "CA", "area": "Alberta", "city": "Edmonton"},
    "72.21.81.200": {"country": "United States", "country_code": "US", "area": "Washington", "city": "Seattle"},
    "45.61.188.33": {"country": "United States", "country_code": "US", "area": "Texas", "city": "Dallas"},
    "185.12.44.91": {"country": "Germany", "country_code": "DE", "area": "Hesse", "city": "Frankfurt"},
    "45.146.130.12": {"country": "Netherlands", "country_code": "NL", "area": "North Holland", "city": "Amsterdam"},
    "103.77.204.9": {"country": "Singapore", "country_code": "SG", "area": "Singapore", "city": "Singapore"},
}
