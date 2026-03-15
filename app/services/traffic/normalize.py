from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse, urlsplit

from app.services.traffic.config import (
    CANONICAL_HOST_MAP,
    DEFAULT_ALLOWED_HOSTS,
    PROJECT_INDEX,
    PROJECTS,
    UNKNOWN_HOST,
    UNKNOWN_REFERRER,
)


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


def parse_csv_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default

    values: list[str] = []
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
