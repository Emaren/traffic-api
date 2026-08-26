from __future__ import annotations

import ipaddress
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.traffic.config import LEGACY_LOG_LINE_RE, UNKNOWN_HOST
from app.services.traffic.normalize import normalize_host, normalize_path, normalize_referrer


_CLOUDFLARE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)


def _valid_ip(value: str | None) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        return ""

    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return ""

    return cleaned


def _is_cloudflare_proxy(value: str | None) -> bool:
    cleaned = _valid_ip(value)
    if not cleaned:
        return False

    address = ipaddress.ip_address(cleaned)

    return any(
        address in network
        for network in _CLOUDFLARE_NETWORKS
    )


def client_ip_from_json_payload(
    payload: dict[str, Any],
) -> str:
    """Resolve client IP without trusting arbitrary forwarded headers.

    X-Forwarded-For is authoritative only when the socket peer is a
    recognized Cloudflare proxy. Direct clients cannot spoof identity or
    geography by supplying their own forwarded header.
    """

    remote = _valid_ip(
        str(payload.get("remote_addr") or "")
    )

    forwarded = str(
        payload.get("x_forwarded_for")
        or ""
    ).strip()

    if (
        remote
        and forwarded
        and _is_cloudflare_proxy(remote)
    ):
        candidate = _valid_ip(
            forwarded.split(",", 1)[0]
        )

        if candidate:
            return candidate

    return remote


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


def read_recent_log_lines(path: Path, tail_lines: int) -> list[str]:
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return list(deque(handle, maxlen=tail_lines))
    except OSError:
        return []


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
    client_ip = client_ip_from_json_payload(payload)

    return {
        "ip": client_ip,
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
