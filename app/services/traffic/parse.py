from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.traffic.config import LEGACY_LOG_LINE_RE, UNKNOWN_HOST
from app.services.traffic.normalize import normalize_host, normalize_path, normalize_referrer


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
