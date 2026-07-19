from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from app.services.traffic.config import (
    PERFORMANCE_DETAIL_RETENTION_DAYS,
    PERFORMANCE_REPORT_RETENTION_DAYS,
    PERFORMANCE_SAMPLE_RETENTION_DAYS,
    PERFORMANCE_DB_PATH,
    PERFORMANCE_ENABLED,
)
from app.services.traffic.normalize import (
    is_allowed_host,
    normalize_host,
    normalize_path,
    project_for_host,
)
from app.services.traffic.parse import iso_now, parse_iso_timestamp

_MAX_TEXT = 500
_SAMPLE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,100}$")
_REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,100}$")
_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_LONG_OPAQUE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{24,}$")
_WOLO_ADDRESS_RE = re.compile(r"^wolo1[0-9a-z]{20,}$", re.IGNORECASE)
_ALLOWED_NAVIGATION_KINDS = {
    "initial",
    "internal",
    "reload",
    "back_forward",
    "prerender",
    "unknown",
}
_ALLOWED_READY_SOURCES = {"explicit", "route_paint", "initial_hydration", "unknown"}
_ALLOWED_NAV_START_SOURCES = {
    "document",
    "link_click",
    "popstate",
    "programmatic",
    "route_commit",
    "unknown",
}
_ALLOWED_REPORT_STATUSES = {"open", "reviewed", "resolved"}

_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_RETENTION_LOCK = threading.Lock()
_LAST_RETENTION_RUN = 0.0
_RETENTION_INTERVAL_SECONDS = 3600.0


def _connect() -> sqlite3.Connection:
    PERFORMANCE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(PERFORMANCE_DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def _ensure_schema(connection: sqlite3.Connection) -> None:
    global _SCHEMA_READY

    if _SCHEMA_READY:
        return

    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS traffic_performance_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL UNIQUE,
                received_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                host TEXT NOT NULL,
                project_slug TEXT NOT NULL,
                project_name TEXT NOT NULL,
                route TEXT NOT NULL,
                route_group TEXT NOT NULL,
                build_version TEXT NOT NULL DEFAULT '',
                traffic_visitor_id TEXT NOT NULL DEFAULT '',
                traffic_session_id TEXT NOT NULL DEFAULT '',
                journey_session_id TEXT NOT NULL DEFAULT '',
                user_uid TEXT NOT NULL DEFAULT '',
                user_display_name TEXT NOT NULL DEFAULT '',
                navigation_kind TEXT NOT NULL DEFAULT 'unknown',
                navigation_start_source TEXT NOT NULL DEFAULT 'unknown',
                ready_source TEXT NOT NULL DEFAULT 'unknown',
                ready_ms REAL,
                ttfb_ms REAL,
                fcp_ms REAL,
                lcp_ms REAL,
                inp_ms REAL,
                cls REAL,
                dom_content_loaded_ms REAL,
                load_event_ms REAL,
                resource_count INTEGER,
                transfer_bytes INTEGER,
                api_request_count INTEGER,
                slowest_api_path TEXT NOT NULL DEFAULT '',
                slowest_api_ms REAL,
                long_task_count INTEGER,
                long_task_max_ms REAL,
                long_task_total_ms REAL,
                viewport_width INTEGER,
                viewport_height INTEGER,
                effective_connection_type TEXT NOT NULL DEFAULT '',
                connection_rtt_ms REAL,
                downlink_mbps REAL,
                save_data INTEGER,
                valid_for_aggregation INTEGER NOT NULL DEFAULT 1,
                invalid_reason TEXT NOT NULL DEFAULT '',
                visibility_tainted INTEGER NOT NULL DEFAULT 0,
                user_agent TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_samples_received
                ON traffic_performance_samples(received_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_samples_project_received
                ON traffic_performance_samples(project_slug, received_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_samples_route_received
                ON traffic_performance_samples(project_slug, route_group, received_at DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_samples_build_received
                ON traffic_performance_samples(project_slug, build_version, received_at DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_samples_user_received
                ON traffic_performance_samples(project_slug, user_uid, received_at DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_samples_display_name_received
                ON traffic_performance_samples(project_slug, user_display_name, received_at DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_samples_visitor_received
                ON traffic_performance_samples(project_slug, traffic_visitor_id, received_at DESC);

            CREATE TABLE IF NOT EXISTS traffic_performance_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                top_resources_json TEXT NOT NULL DEFAULT '[]',
                top_api_requests_json TEXT NOT NULL DEFAULT '[]',
                navigation_timing_json TEXT NOT NULL DEFAULT '{}',
                long_tasks_json TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY(sample_id) REFERENCES traffic_performance_samples(sample_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_performance_details_created
                ON traffic_performance_details(created_at DESC);

            CREATE TABLE IF NOT EXISTS traffic_speed_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sample_id TEXT NOT NULL DEFAULT '',
                project_slug TEXT NOT NULL,
                host TEXT NOT NULL,
                route TEXT NOT NULL,
                build_version TEXT NOT NULL DEFAULT '',
                user_uid TEXT NOT NULL DEFAULT '',
                user_display_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                diagnostic_snapshot_json TEXT NOT NULL DEFAULT '{}',
                recent_sample_ids_json TEXT NOT NULL DEFAULT '[]',
                resolved_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_speed_reports_status_created
                ON traffic_speed_reports(status, created_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_traffic_speed_reports_project_created
                ON traffic_speed_reports(project_slug, created_at DESC, id DESC);
            """
        )
        connection.commit()
        _SCHEMA_READY = True


def _clean_text(value: Any, max_len: int = _MAX_TEXT) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:max_len]


def _clean_identifier(value: Any, *, kind: str) -> str:
    text = _clean_text(value, 100)
    pattern = _SAMPLE_ID_RE if kind == "sample" else _REPORT_ID_RE
    if not text or not pattern.match(text):
        raise ValueError(f"{kind}_id is invalid")
    return text


def _float_or_none(
    value: Any,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float | None:
    if value is None or value == "":
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _int_or_none(
    value: Any,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if value is None or value == "":
        return None
    try:
        parsed = int(float(value))
    except (TypeError, ValueError):
        return None
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _bool_int(value: Any, default: bool = False) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if value is None or value == "":
        return 1 if default else 0
    text = str(value).strip().lower()
    return 1 if text in {"1", "true", "yes", "on"} else 0


def _enum(value: Any, allowed: set[str], default: str) -> str:
    text = _clean_text(value, 60).lower()
    return text if text in allowed else default


def _safe_occurred_at(value: Any, fallback: str) -> str:
    text = _clean_text(value, 80)
    parsed = parse_iso_timestamp(text)
    return parsed.isoformat() if parsed is not None else fallback


def _normalize_route(value: Any) -> str:
    text = _clean_text(value, 1000) or "/"
    try:
        parsed = urlparse(text)
        if parsed.scheme or parsed.netloc:
            text = parsed.path or "/"
    except Exception:
        pass
    return normalize_path(text)


def _derive_route_group(route: str) -> str:
    if route == "/":
        return "/"

    grouped: list[str] = []
    for segment in route.strip("/").split("/"):
        if not segment:
            continue
        if segment.isdigit() or _UUID_SEGMENT_RE.match(segment):
            grouped.append(":id")
        elif _WOLO_ADDRESS_RE.match(segment):
            grouped.append(":address")
        elif _LONG_OPAQUE_SEGMENT_RE.match(segment):
            grouped.append(":value")
        else:
            grouped.append(segment[:120])
    return "/" + "/".join(grouped)


def _sanitize_resource_name(value: Any) -> str:
    text = _clean_text(value, 1000)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        if parsed.scheme or parsed.netloc:
            return normalize_path(parsed.path or "/")
    except Exception:
        pass
    return normalize_path(text)


def _sanitize_timing_item(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    name = _sanitize_resource_name(item.get("name") or item.get("path") or item.get("url"))
    if not name:
        return None
    return {
        "name": name,
        "duration_ms": _float_or_none(item.get("duration_ms"), minimum=0, maximum=600_000),
        "transfer_bytes": _int_or_none(item.get("transfer_bytes"), minimum=0, maximum=2_000_000_000),
        "initiator_type": _clean_text(item.get("initiator_type"), 40),
    }


def _sanitize_timing_items(value: Any, *, limit: int = 10) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for raw_item in value[:limit]:
        item = _sanitize_timing_item(raw_item)
        if item is not None:
            items.append(item)
    return items


def _sanitize_navigation_timing(value: Any) -> dict[str, float | None]:
    if not isinstance(value, dict):
        return {}
    allowed = {
        "dns_ms",
        "connect_ms",
        "tls_ms",
        "request_ms",
        "response_ms",
        "ttfb_ms",
        "dom_interactive_ms",
        "dom_content_loaded_ms",
        "load_event_ms",
    }
    result: dict[str, float | None] = {}
    for key in sorted(allowed):
        if key in value:
            result[key] = _float_or_none(value.get(key), minimum=0, maximum=600_000)
    return result


def _sanitize_long_tasks(value: Any, *, limit: int = 10) -> list[dict[str, float | None]]:
    if not isinstance(value, list):
        return []
    tasks: list[dict[str, float | None]] = []
    for item in value[:limit]:
        if not isinstance(item, dict):
            continue
        tasks.append(
            {
                "start_ms": _float_or_none(item.get("start_ms"), minimum=0, maximum=86_400_000),
                "duration_ms": _float_or_none(item.get("duration_ms"), minimum=0, maximum=600_000),
            }
        )
    return tasks


def _sanitize_details(payload: dict[str, Any]) -> dict[str, str] | None:
    details = payload.get("details")
    if not isinstance(details, dict):
        return None

    top_resources = _sanitize_timing_items(details.get("top_resources"))
    top_api_requests = _sanitize_timing_items(details.get("top_api_requests"))
    navigation_timing = _sanitize_navigation_timing(details.get("navigation_timing"))
    long_tasks = _sanitize_long_tasks(details.get("long_tasks"))

    if not any((top_resources, top_api_requests, navigation_timing, long_tasks)):
        return None

    return {
        "top_resources_json": json.dumps(top_resources, separators=(",", ":"), ensure_ascii=False),
        "top_api_requests_json": json.dumps(top_api_requests, separators=(",", ":"), ensure_ascii=False),
        "navigation_timing_json": json.dumps(navigation_timing, separators=(",", ":"), ensure_ascii=False),
        "long_tasks_json": json.dumps(long_tasks, separators=(",", ":"), ensure_ascii=False),
    }


def _sample_row(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    now = iso_now()
    sample_id = _clean_identifier(payload.get("sample_id"), kind="sample")
    host = normalize_host(_clean_text(payload.get("host"), 160))
    if not is_allowed_host(host):
        raise ValueError(f"host is not allowed: {host}")

    project = project_for_host(host)
    route = _normalize_route(payload.get("route"))
    route_group = _derive_route_group(route)

    return {
        "sample_id": sample_id,
        "received_at": now,
        "updated_at": now,
        "occurred_at": _safe_occurred_at(payload.get("occurred_at"), now),
        "host": host,
        "project_slug": project.get("slug") or "unknown",
        "project_name": project.get("name") or "Unknown",
        "route": route,
        "route_group": route_group,
        "build_version": _clean_text(payload.get("build_version"), 120),
        "traffic_visitor_id": _clean_text(payload.get("traffic_visitor_id"), 120),
        "traffic_session_id": _clean_text(payload.get("traffic_session_id"), 120),
        "journey_session_id": _clean_text(payload.get("journey_session_id"), 120),
        "user_uid": _clean_text(payload.get("user_uid"), 160),
        "user_display_name": _clean_text(payload.get("user_display_name"), 160),
        "navigation_kind": _enum(payload.get("navigation_kind"), _ALLOWED_NAVIGATION_KINDS, "unknown"),
        "navigation_start_source": _enum(
            payload.get("navigation_start_source"), _ALLOWED_NAV_START_SOURCES, "unknown"
        ),
        "ready_source": _enum(payload.get("ready_source"), _ALLOWED_READY_SOURCES, "unknown"),
        "ready_ms": _float_or_none(payload.get("ready_ms"), minimum=0, maximum=600_000),
        "ttfb_ms": _float_or_none(payload.get("ttfb_ms"), minimum=0, maximum=600_000),
        "fcp_ms": _float_or_none(payload.get("fcp_ms"), minimum=0, maximum=600_000),
        "lcp_ms": _float_or_none(payload.get("lcp_ms"), minimum=0, maximum=600_000),
        "inp_ms": _float_or_none(payload.get("inp_ms"), minimum=0, maximum=600_000),
        "cls": _float_or_none(payload.get("cls"), minimum=0, maximum=100),
        "dom_content_loaded_ms": _float_or_none(
            payload.get("dom_content_loaded_ms"), minimum=0, maximum=600_000
        ),
        "load_event_ms": _float_or_none(payload.get("load_event_ms"), minimum=0, maximum=600_000),
        "resource_count": _int_or_none(payload.get("resource_count"), minimum=0, maximum=100_000),
        "transfer_bytes": _int_or_none(payload.get("transfer_bytes"), minimum=0, maximum=20_000_000_000),
        "api_request_count": _int_or_none(payload.get("api_request_count"), minimum=0, maximum=100_000),
        "slowest_api_path": _normalize_route(payload.get("slowest_api_path"))
        if payload.get("slowest_api_path")
        else "",
        "slowest_api_ms": _float_or_none(payload.get("slowest_api_ms"), minimum=0, maximum=600_000),
        "long_task_count": _int_or_none(payload.get("long_task_count"), minimum=0, maximum=100_000),
        "long_task_max_ms": _float_or_none(payload.get("long_task_max_ms"), minimum=0, maximum=600_000),
        "long_task_total_ms": _float_or_none(payload.get("long_task_total_ms"), minimum=0, maximum=86_400_000),
        "viewport_width": _int_or_none(payload.get("viewport_width"), minimum=0, maximum=20_000),
        "viewport_height": _int_or_none(payload.get("viewport_height"), minimum=0, maximum=20_000),
        "effective_connection_type": _clean_text(payload.get("effective_connection_type"), 40),
        "connection_rtt_ms": _float_or_none(payload.get("connection_rtt_ms"), minimum=0, maximum=600_000),
        "downlink_mbps": _float_or_none(payload.get("downlink_mbps"), minimum=0, maximum=1_000_000),
        "save_data": _bool_int(payload.get("save_data")) if payload.get("save_data") is not None else None,
        "valid_for_aggregation": _bool_int(payload.get("valid_for_aggregation"), default=True),
        "invalid_reason": _clean_text(payload.get("invalid_reason"), 240),
        "visibility_tainted": _bool_int(payload.get("visibility_tainted")),
        "user_agent": _clean_text(payload.get("user_agent"), 500),
    }


def _maybe_purge_retention(connection: sqlite3.Connection) -> None:
    global _LAST_RETENTION_RUN
    now_tick = time.monotonic()
    if now_tick - _LAST_RETENTION_RUN < _RETENTION_INTERVAL_SECONDS:
        return

    with _RETENTION_LOCK:
        now_tick = time.monotonic()
        if now_tick - _LAST_RETENTION_RUN < _RETENTION_INTERVAL_SECONDS:
            return

        now = datetime.now(timezone.utc)
        sample_cutoff = (now - timedelta(days=PERFORMANCE_SAMPLE_RETENTION_DAYS)).isoformat()
        detail_cutoff = (now - timedelta(days=PERFORMANCE_DETAIL_RETENTION_DAYS)).isoformat()
        report_cutoff = (now - timedelta(days=PERFORMANCE_REPORT_RETENTION_DAYS)).isoformat()

        connection.execute(
            "DELETE FROM traffic_performance_details WHERE created_at < ?",
            (detail_cutoff,),
        )
        connection.execute(
            "DELETE FROM traffic_performance_samples WHERE received_at < ?",
            (sample_cutoff,),
        )
        connection.execute(
            "DELETE FROM traffic_speed_reports WHERE created_at < ?",
            (report_cutoff,),
        )
        connection.commit()
        _LAST_RETENTION_RUN = now_tick


def record_performance_sample(payload: dict[str, Any]) -> dict[str, Any]:
    if not PERFORMANCE_ENABLED:
        return {"ok": True, "stored": False, "reason": "persistence_disabled", "generated_at": iso_now()}

    row = _sample_row(payload)
    details = _sanitize_details(payload)

    with _connect() as connection:
        _ensure_schema(connection)
        _maybe_purge_retention(connection)

        connection.execute(
            """
            INSERT INTO traffic_performance_samples (
                sample_id, received_at, updated_at, occurred_at,
                host, project_slug, project_name, route, route_group, build_version,
                traffic_visitor_id, traffic_session_id, journey_session_id,
                user_uid, user_display_name,
                navigation_kind, navigation_start_source, ready_source,
                ready_ms, ttfb_ms, fcp_ms, lcp_ms, inp_ms, cls,
                dom_content_loaded_ms, load_event_ms,
                resource_count, transfer_bytes, api_request_count,
                slowest_api_path, slowest_api_ms,
                long_task_count, long_task_max_ms, long_task_total_ms,
                viewport_width, viewport_height,
                effective_connection_type, connection_rtt_ms, downlink_mbps, save_data,
                valid_for_aggregation, invalid_reason, visibility_tainted, user_agent
            ) VALUES (
                :sample_id, :received_at, :updated_at, :occurred_at,
                :host, :project_slug, :project_name, :route, :route_group, :build_version,
                :traffic_visitor_id, :traffic_session_id, :journey_session_id,
                :user_uid, :user_display_name,
                :navigation_kind, :navigation_start_source, :ready_source,
                :ready_ms, :ttfb_ms, :fcp_ms, :lcp_ms, :inp_ms, :cls,
                :dom_content_loaded_ms, :load_event_ms,
                :resource_count, :transfer_bytes, :api_request_count,
                :slowest_api_path, :slowest_api_ms,
                :long_task_count, :long_task_max_ms, :long_task_total_ms,
                :viewport_width, :viewport_height,
                :effective_connection_type, :connection_rtt_ms, :downlink_mbps, :save_data,
                :valid_for_aggregation, :invalid_reason, :visibility_tainted, :user_agent
            )
            ON CONFLICT(sample_id) DO UPDATE SET
                updated_at = excluded.updated_at,
                occurred_at = COALESCE(NULLIF(excluded.occurred_at, ''), traffic_performance_samples.occurred_at),
                host = excluded.host,
                project_slug = excluded.project_slug,
                project_name = excluded.project_name,
                route = excluded.route,
                route_group = excluded.route_group,
                build_version = COALESCE(NULLIF(excluded.build_version, ''), traffic_performance_samples.build_version),
                traffic_visitor_id = COALESCE(NULLIF(excluded.traffic_visitor_id, ''), traffic_performance_samples.traffic_visitor_id),
                traffic_session_id = COALESCE(NULLIF(excluded.traffic_session_id, ''), traffic_performance_samples.traffic_session_id),
                journey_session_id = COALESCE(NULLIF(excluded.journey_session_id, ''), traffic_performance_samples.journey_session_id),
                user_uid = COALESCE(NULLIF(excluded.user_uid, ''), traffic_performance_samples.user_uid),
                user_display_name = COALESCE(NULLIF(excluded.user_display_name, ''), traffic_performance_samples.user_display_name),
                navigation_kind = CASE WHEN excluded.navigation_kind != 'unknown' THEN excluded.navigation_kind ELSE traffic_performance_samples.navigation_kind END,
                navigation_start_source = CASE WHEN excluded.navigation_start_source != 'unknown' THEN excluded.navigation_start_source ELSE traffic_performance_samples.navigation_start_source END,
                ready_source = CASE WHEN excluded.ready_source != 'unknown' THEN excluded.ready_source ELSE traffic_performance_samples.ready_source END,
                ready_ms = COALESCE(excluded.ready_ms, traffic_performance_samples.ready_ms),
                ttfb_ms = COALESCE(excluded.ttfb_ms, traffic_performance_samples.ttfb_ms),
                fcp_ms = COALESCE(excluded.fcp_ms, traffic_performance_samples.fcp_ms),
                lcp_ms = COALESCE(excluded.lcp_ms, traffic_performance_samples.lcp_ms),
                inp_ms = COALESCE(excluded.inp_ms, traffic_performance_samples.inp_ms),
                cls = COALESCE(excluded.cls, traffic_performance_samples.cls),
                dom_content_loaded_ms = COALESCE(excluded.dom_content_loaded_ms, traffic_performance_samples.dom_content_loaded_ms),
                load_event_ms = COALESCE(excluded.load_event_ms, traffic_performance_samples.load_event_ms),
                resource_count = COALESCE(excluded.resource_count, traffic_performance_samples.resource_count),
                transfer_bytes = COALESCE(excluded.transfer_bytes, traffic_performance_samples.transfer_bytes),
                api_request_count = COALESCE(excluded.api_request_count, traffic_performance_samples.api_request_count),
                slowest_api_path = COALESCE(NULLIF(excluded.slowest_api_path, ''), traffic_performance_samples.slowest_api_path),
                slowest_api_ms = COALESCE(excluded.slowest_api_ms, traffic_performance_samples.slowest_api_ms),
                long_task_count = COALESCE(excluded.long_task_count, traffic_performance_samples.long_task_count),
                long_task_max_ms = COALESCE(excluded.long_task_max_ms, traffic_performance_samples.long_task_max_ms),
                long_task_total_ms = COALESCE(excluded.long_task_total_ms, traffic_performance_samples.long_task_total_ms),
                viewport_width = COALESCE(excluded.viewport_width, traffic_performance_samples.viewport_width),
                viewport_height = COALESCE(excluded.viewport_height, traffic_performance_samples.viewport_height),
                effective_connection_type = COALESCE(NULLIF(excluded.effective_connection_type, ''), traffic_performance_samples.effective_connection_type),
                connection_rtt_ms = COALESCE(excluded.connection_rtt_ms, traffic_performance_samples.connection_rtt_ms),
                downlink_mbps = COALESCE(excluded.downlink_mbps, traffic_performance_samples.downlink_mbps),
                save_data = COALESCE(excluded.save_data, traffic_performance_samples.save_data),
                valid_for_aggregation = excluded.valid_for_aggregation,
                invalid_reason = excluded.invalid_reason,
                visibility_tainted = excluded.visibility_tainted,
                user_agent = COALESCE(NULLIF(excluded.user_agent, ''), traffic_performance_samples.user_agent)
            """,
            row,
        )

        if details is not None:
            now = row["updated_at"]
            connection.execute(
                """
                INSERT INTO traffic_performance_details (
                    sample_id, created_at, updated_at,
                    top_resources_json, top_api_requests_json,
                    navigation_timing_json, long_tasks_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sample_id) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    top_resources_json = CASE WHEN excluded.top_resources_json != '[]' THEN excluded.top_resources_json ELSE traffic_performance_details.top_resources_json END,
                    top_api_requests_json = CASE WHEN excluded.top_api_requests_json != '[]' THEN excluded.top_api_requests_json ELSE traffic_performance_details.top_api_requests_json END,
                    navigation_timing_json = CASE WHEN excluded.navigation_timing_json != '{}' THEN excluded.navigation_timing_json ELSE traffic_performance_details.navigation_timing_json END,
                    long_tasks_json = CASE WHEN excluded.long_tasks_json != '[]' THEN excluded.long_tasks_json ELSE traffic_performance_details.long_tasks_json END
                """,
                (
                    row["sample_id"],
                    now,
                    now,
                    details["top_resources_json"],
                    details["top_api_requests_json"],
                    details["navigation_timing_json"],
                    details["long_tasks_json"],
                ),
            )

        connection.commit()

    return {
        "ok": True,
        "stored": True,
        "sample_id": row["sample_id"],
        "project_slug": row["project_slug"],
        "route": row["route"],
        "generated_at": row["updated_at"],
    }


def _decode_json(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(str(value or ""))
    except Exception:
        return fallback


def _row_to_sample(row: sqlite3.Row, *, include_details: bool = False) -> dict[str, Any]:
    sample = dict(row)
    for key in ("save_data", "valid_for_aggregation", "visibility_tainted"):
        if key in sample and sample[key] is not None:
            sample[key] = bool(sample[key])

    if include_details:
        sample["details"] = {
            "top_resources": _decode_json(sample.pop("top_resources_json", "[]"), []),
            "top_api_requests": _decode_json(sample.pop("top_api_requests_json", "[]"), []),
            "navigation_timing": _decode_json(sample.pop("navigation_timing_json", "{}"), {}),
            "long_tasks": _decode_json(sample.pop("long_tasks_json", "[]"), []),
        }
    return sample


def get_performance_sample(sample_id: str) -> dict[str, Any] | None:
    if not PERFORMANCE_ENABLED:
        return None
    sample_id = _clean_identifier(sample_id, kind="sample")
    with _connect() as connection:
        _ensure_schema(connection)
        row = connection.execute(
            """
            SELECT s.*, d.top_resources_json, d.top_api_requests_json,
                   d.navigation_timing_json, d.long_tasks_json
            FROM traffic_performance_samples s
            LEFT JOIN traffic_performance_details d ON d.sample_id = s.sample_id
            WHERE s.sample_id = ?
            """,
            (sample_id,),
        ).fetchone()
    return _row_to_sample(row, include_details=True) if row is not None else None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    fraction = position - lower
    value = ordered[lower] * (1 - fraction) + ordered[upper] * fraction
    return round(value, 3)


def _metric_summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "p50": _percentile(values, 0.50),
        "p75": _percentile(values, 0.75),
        "p95": _percentile(values, 0.95),
        "min": round(min(values), 3) if values else None,
        "max": round(max(values), 3) if values else None,
    }


def build_performance_overview(
    *,
    project_slug: str = "aoe2hdbets",
    since_hours: int = 24,
    build_version: str | None = None,
) -> dict[str, Any]:
    since_hours = max(1, min(int(since_hours or 24), 24 * PERFORMANCE_SAMPLE_RETENTION_DAYS))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()

    clauses = ["project_slug = ?", "received_at >= ?"]
    params: list[Any] = [project_slug, cutoff]
    if build_version:
        clauses.append("build_version = ?")
        params.append(_clean_text(build_version, 120))
    where_sql = " AND ".join(clauses)

    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            f"""
            SELECT *
            FROM traffic_performance_samples
            WHERE {where_sql}
            ORDER BY received_at DESC
            """,
            params,
        ).fetchall()
        report_counts = connection.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM traffic_speed_reports
            WHERE project_slug = ? AND created_at >= ?
            GROUP BY status
            """,
            (project_slug, cutoff),
        ).fetchall()

    valid_rows = [row for row in rows if int(row["valid_for_aggregation"] or 0) == 1]

    metrics = {}
    for metric in ("ready_ms", "ttfb_ms", "fcp_ms", "lcp_ms", "inp_ms", "cls"):
        values = [float(row[metric]) for row in valid_rows if row[metric] is not None]
        metrics[metric] = _metric_summary(values)

    route_buckets: dict[str, list[sqlite3.Row]] = defaultdict(list)
    build_buckets: dict[str, list[sqlite3.Row]] = defaultdict(list)
    nav_buckets: dict[str, list[sqlite3.Row]] = defaultdict(list)

    for row in valid_rows:
        route_buckets[str(row["route_group"] or "/")].append(row)
        build_buckets[str(row["build_version"] or "(unknown build)")].append(row)
        nav_buckets[str(row["navigation_kind"] or "unknown")].append(row)

    def bucket_summary(name: str, bucket_rows: list[sqlite3.Row], key_name: str) -> dict[str, Any]:
        ready_values = [float(row["ready_ms"]) for row in bucket_rows if row["ready_ms"] is not None]
        lcp_values = [float(row["lcp_ms"]) for row in bucket_rows if row["lcp_ms"] is not None]
        return {
            key_name: name,
            "samples": len(bucket_rows),
            "ready": _metric_summary(ready_values),
            "lcp": _metric_summary(lcp_values),
            "slow_samples": sum(1 for value in ready_values if value >= 2000),
        }

    routes = [bucket_summary(name, bucket, "route_group") for name, bucket in route_buckets.items()]
    routes.sort(
        key=lambda item: (
            item["ready"]["p75"] is not None,
            item["ready"]["p75"] or -1,
            item["samples"],
        ),
        reverse=True,
    )

    builds = [bucket_summary(name, bucket, "build_version") for name, bucket in build_buckets.items()]
    builds.sort(key=lambda item: item["samples"], reverse=True)

    navigation_kinds = [bucket_summary(name, bucket, "navigation_kind") for name, bucket in nav_buckets.items()]
    navigation_kinds.sort(key=lambda item: item["samples"], reverse=True)

    reports = {str(row["status"]): int(row["count"]) for row in report_counts}

    return {
        "ok": True,
        "generated_at": iso_now(),
        "project_slug": project_slug,
        "since_hours": since_hours,
        "build_version": build_version or "",
        "samples": len(rows),
        "valid_samples": len(valid_rows),
        "invalid_samples": len(rows) - len(valid_rows),
        "slow_samples": sum(
            1 for row in valid_rows if row["ready_ms"] is not None and float(row["ready_ms"]) >= 2000
        ),
        "metrics": metrics,
        "routes": routes[:50],
        "builds": builds[:25],
        "navigation_kinds": navigation_kinds,
        "reports": {
            "open": reports.get("open", 0),
            "reviewed": reports.get("reviewed", 0),
            "resolved": reports.get("resolved", 0),
        },
    }


def list_performance_samples(
    *,
    limit: int = 100,
    project_slug: str = "aoe2hdbets",
    since_hours: int = 24,
    before_received_at: str | None = None,
    user_query: str | None = None,
    route: str | None = None,
    build_version: str | None = None,
    slow_only: bool = False,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    since_hours = max(1, min(int(since_hours or 24), 24 * PERFORMANCE_SAMPLE_RETENTION_DAYS))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()

    clauses = ["project_slug = ?", "received_at >= ?"]
    params: list[Any] = [project_slug, cutoff]

    if before_received_at:
        clauses.append("received_at < ?")
        params.append(_clean_text(before_received_at, 80))
    if user_query:
        clean_query = _clean_text(user_query, 160)
        clauses.append("(user_uid LIKE ? OR user_display_name LIKE ? OR traffic_visitor_id LIKE ?)")
        wildcard = f"%{clean_query}%"
        params.extend([wildcard, wildcard, wildcard])
    if route:
        clauses.append("route_group = ?")
        params.append(_derive_route_group(_normalize_route(route)))
    if build_version:
        clauses.append("build_version = ?")
        params.append(_clean_text(build_version, 120))
    if slow_only:
        clauses.append("ready_ms >= 2000")

    where_sql = " AND ".join(clauses)

    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            f"""
            SELECT *
            FROM traffic_performance_samples
            WHERE {where_sql}
            ORDER BY received_at DESC, id DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()

    return [_row_to_sample(row) for row in rows]


def create_speed_report(payload: dict[str, Any]) -> dict[str, Any]:
    if not PERFORMANCE_ENABLED:
        return {"ok": True, "stored": False, "reason": "persistence_disabled", "generated_at": iso_now()}
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    report_id = _clean_identifier(payload.get("report_id"), kind="report")
    sample_id = _clean_text(payload.get("sample_id"), 100)
    if sample_id and not _SAMPLE_ID_RE.match(sample_id):
        raise ValueError("sample_id is invalid")

    host = normalize_host(_clean_text(payload.get("host"), 160))
    if not is_allowed_host(host):
        raise ValueError(f"host is not allowed: {host}")
    project = project_for_host(host)
    route = _normalize_route(payload.get("route"))
    now = iso_now()

    recent_sample_ids_raw = payload.get("recent_sample_ids")
    recent_sample_ids: list[str] = []
    if isinstance(recent_sample_ids_raw, list):
        for value in recent_sample_ids_raw[:20]:
            text = _clean_text(value, 100)
            if _SAMPLE_ID_RE.match(text):
                recent_sample_ids.append(text)

    diagnostic = payload.get("diagnostic_snapshot")
    if not isinstance(diagnostic, dict):
        diagnostic = {}
    sanitized_diagnostic = {
        "note": _clean_text(diagnostic.get("note"), 500),
        "route": route,
        "ready_ms": _float_or_none(diagnostic.get("ready_ms"), minimum=0, maximum=600_000),
        "ttfb_ms": _float_or_none(diagnostic.get("ttfb_ms"), minimum=0, maximum=600_000),
        "lcp_ms": _float_or_none(diagnostic.get("lcp_ms"), minimum=0, maximum=600_000),
        "inp_ms": _float_or_none(diagnostic.get("inp_ms"), minimum=0, maximum=600_000),
        "cls": _float_or_none(diagnostic.get("cls"), minimum=0, maximum=100),
        "slowest_api_path": _normalize_route(diagnostic.get("slowest_api_path"))
        if diagnostic.get("slowest_api_path")
        else "",
        "slowest_api_ms": _float_or_none(diagnostic.get("slowest_api_ms"), minimum=0, maximum=600_000),
        "top_resources": _sanitize_timing_items(diagnostic.get("top_resources")),
        "top_api_requests": _sanitize_timing_items(diagnostic.get("top_api_requests")),
    }

    row = {
        "report_id": report_id,
        "created_at": now,
        "updated_at": now,
        "sample_id": sample_id,
        "project_slug": project.get("slug") or "unknown",
        "host": host,
        "route": route,
        "build_version": _clean_text(payload.get("build_version"), 120),
        "user_uid": _clean_text(payload.get("user_uid"), 160),
        "user_display_name": _clean_text(payload.get("user_display_name"), 160),
        "status": "open",
        "diagnostic_snapshot_json": json.dumps(sanitized_diagnostic, separators=(",", ":"), ensure_ascii=False),
        "recent_sample_ids_json": json.dumps(recent_sample_ids, separators=(",", ":"), ensure_ascii=False),
    }

    with _connect() as connection:
        _ensure_schema(connection)
        _maybe_purge_retention(connection)
        connection.execute(
            """
            INSERT INTO traffic_speed_reports (
                report_id, created_at, updated_at, sample_id,
                project_slug, host, route, build_version,
                user_uid, user_display_name, status,
                diagnostic_snapshot_json, recent_sample_ids_json
            ) VALUES (
                :report_id, :created_at, :updated_at, :sample_id,
                :project_slug, :host, :route, :build_version,
                :user_uid, :user_display_name, :status,
                :diagnostic_snapshot_json, :recent_sample_ids_json
            )
            ON CONFLICT(report_id) DO NOTHING
            """,
            row,
        )
        connection.commit()

    return {
        "ok": True,
        "stored": True,
        "report_id": report_id,
        "status": "open",
        "generated_at": now,
    }


def _row_to_report(row: sqlite3.Row) -> dict[str, Any]:
    report = dict(row)
    report["diagnostic_snapshot"] = _decode_json(report.pop("diagnostic_snapshot_json", "{}"), {})
    report["recent_sample_ids"] = _decode_json(report.pop("recent_sample_ids_json", "[]"), [])
    return report


def list_speed_reports(
    *,
    limit: int = 100,
    project_slug: str = "aoe2hdbets",
    status: str | None = None,
    before_created_at: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 300))
    clauses = ["project_slug = ?"]
    params: list[Any] = [project_slug]

    if status:
        cleaned_status = _enum(status, _ALLOWED_REPORT_STATUSES, "")
        if not cleaned_status:
            raise ValueError("status is invalid")
        clauses.append("status = ?")
        params.append(cleaned_status)
    if before_created_at:
        clauses.append("created_at < ?")
        params.append(_clean_text(before_created_at, 80))

    where_sql = " AND ".join(clauses)
    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            f"""
            SELECT *
            FROM traffic_speed_reports
            WHERE {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
    return [_row_to_report(row) for row in rows]


def get_speed_report(report_id: str) -> dict[str, Any] | None:
    report_id = _clean_identifier(report_id, kind="report")
    with _connect() as connection:
        _ensure_schema(connection)
        row = connection.execute(
            "SELECT * FROM traffic_speed_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
    return _row_to_report(row) if row is not None else None


def update_speed_report_status(report_id: str, status: str) -> dict[str, Any]:
    report_id = _clean_identifier(report_id, kind="report")
    cleaned_status = _enum(status, _ALLOWED_REPORT_STATUSES, "")
    if not cleaned_status:
        raise ValueError("status is invalid")

    now = iso_now()
    resolved_at = now if cleaned_status == "resolved" else None
    with _connect() as connection:
        _ensure_schema(connection)
        cursor = connection.execute(
            """
            UPDATE traffic_speed_reports
            SET status = ?, updated_at = ?, resolved_at = ?
            WHERE report_id = ?
            """,
            (cleaned_status, now, resolved_at, report_id),
        )
        connection.commit()
        if cursor.rowcount == 0:
            raise LookupError("speed report not found")

    return {
        "ok": True,
        "report_id": report_id,
        "status": cleaned_status,
        "updated_at": now,
        "resolved_at": resolved_at,
    }

