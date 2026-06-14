from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from py_vapid import Vapid01
from pywebpush import WebPushException, webpush

from app.services.traffic.classify import (
    classify_request,
    detect_route_kind,
    is_known_automation_ua,
    is_suspicious_path,
)
from app.services.traffic.config import (
    ALBERTA_TZ_NAME,
    ADMIN_API_KEY,
    INTERNAL_IGNORE_PATHS,
    NOTIFICATION_BATCH_LIMIT,
    PROJECTS,
    SITE_BASE_URL,
    WEB_PUSH_PRIVATE_KEY,
    WEB_PUSH_PUBLIC_KEY,
    WEB_PUSH_SUBJECT,
)
from app.services.traffic.overview import should_ignore_entry
from app.services.traffic.parse import iso_now, parse_iso_timestamp
from app.services.traffic.persistence import (
    _connect,
    _ensure_schema,
    persistence_enabled,
    sync_configured_logs_to_persistence,
)
from app.services.traffic.sessions import (
    build_single_session,
    enrich_sessions,
    primary_navigation_event_ids_for_session,
    split_session_events,
)
from app.services.traffic.normalize import ALLOWED_HOSTS, is_allowed_host
from app.services.traffic.known_visitors import known_visitor_for_ip
from app.services.traffic.visibility import list_visibility_rules

ALBERTA_ZONE = ZoneInfo(ALBERTA_TZ_NAME)

ALLOWED_RULE_TYPES = {
    "person_key",
    "visitor_profile_id",
    "ip",
    "path",
    "project_slug",
    "host",
}

ALLOWED_OPERATOR_RULE_TYPES = {
    "person_key",
    "visitor_profile_id",
    "ip",
}

DEFAULT_NOTIFICATION_SETTINGS: dict[str, Any] = {
    "enabled": False,
    "provider": "pushover",
    "armed_at": None,
    "site_base_url": SITE_BASE_URL,
    "providers": {
        "pushover": {
            "app_token": "",
            "user_key": "",
            "device": "",
            "priority": 0,
            "sound": "",
        },
        "ntfy": {
            "base_url": "https://ntfy.sh",
            "topic": "",
            "token": "",
            "priority": 4,
            "tags": "traffic,eyes",
        },
        "web_push": {
            "ttl_seconds": 120,
        },
    },
    "policy": {
        "page_hits_only": True,
        "suppress_operator_traffic": False,
        "filter_exploit_probes": True,
        "filter_known_automation": True,
        "include_human_confirmed": True,
        "include_likely_human": True,
        "include_unclear": True,
        "include_suspicious": True,
        "include_bots": True,
        "include_returning": True,
        "new_visitors_only": False,
        "selected_projects": [],
        "max_notifications_per_visitor_per_hour": 0,
        "max_notifications_per_session": 0,
        "max_notifications_per_path_per_visitor_per_hour": 0,
    },
}

EXECUTABLE_PATH_RE = re.compile(
    r"/[^/?]+\.(?:php\d*|phtml|phar|asp|aspx|jsp|cgi|pl)(?:$|[/?])",
    re.IGNORECASE,
)

EXPLOIT_PATH_SNIPPETS = (
    "/wp-admin",
    "/wp-content",
    "/wp-includes",
    "xmlrpc.php",
    "phpmyadmin",
    "/cgi-bin",
    "/vendor/phpunit",
    "/boaform",
    "/hnap1",
    "/public/index.php",
    "/storage/",
    ".env",
)

ACTIVE_VISIT_BURST_WINDOW_SECONDS = 75


def admin_api_configured() -> bool:
    return bool(ADMIN_API_KEY)


def _deep_copy_default_settings() -> dict[str, Any]:
    return json.loads(json.dumps(DEFAULT_NOTIFICATION_SETTINGS))


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _normalize_int(value: Any, default: int = 0, minimum: int = 0, maximum: int = 10_000) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def _normalize_project_slugs(values: Any) -> list[str]:
    known = [project["slug"] for project in PROJECTS]
    known_set = set(known)
    if not isinstance(values, list):
        return []
    cleaned: list[str] = []
    for value in values:
        text = str(value or "").strip().lower()
        if text and text in known_set and text not in cleaned:
            cleaned.append(text)
    if len(cleaned) == len(known):
        return []
    return cleaned


def _normalize_settings(payload: dict[str, Any] | None) -> dict[str, Any]:
    normalized = _deep_copy_default_settings()
    if not isinstance(payload, dict):
        return normalized

    normalized["enabled"] = _normalize_bool(payload.get("enabled"))
    provider = str(payload.get("provider") or normalized["provider"]).strip().lower()
    normalized["provider"] = provider if provider in {"pushover", "ntfy", "web_push"} else "pushover"
    armed_at = str(payload.get("armed_at") or "").strip()
    normalized["armed_at"] = armed_at or None
    site_base_url = str(payload.get("site_base_url") or normalized["site_base_url"]).strip()
    normalized["site_base_url"] = (site_base_url or SITE_BASE_URL).rstrip("/")

    incoming_providers = payload.get("providers") or {}
    if isinstance(incoming_providers, dict):
        pushover = incoming_providers.get("pushover") or {}
        if isinstance(pushover, dict):
            normalized["providers"]["pushover"] = {
                "app_token": str(pushover.get("app_token") or "").strip(),
                "user_key": str(pushover.get("user_key") or "").strip(),
                "device": str(pushover.get("device") or "").strip(),
                "priority": _normalize_int(pushover.get("priority"), default=0, minimum=-2, maximum=2),
                "sound": str(pushover.get("sound") or "").strip(),
            }

        ntfy = incoming_providers.get("ntfy") or {}
        if isinstance(ntfy, dict):
            normalized["providers"]["ntfy"] = {
                "base_url": str(ntfy.get("base_url") or "https://ntfy.sh").strip().rstrip("/"),
                "topic": str(ntfy.get("topic") or "").strip(),
                "token": str(ntfy.get("token") or "").strip(),
                "priority": _normalize_int(ntfy.get("priority"), default=4, minimum=1, maximum=5),
                "tags": str(ntfy.get("tags") or "traffic,eyes").strip(),
            }

        web_push = incoming_providers.get("web_push") or {}
        if isinstance(web_push, dict):
            normalized["providers"]["web_push"] = {
                "ttl_seconds": _normalize_int(
                    web_push.get("ttl_seconds"),
                    default=120,
                    minimum=30,
                    maximum=86400,
                ),
            }

    incoming_policy = payload.get("policy") or {}
    if isinstance(incoming_policy, dict):
        normalized["policy"] = {
            "page_hits_only": _normalize_bool(incoming_policy.get("page_hits_only", True)),
            "suppress_operator_traffic": _normalize_bool(
                incoming_policy.get("suppress_operator_traffic", False)
            ),
            "filter_exploit_probes": _normalize_bool(
                incoming_policy.get("filter_exploit_probes", True)
            ),
            "filter_known_automation": _normalize_bool(
                incoming_policy.get("filter_known_automation", True)
            ),
            "include_human_confirmed": _normalize_bool(
                incoming_policy.get("include_human_confirmed", True)
            ),
            "include_likely_human": _normalize_bool(
                incoming_policy.get("include_likely_human", True)
            ),
            "include_unclear": _normalize_bool(incoming_policy.get("include_unclear", True)),
            "include_suspicious": _normalize_bool(
                incoming_policy.get("include_suspicious", True)
            ),
            "include_bots": _normalize_bool(incoming_policy.get("include_bots", True)),
            "include_returning": _normalize_bool(
                incoming_policy.get("include_returning", True)
            ),
            "new_visitors_only": _normalize_bool(
                incoming_policy.get("new_visitors_only", False)
            ),
            "selected_projects": _normalize_project_slugs(
                incoming_policy.get("selected_projects")
            ),
            "max_notifications_per_visitor_per_hour": _normalize_int(
                incoming_policy.get("max_notifications_per_visitor_per_hour"),
                default=0,
                minimum=0,
                maximum=500,
            ),
            "max_notifications_per_session": _normalize_int(
                incoming_policy.get("max_notifications_per_session"),
                default=0,
                minimum=0,
                maximum=500,
            ),
            "max_notifications_per_path_per_visitor_per_hour": _normalize_int(
                incoming_policy.get("max_notifications_per_path_per_visitor_per_hour"),
                default=0,
                minimum=0,
                maximum=500,
            ),
        }

    return normalized


def get_notification_settings() -> dict[str, Any]:
    with _connect() as connection:
        _ensure_schema(connection)
        row = connection.execute(
            """
            SELECT payload_json
            FROM traffic_notification_settings
            WHERE id = 1
            """
        ).fetchone()

    if not row:
        return _deep_copy_default_settings()

    try:
        payload = json.loads(row["payload_json"])
    except Exception:
        payload = None
    return _normalize_settings(payload)


def update_notification_settings(payload: dict[str, Any]) -> dict[str, Any]:
    current = get_notification_settings()
    merged = _normalize_settings(payload)
    if merged["enabled"] and not current.get("enabled") and not merged.get("armed_at"):
        merged["armed_at"] = iso_now()

    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            """
            INSERT INTO traffic_notification_settings (id, payload_json, updated_at)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at
            """,
            (json.dumps(merged), iso_now()),
        )
        connection.commit()

    return merged


def _event_timestamp_alberta(value: str) -> str:
    parsed = parse_iso_timestamp(value)
    if not parsed:
        return value
    return parsed.astimezone(ALBERTA_ZONE).strftime("%Y-%m-%d %I:%M:%S %p")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _web_push_public_key() -> str:
    if WEB_PUSH_PUBLIC_KEY:
        return WEB_PUSH_PUBLIC_KEY
    if not WEB_PUSH_PRIVATE_KEY:
        return ""
    try:
        vapid = Vapid01.from_string(WEB_PUSH_PRIVATE_KEY)
        public_bytes = vapid.public_key.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint,
        )
        return _b64url_encode(public_bytes)
    except Exception:
        return ""


def web_push_configured() -> bool:
    return bool(WEB_PUSH_PRIVATE_KEY and _web_push_public_key())


def web_push_public_key() -> str:
    return _web_push_public_key()


def _web_push_subject() -> str:
    return WEB_PUSH_SUBJECT or SITE_BASE_URL


def list_web_push_subscriptions(
    *,
    active_only: bool = False,
    connection: Any | None = None,
) -> list[dict[str, Any]]:
    query = """
        SELECT
            id,
            endpoint,
            subscription_json,
            device_label,
            user_agent,
            active,
            last_error,
            created_at,
            updated_at,
            last_success_at
        FROM traffic_push_subscriptions
    """
    params: tuple[Any, ...] = ()
    if active_only:
        query += " WHERE active = 1"
    query += " ORDER BY active DESC, updated_at DESC, id DESC"

    if connection is None:
        with _connect() as managed_connection:
            _ensure_schema(managed_connection)
            rows = managed_connection.execute(query, params).fetchall()
    else:
        _ensure_schema(connection)
        rows = connection.execute(query, params).fetchall()

    subscriptions: list[dict[str, Any]] = []
    for row in rows:
        try:
            subscription = json.loads(row["subscription_json"] or "{}")
        except Exception:
            subscription = {}

        endpoint = row["endpoint"] or ""
        subscriptions.append(
            {
                "id": int(row["id"]),
                "endpoint": endpoint,
                "endpoint_tail": endpoint[-36:] if endpoint else "",
                "device_label": row["device_label"] or "",
                "user_agent": row["user_agent"] or "",
                "active": bool(row["active"]),
                "last_error": row["last_error"] or "",
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "last_success_at": row["last_success_at"],
                "subscription": subscription,
            }
        )
    return subscriptions


def register_web_push_subscription(payload: dict[str, Any]) -> dict[str, Any]:
    subscription = payload.get("subscription") or {}
    if not isinstance(subscription, dict):
        raise ValueError("Web-push subscription payload is required")

    endpoint = str(subscription.get("endpoint") or "").strip()
    keys = subscription.get("keys") or {}
    if not isinstance(keys, dict):
        keys = {}
    p256dh = str(keys.get("p256dh") or "").strip()
    auth = str(keys.get("auth") or "").strip()

    if not endpoint or not p256dh or not auth:
        raise ValueError("Web-push subscription is missing endpoint or keys")

    device_label = str(payload.get("device_label") or "").strip() or "Traffic device"
    user_agent = str(payload.get("user_agent") or "").strip()
    now = iso_now()
    subscription_json = json.dumps(
        {
            "endpoint": endpoint,
            "keys": {
                "p256dh": p256dh,
                "auth": auth,
            },
        }
    )

    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            """
            INSERT INTO traffic_push_subscriptions (
                endpoint,
                subscription_json,
                device_label,
                user_agent,
                active,
                last_error,
                created_at,
                updated_at,
                last_success_at
            ) VALUES (?, ?, ?, ?, 1, '', ?, ?, NULL)
            ON CONFLICT(endpoint) DO UPDATE SET
                subscription_json = excluded.subscription_json,
                device_label = excluded.device_label,
                user_agent = excluded.user_agent,
                active = 1,
                last_error = '',
                updated_at = excluded.updated_at
            """,
            (
                endpoint,
                subscription_json,
                device_label,
                user_agent,
                now,
                now,
            ),
        )
        connection.commit()

        row = connection.execute(
            """
            SELECT
                id,
                endpoint,
                subscription_json,
                device_label,
                user_agent,
                active,
                last_error,
                created_at,
                updated_at,
                last_success_at
            FROM traffic_push_subscriptions
            WHERE endpoint = ?
            """,
            (endpoint,),
        ).fetchone()

    if not row:
        raise RuntimeError("Could not persist web-push subscription")

    return {
        "id": int(row["id"]),
        "endpoint": row["endpoint"],
        "endpoint_tail": row["endpoint"][-36:] if row["endpoint"] else "",
        "device_label": row["device_label"] or "",
        "user_agent": row["user_agent"] or "",
        "active": bool(row["active"]),
        "last_error": row["last_error"] or "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_success_at": row["last_success_at"],
    }


def delete_web_push_subscription(subscription_id: int) -> None:
    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            "DELETE FROM traffic_push_subscriptions WHERE id = ?",
            (subscription_id,),
        )
        connection.commit()


def _mark_web_push_subscription_result(
    connection: Any,
    *,
    endpoint: str,
    active: bool,
    last_error: str = "",
    success_at: str | None = None,
) -> None:
    connection.execute(
        """
        UPDATE traffic_push_subscriptions
        SET
            active = ?,
            last_error = ?,
            updated_at = ?,
            last_success_at = COALESCE(?, last_success_at)
        WHERE endpoint = ?
        """,
        (
            1 if active else 0,
            last_error,
            iso_now(),
            success_at,
            endpoint,
        ),
    )


def _persist_web_push_subscription_results(
    results: list[dict[str, Any]],
    *,
    connection: Any | None = None,
) -> None:
    if not results:
        return

    should_commit = connection is None
    managed_connection = connection
    if managed_connection is None:
        managed_connection = _connect()
        _ensure_schema(managed_connection)

    try:
        for result in results:
            _mark_web_push_subscription_result(
                managed_connection,
                endpoint=result["endpoint"],
                active=bool(result.get("active", True)),
                last_error=str(result.get("last_error") or ""),
                success_at=result.get("success_at"),
            )
        if should_commit:
            managed_connection.commit()
    finally:
        if should_commit:
            managed_connection.close()


def _web_push_info() -> dict[str, Any]:
    subscriptions = list_web_push_subscriptions()
    active = [subscription for subscription in subscriptions if subscription["active"]]
    return {
        "configured": web_push_configured(),
        "public_key": web_push_public_key(),
        "subject": _web_push_subject(),
        "ready": bool(web_push_configured() and active),
        "active_count": len(active),
        "subscriptions": subscriptions,
    }


def list_notification_mutes() -> list[dict[str, Any]]:
    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            """
            SELECT id, rule_type, match_value, label, reason, active, created_at
            FROM traffic_notification_mutes
            ORDER BY active DESC, created_at DESC, id DESC
            """
        ).fetchall()

    return [
        {
            "id": int(row["id"]),
            "rule_type": row["rule_type"],
            "match_value": row["match_value"],
            "label": row["label"],
            "reason": row["reason"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def list_operator_identities() -> list[dict[str, Any]]:
    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            """
            SELECT id, rule_type, match_value, label, notes, active, created_at, updated_at
            FROM traffic_operator_identities
            ORDER BY active DESC, updated_at DESC, created_at DESC, id DESC
            """
        ).fetchall()

    return [
        {
            "id": int(row["id"]),
            "rule_type": row["rule_type"],
            "match_value": row["match_value"],
            "label": row["label"],
            "notes": row["notes"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def create_operator_identity(payload: dict[str, Any]) -> dict[str, Any]:
    rule_type = str(payload.get("rule_type") or "").strip()
    match_value = str(payload.get("match_value") or "").strip()
    if rule_type not in ALLOWED_OPERATOR_RULE_TYPES:
        raise ValueError("Unsupported operator rule type")
    if not match_value:
        raise ValueError("Operator match value is required")

    label = str(payload.get("label") or match_value).strip() or match_value
    notes = str(payload.get("notes") or "Marked as self traffic from the admin dashboard").strip()
    timestamp = iso_now()

    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            """
            INSERT INTO traffic_operator_identities (
                rule_type,
                match_value,
                label,
                notes,
                active,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(rule_type, match_value) DO UPDATE SET
                label = excluded.label,
                notes = excluded.notes,
                active = 1,
                updated_at = excluded.updated_at
            """,
            (rule_type, match_value, label, notes, timestamp, timestamp),
        )
        connection.commit()
        row = connection.execute(
            """
            SELECT id, rule_type, match_value, label, notes, active, created_at, updated_at
            FROM traffic_operator_identities
            WHERE rule_type = ? AND match_value = ?
            """,
            (rule_type, match_value),
        ).fetchone()

    if not row:
        raise RuntimeError("Could not save operator identity")

    return {
        "id": int(row["id"]),
        "rule_type": row["rule_type"],
        "match_value": row["match_value"],
        "label": row["label"],
        "notes": row["notes"],
        "active": bool(row["active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def delete_operator_identity(operator_id: int) -> None:
    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            "DELETE FROM traffic_operator_identities WHERE id = ?",
            (operator_id,),
        )
        connection.commit()


def _match_operator_identity(
    operators: list[dict[str, Any]],
    *,
    person_key: str,
    visitor_profile_id: str,
    ip: str,
) -> dict[str, Any] | None:
    for operator in operators:
        if not operator["active"]:
            continue
        rule_type = operator["rule_type"]
        match_value = operator["match_value"]
        if rule_type == "person_key" and person_key == match_value:
            return operator
        if rule_type == "visitor_profile_id" and visitor_profile_id == match_value:
            return operator
        if rule_type == "ip" and ip == match_value:
            return operator
    return None


def create_notification_mute(payload: dict[str, Any]) -> dict[str, Any]:
    rule_type = str(payload.get("rule_type") or "").strip()
    match_value = str(payload.get("match_value") or "").strip()
    if rule_type not in ALLOWED_RULE_TYPES:
        raise ValueError("Unsupported mute rule type")
    if not match_value:
        raise ValueError("Mute match value is required")

    label = str(payload.get("label") or match_value).strip() or match_value
    reason = str(payload.get("reason") or "Muted from the admin dashboard").strip()
    created_at = iso_now()

    with _connect() as connection:
        _ensure_schema(connection)
        cursor = connection.execute(
            """
            INSERT INTO traffic_notification_mutes (
                rule_type,
                match_value,
                label,
                reason,
                active,
                created_at
            ) VALUES (?, ?, ?, ?, 1, ?)
            """,
            (rule_type, match_value, label, reason, created_at),
        )
        connection.commit()
        mute_id = int(cursor.lastrowid)

    return {
        "id": mute_id,
        "rule_type": rule_type,
        "match_value": match_value,
        "label": label,
        "reason": reason,
        "active": True,
        "created_at": created_at,
    }


def delete_notification_mute(mute_id: int) -> None:
    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            "DELETE FROM traffic_notification_mutes WHERE id = ?",
            (mute_id,),
        )
        connection.commit()


def list_notification_events(limit: int = 100) -> list[dict[str, Any]]:
    operators = list_operator_identities()
    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            """
            SELECT
                id,
                traffic_event_id,
                session_id,
                event_timestamp,
                project_slug,
                project_name,
                host,
                path,
                route_kind,
                person_key,
                visitor_profile_id,
                visitor_alias,
                ip,
                country_code,
                country,
                classification_state,
                verdict_label,
                returning_visitor,
                total_project_visits,
                projects_visited_in_window,
                status,
                suppression_reason,
                provider,
                provider_message_id,
                delivery_error,
                notification_title,
                notification_body,
                destination_url,
                details_json,
                created_at,
                delivered_at
            FROM traffic_notification_events
            ORDER BY event_timestamp DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    events: list[dict[str, Any]] = []
    for row in rows:
        try:
            details = json.loads(row["details_json"] or "{}")
        except Exception:
            details = {}
        operator_identity = _match_operator_identity(
            operators,
            person_key=row["person_key"],
            visitor_profile_id=row["visitor_profile_id"],
            ip=row["ip"],
        )
        events.append(
            {
                "id": int(row["id"]),
                "traffic_event_id": row["traffic_event_id"],
                "session_id": row["session_id"],
                "event_timestamp": row["event_timestamp"],
                "event_timestamp_alberta": _event_timestamp_alberta(row["event_timestamp"]),
                "project_slug": row["project_slug"],
                "project_name": row["project_name"],
                "host": row["host"],
                "path": row["path"],
                "route_kind": row["route_kind"],
                "person_key": row["person_key"],
                "visitor_profile_id": row["visitor_profile_id"],
                "visitor_alias": row["visitor_alias"],
                "ip": row["ip"],
                "country_code": row["country_code"],
                "country": row["country"],
                "classification_state": row["classification_state"],
                "verdict_label": row["verdict_label"],
                "returning_visitor": bool(row["returning_visitor"]),
                "total_project_visits": int(row["total_project_visits"]),
                "projects_visited_in_window": int(row["projects_visited_in_window"]),
                "status": row["status"],
                "suppression_reason": row["suppression_reason"],
                "provider": row["provider"],
                "provider_message_id": row["provider_message_id"],
                "delivery_error": row["delivery_error"],
                "notification_title": row["notification_title"],
                "notification_body": row["notification_body"],
                "destination_url": row["destination_url"],
                "operator_identity": operator_identity,
                "details": details,
                "created_at": row["created_at"],
                "delivered_at": row["delivered_at"],
            }
        )
    return events


def _notification_stats() -> dict[str, Any]:
    with _connect() as connection:
        _ensure_schema(connection)
        summary_rows = connection.execute(
            """
            SELECT status, COUNT(*) AS count, MAX(delivered_at) AS last_delivered_at
            FROM traffic_notification_events
            GROUP BY status
            """
        ).fetchall()

    delivered = 0
    suppressed = 0
    errors = 0
    total = 0
    last_delivered_at: str | None = None

    for row in summary_rows:
        status = row["status"]
        count = int(row["count"])
        total += count
        if status == "delivered":
            delivered += count
            last_delivered_at = row["last_delivered_at"] or last_delivered_at
        elif status == "suppressed":
            suppressed += count
        elif status == "error":
            errors += count

    return {
        "delivered": delivered,
        "suppressed": suppressed,
        "errors": errors,
        "total": total,
        "last_delivered_at": last_delivered_at,
    }


def build_notification_dashboard(loop_state: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = get_notification_settings()
    provider_ready = _provider_ready(settings)
    return {
        "ok": True,
        "generated_at": iso_now(),
        "projects": [{"slug": project["slug"], "name": project["name"]} for project in PROJECTS],
        "settings": settings,
        "provider_ready": provider_ready,
        "web_push": _web_push_info(),
        "operators": list_operator_identities(),
        "mutes": list_notification_mutes(),
        "visibility_rules": list_visibility_rules(),
        "recent_events": list_notification_events(limit=120),
        "stats": _notification_stats(),
        "loop": loop_state or {},
    }


def _provider_ready(settings: dict[str, Any]) -> bool:
    provider = settings.get("provider")
    if provider == "pushover":
        provider_settings = settings["providers"]["pushover"]
        return bool(provider_settings.get("app_token") and provider_settings.get("user_key"))
    if provider == "ntfy":
        provider_settings = settings["providers"]["ntfy"]
        return bool(provider_settings.get("base_url") and provider_settings.get("topic"))
    if provider == "web_push":
        return _web_push_info()["ready"]
    return False


def _country_flag(country_code: str) -> str:
    text = (country_code or "").strip().upper()
    if len(text) != 2 or not text.isalpha():
        return ""
    return chr(0x1F1E6 + ord(text[0]) - ord("A")) + chr(0x1F1E6 + ord(text[1]) - ord("A"))


def _entry_from_row(row: Any) -> dict[str, Any] | None:
    timestamp = parse_iso_timestamp(row["timestamp"])
    if not timestamp:
        return None

    entry = {
        "event_id": row["event_id"],
        "ip": row["ip"],
        "timestamp": timestamp,
        "timestamp_iso": row["timestamp"],
        "request": row["request"],
        "method": row["method"],
        "raw_path": row["raw_path"],
        "normalized_path": row["normalized_path"],
        "status": row["status"],
        "referrer": row["referrer"],
        "referrer_host": row["referrer_host"],
        "ua": row["ua"],
        "host": row["host"],
        "raw": row["raw"],
    }
    if "line_offset" in row.keys():
        entry["line_offset"] = row["line_offset"]
    entry["category"] = classify_request(entry["ua"], entry["normalized_path"])
    entry["route_kind"] = detect_route_kind(entry["normalized_path"])
    return entry


def _load_unprocessed_candidates(
    connection: Any,
    *,
    limit: int,
    armed_at: str | None,
) -> list[dict[str, Any]]:
    allowed_placeholders = ", ".join("?" for _ in ALLOWED_HOSTS) or "''"
    ignored_path_placeholders = ", ".join("?" for _ in INTERNAL_IGNORE_PATHS) or "''"
    params: list[Any] = []
    query = """
        SELECT
            event_id,
            line_offset,
            timestamp,
            ip,
            request,
            method,
            raw_path,
            normalized_path,
            status,
            referrer,
            referrer_host,
            ua,
            host,
            raw
        FROM traffic_entries
        WHERE NOT EXISTS (
            SELECT 1
            FROM traffic_notification_events
            WHERE traffic_notification_events.traffic_event_id = traffic_entries.event_id
        )
          AND host IN (""" + allowed_placeholders + """)
          AND normalized_path NOT IN (""" + ignored_path_placeholders + """)
    """
    params.extend(sorted(ALLOWED_HOSTS))
    params.extend(sorted(INTERNAL_IGNORE_PATHS))
    if armed_at:
        query += " AND timestamp >= ?"
        params.append(armed_at)
    query += " ORDER BY timestamp ASC LIMIT ?"
    params.append(limit)

    rows = connection.execute(query, tuple(params)).fetchall()
    candidates: list[dict[str, Any]] = []
    for row in rows:
        parsed = _entry_from_row(row)
        if parsed:
            candidates.append(parsed)
    return candidates


def _load_person_recent_entries(
    connection: Any,
    *,
    ip: str,
    ua: str,
    window_hours: int = 24,
) -> list[dict[str, Any]]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    rows = connection.execute(
        """
        SELECT
            event_id,
            line_offset,
            timestamp,
            ip,
            request,
            method,
            raw_path,
            normalized_path,
            status,
            referrer,
            referrer_host,
            ua,
            host,
            raw
        FROM traffic_entries
        WHERE ip = ? AND ua = ? AND timestamp >= ?
        ORDER BY timestamp ASC
        """,
        (ip, ua, cutoff),
    ).fetchall()

    entries: list[dict[str, Any]] = []
    for row in rows:
        parsed = _entry_from_row(row)
        if not parsed:
            continue
        if not is_allowed_host(parsed["host"]):
            continue
        if should_ignore_entry(parsed):
            continue
        entries.append(parsed)
    return entries


def _find_session_for_entry(
    connection: Any, entry: dict[str, Any]
) -> tuple[dict[str, Any] | None, bool]:
    recent_entries = _load_person_recent_entries(
        connection,
        ip=entry["ip"],
        ua=entry["ua"],
        window_hours=24,
    )
    if not recent_entries:
        return None, False

    session_groups = split_session_events(recent_entries)
    sessions = [build_single_session(group) for group in session_groups]
    enrich_sessions(sessions)

    for group, session in zip(session_groups, sessions):
        if any(candidate["event_id"] == entry["event_id"] for candidate in group):
            primary_navigation_event_ids = primary_navigation_event_ids_for_session(group)
            return session, (
                not primary_navigation_event_ids
                or entry["event_id"] in primary_navigation_event_ids
            )
    return None, False


def _count_recent_notifications(
    connection: Any,
    *,
    person_key: str,
    session_id: str | None = None,
    path: str | None = None,
    since_hours: int = 1,
) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    query = """
        SELECT COUNT(*) AS count
        FROM traffic_notification_events
        WHERE status = 'delivered'
          AND person_key = ?
          AND event_timestamp >= ?
    """
    params: list[Any] = [person_key, cutoff]
    if session_id:
        query += " AND session_id = ?"
        params.append(session_id)
    if path:
        query += " AND path = ?"
        params.append(path)
    row = connection.execute(query, tuple(params)).fetchone()
    return int(row["count"]) if row else 0


def _recent_delivered_event_in_visit_burst(
    connection: Any,
    *,
    person_key: str,
    session_id: str,
    event_timestamp: str,
    since_seconds: int = ACTIVE_VISIT_BURST_WINDOW_SECONDS,
) -> bool:
    current_timestamp = parse_iso_timestamp(event_timestamp)
    if current_timestamp is None:
        current_timestamp = datetime.now(timezone.utc)
    cutoff = (current_timestamp - timedelta(seconds=since_seconds)).isoformat()
    row = connection.execute(
        """
        SELECT id
        FROM traffic_notification_events
        WHERE status = 'delivered'
          AND person_key = ?
          AND session_id = ?
          AND event_timestamp >= ?
          AND event_timestamp <= ?
        ORDER BY event_timestamp DESC, id DESC
        LIMIT 1
        """,
        (person_key, session_id, cutoff, event_timestamp),
    ).fetchone()
    return row is not None


def _suppression_reason(
    settings: dict[str, Any],
    session: dict[str, Any],
    entry: dict[str, Any],
    is_primary_navigation_event: bool,
    operators: list[dict[str, Any]],
    mutes: list[dict[str, Any]],
    connection: Any,
) -> str | None:
    policy = settings["policy"]
    operator_identity = _match_operator_identity(
        operators,
        person_key=session["person_key"],
        visitor_profile_id=session["visitor_profile_id"],
        ip=session["ip"],
    )
    if operator_identity and policy["suppress_operator_traffic"]:
        return "operator_traffic"
    if policy["page_hits_only"] and entry["route_kind"] != "page":
        return "page_only_filter"
    if entry["route_kind"] == "page" and not is_primary_navigation_event:
        return "prefetch_page_burst"
    if policy["filter_exploit_probes"] and _looks_like_exploit_probe(entry["normalized_path"]):
        return "exploit_probe_filter"
    if policy["filter_known_automation"] and is_known_automation_ua(entry.get("ua")):
        return "known_automation_filter"

    selected_projects = policy["selected_projects"]
    if selected_projects and session["project_slug"] not in selected_projects:
        return "project_not_selected"

    state = session["classification_state"]
    if state == "human_confirmed" and not policy["include_human_confirmed"]:
        return "human_confirmed_filtered"
    if state == "likely_human" and not policy["include_likely_human"]:
        return "likely_human_filtered"
    if state == "candidate" and not policy["include_unclear"]:
        return "unclear_filtered"
    if state == "suspicious" and not policy["include_suspicious"]:
        return "suspicious_filtered"
    if state == "bot" and not policy["include_bots"]:
        return "bot_filtered"

    if policy["new_visitors_only"] and session["returning_visitor"]:
        return "returning_filtered"
    if not policy["include_returning"] and session["returning_visitor"]:
        return "returning_filtered"

    for mute in mutes:
        if not mute["active"]:
            continue
        rule_type = mute["rule_type"]
        match_value = mute["match_value"]
        if rule_type == "person_key" and session["person_key"] == match_value:
            return "muted_person"
        if rule_type == "visitor_profile_id" and session["visitor_profile_id"] == match_value:
            return "muted_visitor_profile"
        if rule_type == "ip" and session["ip"] == match_value:
            return "muted_ip"
        if rule_type == "path" and entry["normalized_path"] == match_value:
            return "muted_path"
        if rule_type == "project_slug" and session["project_slug"] == match_value:
            return "muted_project"
        if rule_type == "host" and session["host"] == match_value:
            return "muted_host"

    per_visitor_cap = policy["max_notifications_per_visitor_per_hour"]
    if per_visitor_cap > 0:
        recent_count = _count_recent_notifications(
            connection,
            person_key=session["person_key"],
            since_hours=1,
        )
        if recent_count >= per_visitor_cap:
            return "visitor_hour_cap"

    if _recent_delivered_event_in_visit_burst(
        connection,
        person_key=session["person_key"],
        session_id=session["session_id"],
        event_timestamp=entry["timestamp_iso"],
    ):
        return "active_visit_burst"

    per_session_cap = policy["max_notifications_per_session"]
    if per_session_cap > 0:
        session_count = _count_recent_notifications(
            connection,
            person_key=session["person_key"],
            session_id=session["session_id"],
            since_hours=24,
        )
        if session_count >= per_session_cap:
            return "session_cap"

    per_path_cap = policy["max_notifications_per_path_per_visitor_per_hour"]
    if per_path_cap > 0:
        path_count = _count_recent_notifications(
            connection,
            person_key=session["person_key"],
            path=entry["normalized_path"],
            since_hours=1,
        )
        if path_count >= per_path_cap:
            return "path_hour_cap"

    return None


def _looks_like_exploit_probe(path: str | None) -> bool:
    lowered = (path or "").strip().lower()
    if not lowered:
        return False
    if detect_route_kind(lowered) == "probe":
        return True
    if is_suspicious_path(lowered):
        return True
    if any(snippet in lowered for snippet in EXPLOIT_PATH_SNIPPETS):
        return True
    return bool(EXECUTABLE_PATH_RE.search(lowered))


def _notification_title(session: dict[str, Any]) -> str:
    flag = _country_flag(session.get("country_code", ""))
    prefix = f"{flag} " if flag else ""
    return f"{prefix}{session['project_name']} · {session['visitor_alias']}"


def _notification_body(session: dict[str, Any], entry: dict[str, Any]) -> str:
    visitor_state = "Returning" if session["returning_visitor"] else "New"
    location_parts = [
        value
        for value in (session.get("city"), session.get("area"), session.get("country"))
        if value and value != "Unknown"
    ]
    location = ", ".join(location_parts) or "Location pending"
    return "\n".join(
        [
            f"{session['verdict_label']} hit {entry['normalized_path']}",
            f"IP {session['ip']} · {visitor_state} · Project visits {session['total_project_visits']}",
            location,
        ]
    )


def _notification_url(settings: dict[str, Any], session: dict[str, Any]) -> str:
    base = settings.get("site_base_url") or SITE_BASE_URL
    return f"{base}/visitors/{session['visitor_profile_id']}"


def _send_pushover(
    settings: dict[str, Any],
    *,
    title: str,
    body: str,
    url: str,
) -> dict[str, Any]:
    provider = settings["providers"]["pushover"]
    payload = {
        "token": provider["app_token"],
        "user": provider["user_key"],
        "title": title,
        "message": body,
        "url": url,
        "url_title": "Open visitor in Traffic",
        "priority": str(provider["priority"]),
    }
    if provider.get("device"):
        payload["device"] = provider["device"]
    if provider.get("sound"):
        payload["sound"] = provider["sound"]

    request = Request(
        "https://api.pushover.net/1/messages.json",
        data=urlencode(payload).encode("utf-8"),
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        content = response.read().decode("utf-8")
    parsed = json.loads(content or "{}")
    if parsed.get("status") != 1:
        raise RuntimeError(parsed.get("errors") or "Pushover rejected the notification")
    return {
        "provider": "pushover",
        "provider_message_id": str(parsed.get("request") or ""),
        "details": parsed,
    }


def _send_ntfy(
    settings: dict[str, Any],
    *,
    title: str,
    body: str,
    url: str,
) -> dict[str, Any]:
    provider = settings["providers"]["ntfy"]
    request = Request(
        f"{provider['base_url']}/{provider['topic']}",
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Title": title,
            "Priority": str(provider["priority"]),
            "Tags": provider.get("tags") or "traffic,eyes",
            "Click": url,
            **({"Authorization": f"Bearer {provider['token']}"} if provider.get("token") else {}),
        },
    )
    with urlopen(request, timeout=10) as response:
        content = response.read().decode("utf-8")
    parsed = json.loads(content or "{}")
    return {
        "provider": "ntfy",
        "provider_message_id": str(parsed.get("id") or ""),
        "details": parsed,
    }


def _send_web_push(
    settings: dict[str, Any],
    *,
    title: str,
    body: str,
    url: str,
    connection: Any | None = None,
) -> dict[str, Any]:
    if not web_push_configured():
        raise RuntimeError("Traffic web push is not configured yet on the server.")

    subscriptions = list_web_push_subscriptions(active_only=True, connection=connection)
    if not subscriptions:
        raise RuntimeError("No active Traffic web-push subscriptions are registered yet.")

    payload = json.dumps(
        {
            "title": title,
            "body": body,
            "url": url,
            "icon": f"{SITE_BASE_URL}/icons/traffic-192.png",
            "badge": f"{SITE_BASE_URL}/icons/traffic-180.png",
            "tag": "traffic-observatory",
        }
    )
    vapid_claims = {"sub": _web_push_subject()}
    ttl_seconds = int(settings["providers"]["web_push"]["ttl_seconds"])

    sent_devices: list[dict[str, Any]] = []
    failed_devices: list[dict[str, Any]] = []
    subscription_results: list[dict[str, Any]] = []

    for subscription in subscriptions:
        endpoint = subscription["endpoint"]
        try:
            response = webpush(
                subscription_info=subscription["subscription"],
                data=payload,
                vapid_private_key=WEB_PUSH_PRIVATE_KEY,
                vapid_claims=vapid_claims,
                ttl=ttl_seconds,
                timeout=10,
            )
            status_code = getattr(response, "status_code", None)
            subscription_results.append(
                {
                    "endpoint": endpoint,
                    "active": True,
                    "last_error": "",
                    "success_at": iso_now(),
                }
            )
            sent_devices.append(
                {
                    "subscription_id": subscription["id"],
                    "device_label": subscription["device_label"],
                    "endpoint_tail": subscription["endpoint_tail"],
                    "status_code": status_code,
                }
            )
        except WebPushException as exc:
            status_code = getattr(exc.response, "status_code", None)
            message = str(exc)
            deactivate = status_code in {404, 410}
            subscription_results.append(
                {
                    "endpoint": endpoint,
                    "active": not deactivate,
                    "last_error": message,
                    "success_at": None,
                }
            )
            failed_devices.append(
                {
                    "subscription_id": subscription["id"],
                    "device_label": subscription["device_label"],
                    "endpoint_tail": subscription["endpoint_tail"],
                    "status_code": status_code,
                    "error": message,
                    "deactivated": deactivate,
                }
            )
        except Exception as exc:
            message = str(exc)
            subscription_results.append(
                {
                    "endpoint": endpoint,
                    "active": True,
                    "last_error": message,
                    "success_at": None,
                }
            )
            failed_devices.append(
                {
                    "subscription_id": subscription["id"],
                    "device_label": subscription["device_label"],
                    "endpoint_tail": subscription["endpoint_tail"],
                    "error": message,
                    "deactivated": False,
                }
            )

    _persist_web_push_subscription_results(subscription_results, connection=connection)

    if not sent_devices:
        if failed_devices:
            raise RuntimeError(failed_devices[0].get("error") or "Traffic web push failed")
        raise RuntimeError("Traffic web push did not find any active devices")

    return {
        "provider": "web_push",
        "provider_message_id": f"{len(sent_devices)}-device{'s' if len(sent_devices) != 1 else ''}",
        "details": {
            "sent": sent_devices,
            "failed": failed_devices,
            "count": len(sent_devices),
        },
    }


def _deliver_notification(
    settings: dict[str, Any],
    *,
    title: str,
    body: str,
    url: str,
    connection: Any | None = None,
) -> dict[str, Any]:
    provider = settings.get("provider")
    if provider == "pushover":
        return _send_pushover(settings, title=title, body=body, url=url)
    if provider == "ntfy":
        return _send_ntfy(settings, title=title, body=body, url=url)
    if provider == "web_push":
        return _send_web_push(settings, title=title, body=body, url=url, connection=connection)
    raise RuntimeError("No supported notification provider selected")


def _record_notification_event(
    connection: Any,
    *,
    entry: dict[str, Any],
    session: dict[str, Any],
    status: str,
    suppression_reason: str = "",
    provider: str = "",
    provider_message_id: str = "",
    delivery_error: str = "",
    notification_title: str = "",
    notification_body: str = "",
    destination_url: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO traffic_notification_events (
            traffic_event_id,
            session_id,
            event_timestamp,
            project_slug,
            project_name,
            host,
            path,
            route_kind,
            person_key,
            visitor_profile_id,
            visitor_alias,
            ip,
            country_code,
            country,
            classification_state,
            verdict_label,
            returning_visitor,
            total_project_visits,
            projects_visited_in_window,
            status,
            suppression_reason,
            provider,
            provider_message_id,
            delivery_error,
            notification_title,
            notification_body,
            destination_url,
            details_json,
            created_at,
            delivered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry["event_id"],
            session["session_id"],
            entry["timestamp_iso"],
            session["project_slug"],
            session["project_name"],
            session["host"],
            entry["normalized_path"],
            entry["route_kind"],
            session["person_key"],
            session["visitor_profile_id"],
            session["visitor_alias"],
            session["ip"],
            session.get("country_code", ""),
            session.get("country", ""),
            session["classification_state"],
            session["verdict_label"],
            1 if session["returning_visitor"] else 0,
            session["total_project_visits"],
            session["projects_visited_in_window"],
            status,
            suppression_reason,
            provider,
            provider_message_id,
            delivery_error,
            notification_title,
            notification_body,
            destination_url,
            json.dumps(details or {}),
            iso_now(),
            iso_now() if status == "delivered" else None,
        ),
    )



def _load_unprocessed_browser_notification_candidates(
    connection: Any,
    *,
    limit: int,
    armed_at: str | None,
) -> list[Any]:
    params: list[Any] = []
    query = """
        SELECT
            id,
            received_at,
            occurred_at,
            host,
            project_slug,
            project_name,
            path,
            title,
            visitor_id,
            session_id,
            page_view_id,
            event_type,
            click_label,
            click_href,
            ip,
            country_code,
            country,
            area,
            city,
            max_scroll_depth_pct,
            visible_ms
        FROM traffic_browser_events
        WHERE NOT EXISTS (
            SELECT 1
            FROM traffic_notification_events
            WHERE traffic_notification_events.traffic_event_id = 'browser:' || traffic_browser_events.id
        )
          AND event_type IN ('page_view', 'click', 'outbound_click')
    """
    if armed_at:
        query += " AND received_at >= ?"
        params.append(armed_at)
    query += " ORDER BY received_at ASC, id ASC LIMIT ?"
    params.append(limit)

    try:
        return connection.execute(query, tuple(params)).fetchall()
    except Exception:
        return []


def _browser_event_to_entry(row: Any) -> dict[str, Any]:
    path = str(row["path"] or "/")
    return {
        "event_id": f"browser:{row['id']}",
        "timestamp_iso": row["received_at"] or row["occurred_at"],
        "normalized_path": path,
        "route_kind": detect_route_kind(path),
        "host": row["host"] or "",
        "ua": "",
    }


def _browser_event_to_session(row: Any) -> dict[str, Any]:
    ip = str(row["ip"] or "").strip()
    known = known_visitor_for_ip(ip) if ip else None
    label = str((known or {}).get("label") or "").strip()
    detail = str((known or {}).get("detail") or "").strip()

    city = str(row["city"] or "").strip()
    area = str(row["area"] or "").strip()
    country = str(row["country"] or "").strip()
    country_code = str(row["country_code"] or "").strip()

    visitor_alias = label or city or country or "Browser visitor"
    person_key = f"known:{label.lower()}:{ip}" if label else f"browser:{ip or row['session_id'] or row['visitor_id'] or row['id']}"
    visitor_profile_id = f"browser-{str(row['visitor_id'] or row['session_id'] or row['id']).replace(':', '-')}"

    return {
        "session_id": f"browser:{row['session_id'] or row['id']}",
        "project_slug": row["project_slug"] or "unknown",
        "project_name": row["project_name"] or "Unknown",
        "host": row["host"] or "",
        "person_key": person_key,
        "visitor_profile_id": visitor_profile_id,
        "visitor_alias": visitor_alias,
        "ip": ip,
        "country_code": country_code,
        "country": country,
        "area": area,
        "city": city,
        "classification_state": "human_confirmed" if label else "likely_human",
        "verdict_label": "Confirmed Human" if label else "Likely Human",
        "returning_visitor": False,
        "total_project_visits": 1,
        "projects_visited_in_window": 1,
    }


def _browser_notification_body(session: dict[str, Any], row: Any) -> str:
    event_type = str(row["event_type"] or "event").replace("_", " ")
    label = str(row["click_label"] or "").strip()
    action = f"{event_type}: {label}" if label else event_type
    location = ", ".join(
        value for value in (session.get("city"), session.get("area"), session.get("country")) if value
    ) or "Location pending"
    return "\n".join(
        [
            f"{session['verdict_label']} browser signal on {row['path']}",
            f"{action} · IP {session['ip']}",
            location,
        ]
    )


def _process_browser_notification_candidates(
    connection: Any,
    *,
    settings: dict[str, Any],
    operators: list[dict[str, Any]],
    mutes: list[dict[str, Any]],
    limit: int,
) -> dict[str, int]:
    rows = _load_unprocessed_browser_notification_candidates(
        connection,
        limit=limit,
        armed_at=settings.get("armed_at"),
    )

    checked = 0
    delivered = 0
    suppressed = 0
    errors = 0

    for row in rows:
        checked += 1
        entry = _browser_event_to_entry(row)
        session = _browser_event_to_session(row)

        suppression_reason = _suppression_reason(
            settings,
            session,
            entry,
            True,
            operators,
            mutes,
            connection,
        )

        title = _notification_title(session)
        body = _browser_notification_body(session, row)
        url = _notification_url(settings, session)

        if suppression_reason:
            _record_notification_event(
                connection,
                entry=entry,
                session=session,
                status="suppressed",
                suppression_reason=suppression_reason,
                notification_title=title,
                notification_body=body,
                destination_url=url,
                details={
                    "reason": suppression_reason,
                    "source": "browser_event",
                    "browser_event_id": int(row["id"]),
                    "browser_event_type": row["event_type"],
                },
            )
            connection.commit()
            suppressed += 1
            continue

        try:
            delivered_payload = _deliver_notification(
                settings,
                title=title,
                body=body,
                url=url,
                connection=connection,
            )
            _record_notification_event(
                connection,
                entry=entry,
                session=session,
                status="delivered",
                provider=delivered_payload["provider"],
                provider_message_id=delivered_payload.get("provider_message_id", ""),
                notification_title=title,
                notification_body=body,
                destination_url=url,
                details={
                    **delivered_payload.get("details", {}),
                    "source": "browser_event",
                    "browser_event_id": int(row["id"]),
                    "browser_event_type": row["event_type"],
                },
            )
            connection.commit()
            delivered += 1
        except Exception as exc:
            _record_notification_event(
                connection,
                entry=entry,
                session=session,
                status="error",
                provider=settings.get("provider", ""),
                delivery_error=str(exc),
                notification_title=title,
                notification_body=body,
                destination_url=url,
                details={
                    "error": str(exc),
                    "source": "browser_event",
                    "browser_event_id": int(row["id"]),
                    "browser_event_type": row["event_type"],
                },
            )
            connection.commit()
            errors += 1

    return {
        "checked": checked,
        "delivered": delivered,
        "suppressed": suppressed,
        "errors": errors,
    }


def process_notification_batch(limit: int = NOTIFICATION_BATCH_LIMIT) -> dict[str, Any]:
    if not persistence_enabled():
        return {
            "mode": "persistence_disabled",
            "checked": 0,
            "delivered": 0,
            "suppressed": 0,
            "errors": 0,
            "last_run_at": iso_now(),
        }

    settings = get_notification_settings()
    if not settings.get("enabled"):
        return {
            "mode": "disabled",
            "checked": 0,
            "delivered": 0,
            "suppressed": 0,
            "errors": 0,
            "last_run_at": iso_now(),
        }

    if not _provider_ready(settings):
        return {
            "mode": "provider_not_configured",
            "checked": 0,
            "delivered": 0,
            "suppressed": 0,
            "errors": 0,
            "last_run_at": iso_now(),
        }

    sync_configured_logs_to_persistence()

    with _connect() as connection:
        _ensure_schema(connection)
        operators = list_operator_identities()
        mutes = list_notification_mutes()
        candidates = _load_unprocessed_candidates(
            connection,
            limit=limit,
            armed_at=settings.get("armed_at"),
        )

        checked = 0
        delivered = 0
        suppressed = 0
        errors = 0

        for entry in candidates:
            checked += 1

            if not is_allowed_host(entry["host"]):
                continue
            if should_ignore_entry(entry):
                continue

            session, is_primary_navigation_event = _find_session_for_entry(connection, entry)
            if not session:
                continue

            suppression_reason = _suppression_reason(
                settings,
                session,
                entry,
                is_primary_navigation_event,
                operators,
                mutes,
                connection,
            )
            title = _notification_title(session)
            body = _notification_body(session, entry)
            url = _notification_url(settings, session)

            if suppression_reason:
                _record_notification_event(
                    connection,
                    entry=entry,
                    session=session,
                    status="suppressed",
                    suppression_reason=suppression_reason,
                    notification_title=title,
                    notification_body=body,
                    destination_url=url,
                    details={"reason": suppression_reason},
                )
                connection.commit()
                suppressed += 1
                continue

            try:
                delivered_payload = _deliver_notification(
                    settings,
                    title=title,
                    body=body,
                    url=url,
                    connection=connection,
                )
                _record_notification_event(
                    connection,
                    entry=entry,
                    session=session,
                    status="delivered",
                    provider=delivered_payload["provider"],
                    provider_message_id=delivered_payload.get("provider_message_id", ""),
                    notification_title=title,
                    notification_body=body,
                    destination_url=url,
                    details=delivered_payload.get("details", {}),
                )
                connection.commit()
                delivered += 1
            except Exception as exc:
                _record_notification_event(
                    connection,
                    entry=entry,
                    session=session,
                    status="error",
                    provider=settings.get("provider", ""),
                    delivery_error=str(exc),
                    notification_title=title,
                    notification_body=body,
                    destination_url=url,
                    details={"error": str(exc)},
                )
                connection.commit()
                errors += 1

        browser_result = _process_browser_notification_candidates(
            connection,
            settings=settings,
            operators=operators,
            mutes=mutes,
            limit=max(25, limit),
        )
        checked += browser_result["checked"]
        delivered += browser_result["delivered"]
        suppressed += browser_result["suppressed"]
        errors += browser_result["errors"]

    return {
        "mode": "running",
        "checked": checked,
        "delivered": delivered,
        "suppressed": suppressed,
        "errors": errors,
        "last_run_at": iso_now(),
    }


def send_test_notification() -> dict[str, Any]:
    settings = get_notification_settings()
    if not _provider_ready(settings):
        raise RuntimeError("Configure a notification provider before sending a test alert.")

    title = "🇨🇦 Traffic · Test visitor"
    body = "\n".join(
        [
            "Likely Human hit /test-notification",
            "IP 172.219.42.87 · New · Project visits 1",
            "Grande Prairie, Alberta, Canada",
        ]
    )
    url = f"{settings.get('site_base_url') or SITE_BASE_URL}/"
    return _deliver_notification(settings, title=title, body=body, url=url)
