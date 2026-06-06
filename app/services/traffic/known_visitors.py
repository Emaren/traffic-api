from __future__ import annotations

from time import monotonic
from threading import Lock
from typing import Any

from app.services.traffic.parse import iso_now
from app.services.traffic.persistence import _connect, _ensure_schema

ALLOWED_RULE_TYPES = {"ip"}
ALLOWED_IDENTITY_KINDS = {
    "owner",
    "family",
    "known_player",
    "known_human",
    "known_automation",
    "crawler",
}
HUMAN_IDENTITY_KINDS = {"owner", "family", "known_player", "known_human"}

_STATIC_KNOWN_VISITORS_BY_IP: dict[str, dict[str, str]] = {
    "172.219.42.87": {"label": "Tony", "detail": "owner", "identity_kind": "owner", "confidence": "confirmed"},
    "104.28.116.13": {"label": "Tony", "detail": "owner", "identity_kind": "owner", "confidence": "confirmed"},
    "104.28.116.14": {"label": "Tony", "detail": "owner", "identity_kind": "owner", "confidence": "confirmed"},
    "187.137.98.115": {"label": "Julio", "detail": "known player", "identity_kind": "known_player", "confidence": "confirmed"},
    "174.90.223.103": {"label": "Joe", "detail": "likely family", "identity_kind": "family", "confidence": "confirmed"},
    "68.131.37.96": {"label": "Jim", "detail": "known player", "identity_kind": "known_player", "confidence": "confirmed"},
}

_CACHE_LOCK = Lock()
_CACHE_TTL_SECONDS = 30.0
_IDENTITY_CACHE: tuple[float, dict[str, dict[str, str]]] | None = None


def _normalize_identity(row: Any) -> dict[str, str]:
    detail = str(row["detail"] or row["notes"] or "known visitor").strip()
    return {
        "label": str(row["label"] or row["match_value"]).strip(),
        "detail": detail,
        "identity_kind": str(row["identity_kind"] or "known_human").strip(),
        "confidence": str(row["confidence"] or "confirmed").strip(),
        "rule_type": str(row["rule_type"]).strip(),
        "match_value": str(row["match_value"]).strip(),
        "notes": str(row["notes"] or "").strip(),
    }


def clear_known_identity_cache() -> None:
    global _IDENTITY_CACHE
    with _CACHE_LOCK:
        _IDENTITY_CACHE = None


def list_known_identities(*, active_only: bool = False) -> list[dict[str, Any]]:
    with _connect() as connection:
        _ensure_schema(connection)
        query = """
            SELECT id, rule_type, match_value, label, detail, identity_kind, confidence, notes, active, created_at, updated_at
            FROM traffic_known_identities
        """
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY active DESC, updated_at DESC, id DESC"
        rows = connection.execute(query).fetchall()

    return [
        {
            "id": int(row["id"]),
            "rule_type": row["rule_type"],
            "match_value": row["match_value"],
            "label": row["label"],
            "detail": row["detail"],
            "identity_kind": row["identity_kind"],
            "confidence": row["confidence"],
            "notes": row["notes"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def create_known_identity(payload: dict[str, Any]) -> dict[str, Any]:
    rule_type = str(payload.get("rule_type") or "ip").strip()
    match_value = str(payload.get("match_value") or "").strip()
    label = str(payload.get("label") or match_value).strip()
    detail = str(payload.get("detail") or payload.get("notes") or "known visitor").strip()
    identity_kind = str(payload.get("identity_kind") or "known_human").strip()
    confidence = str(payload.get("confidence") or "confirmed").strip()
    notes = str(payload.get("notes") or "").strip()

    if rule_type not in ALLOWED_RULE_TYPES:
        raise ValueError("Unsupported known identity rule type")
    if not match_value:
        raise ValueError("Known identity match value is required")
    if not label:
        raise ValueError("Known identity label is required")
    if identity_kind not in ALLOWED_IDENTITY_KINDS:
        raise ValueError("Unsupported known identity kind")

    now = iso_now()

    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            """
            INSERT INTO traffic_known_identities (
                rule_type, match_value, label, detail, identity_kind, confidence, notes, active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(rule_type, match_value) DO UPDATE SET
                label = excluded.label,
                detail = excluded.detail,
                identity_kind = excluded.identity_kind,
                confidence = excluded.confidence,
                notes = excluded.notes,
                active = 1,
                updated_at = excluded.updated_at
            """,
            (rule_type, match_value, label, detail, identity_kind, confidence, notes, now, now),
        )
        connection.commit()
        row = connection.execute(
            """
            SELECT id, rule_type, match_value, label, detail, identity_kind, confidence, notes, active, created_at, updated_at
            FROM traffic_known_identities
            WHERE rule_type = ? AND match_value = ?
            """,
            (rule_type, match_value),
        ).fetchone()

    clear_known_identity_cache()

    if not row:
        raise RuntimeError("Could not save known identity")

    return {
        "id": int(row["id"]),
        "rule_type": row["rule_type"],
        "match_value": row["match_value"],
        "label": row["label"],
        "detail": row["detail"],
        "identity_kind": row["identity_kind"],
        "confidence": row["confidence"],
        "notes": row["notes"],
        "active": bool(row["active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def delete_known_identity(identity_id: int) -> None:
    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute("DELETE FROM traffic_known_identities WHERE id = ?", (identity_id,))
        connection.commit()
    clear_known_identity_cache()


def _load_active_identities_by_ip() -> dict[str, dict[str, str]]:
    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            """
            SELECT rule_type, match_value, label, detail, identity_kind, confidence, notes
            FROM traffic_known_identities
            WHERE active = 1
            """
        ).fetchall()

    identities: dict[str, dict[str, str]] = {}

    for row in rows:
        if row["rule_type"] != "ip":
            continue
        identities[str(row["match_value"]).strip()] = _normalize_identity(row)

    return identities


def _cached_active_identities_by_ip() -> dict[str, dict[str, str]]:
    global _IDENTITY_CACHE

    now = monotonic()
    with _CACHE_LOCK:
        if _IDENTITY_CACHE and now - _IDENTITY_CACHE[0] < _CACHE_TTL_SECONDS:
            return _IDENTITY_CACHE[1]

    try:
        identities = _load_active_identities_by_ip()
    except Exception:
        identities = {}

    merged = {**_STATIC_KNOWN_VISITORS_BY_IP, **identities}

    with _CACHE_LOCK:
        _IDENTITY_CACHE = (now, merged)

    return merged


def known_visitor_for_ip(ip: str | None) -> dict[str, str] | None:
    cleaned = (ip or "").strip()
    if not cleaned:
        return None
    return _cached_active_identities_by_ip().get(cleaned)


def apply_known_visitor_confirmation(session: dict[str, Any]) -> dict[str, str] | None:
    known_visitor = known_visitor_for_ip(session.get("ip"))
    if not known_visitor:
        return None

    label = known_visitor["label"]
    detail = known_visitor["detail"]
    identity_kind = known_visitor.get("identity_kind", "known_human")

    session["known_visitor_label"] = label
    session["known_visitor_detail"] = detail
    session["known_visitor_kind"] = identity_kind
    session["known_visitor_confirmed"] = known_visitor.get("confidence") == "confirmed"

    reasons = session.get("classification_reasons")
    if not isinstance(reasons, list):
        reasons = []

    automation_or_burst = (
        session.get("known_automation")
        or session.get("is_burst_cluster")
        or session.get("is_chain_poll_cluster")
        or session.get("route_bundle_spam")
        or "chain_rpc_poll" in reasons
        or "distributed_ip_burst" in reasons
    )

    if identity_kind in {"known_automation", "crawler"}:
        session["classification_state"] = "bot" if identity_kind == "crawler" else "browser_script"
        session["human_confidence"] = 0
        session["suspicious_score"] = max(int(session.get("suspicious_score") or 0), 40)
        if "known_non_human_identity" not in reasons:
            reasons.append("known_non_human_identity")
        session["classification_reasons"] = reasons
        session["classification_summary"] = f"Known non-human identity: {label} is registered as {detail}."
        session["attention_label"] = "Known automation"
        session["attention_summary"] = f"{label} · {detail}. Traffic classified this from the known identity registry."
        session["human_confirmed"] = False
        return known_visitor

    if identity_kind in HUMAN_IDENTITY_KINDS and not automation_or_burst:
        session["classification_state"] = "human_confirmed"
        session["human_confidence"] = max(int(session.get("human_confidence") or 0), 100)
        session["suspicious_score"] = min(int(session.get("suspicious_score") or 0), 5)
        if "known_confirmed_visitor_ip" not in reasons:
            reasons.append("known_confirmed_visitor_ip")
        session["classification_reasons"] = reasons
        session["classification_summary"] = (
            f"Confirmed human: {label} is registered as a known visitor for this IP."
        )
        session["attention_label"] = "Known human"
        session["attention_summary"] = (
            f"{label} · {detail}. Traffic upgraded this session because the IP is in the known identity registry."
        )
        session["data_confidence_label"] = "Confirmed"
        session["data_confidence_summary"] = (
            "This session has operator-confirmed human context from the known identity registry."
        )
        session["human_confirmed"] = True
        return known_visitor

    if "known_identity_unusual_behavior" not in reasons:
        reasons.append("known_identity_unusual_behavior")
    session["classification_reasons"] = reasons
    session["attention_label"] = "Known identity watch"
    session["attention_summary"] = (
        f"{label} · {detail}, but the behavior still looks automated or burst-like. Traffic did not blindly upgrade it."
    )
    session["human_confirmed"] = session.get("classification_state") == "human_confirmed"

    return known_visitor
