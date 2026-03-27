from __future__ import annotations

from typing import Any

from app.services.traffic.normalize import project_for_host
from app.services.traffic.parse import iso_now
from app.services.traffic.persistence import _connect, _ensure_schema

ALLOWED_VISIBILITY_RULE_TYPES = {
    "ip",
    "path",
    "project_slug",
    "host",
}


def list_visibility_rules(*, active_only: bool = False) -> list[dict[str, Any]]:
    with _connect() as connection:
        _ensure_schema(connection)
        query = """
            SELECT id, rule_type, match_value, label, reason, active, created_at
            FROM traffic_visibility_rules
        """
        params: tuple[Any, ...] = ()
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY active DESC, created_at DESC, id DESC"
        rows = connection.execute(query, params).fetchall()

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


def visibility_signature() -> tuple[str, ...]:
    active_rules = list_visibility_rules(active_only=True)
    return tuple(
        sorted(
            f"{rule['rule_type']}:{rule['match_value']}"
            for rule in active_rules
            if rule["active"]
        )
    )


def create_visibility_rule(payload: dict[str, Any]) -> dict[str, Any]:
    rule_type = str(payload.get("rule_type") or "").strip()
    match_value = str(payload.get("match_value") or "").strip()
    if rule_type not in ALLOWED_VISIBILITY_RULE_TYPES:
        raise ValueError("Unsupported visibility rule type")
    if not match_value:
        raise ValueError("Visibility match value is required")

    label = str(payload.get("label") or match_value).strip() or match_value
    reason = str(payload.get("reason") or "Hidden from Traffic observatory surfaces").strip()
    created_at = iso_now()

    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            """
            INSERT INTO traffic_visibility_rules (
                rule_type,
                match_value,
                label,
                reason,
                active,
                created_at
            ) VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(rule_type, match_value) DO UPDATE SET
                label = excluded.label,
                reason = excluded.reason,
                active = 1,
                created_at = excluded.created_at
            """,
            (rule_type, match_value, label, reason, created_at),
        )
        connection.commit()
        row = connection.execute(
            """
            SELECT id, rule_type, match_value, label, reason, active, created_at
            FROM traffic_visibility_rules
            WHERE rule_type = ? AND match_value = ?
            """,
            (rule_type, match_value),
        ).fetchone()

    if not row:
        raise RuntimeError("Could not save visibility rule")

    return {
        "id": int(row["id"]),
        "rule_type": row["rule_type"],
        "match_value": row["match_value"],
        "label": row["label"],
        "reason": row["reason"],
        "active": bool(row["active"]),
        "created_at": row["created_at"],
    }


def delete_visibility_rule(rule_id: int) -> None:
    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(
            "DELETE FROM traffic_visibility_rules WHERE id = ?",
            (rule_id,),
        )
        connection.commit()


def entry_hidden_by_visibility_rules(
    entry: dict[str, Any],
    *,
    rules: list[dict[str, Any]] | None = None,
) -> bool:
    active_rules = rules if rules is not None else list_visibility_rules(active_only=True)
    project_slug = project_for_host(entry["host"])["slug"]

    for rule in active_rules:
        if not rule["active"]:
            continue
        if rule["rule_type"] == "ip" and entry["ip"] == rule["match_value"]:
            return True
        if rule["rule_type"] == "path" and entry["normalized_path"] == rule["match_value"]:
            return True
        if rule["rule_type"] == "host" and entry["host"] == rule["match_value"]:
            return True
        if rule["rule_type"] == "project_slug" and project_slug == rule["match_value"]:
            return True

    return False
