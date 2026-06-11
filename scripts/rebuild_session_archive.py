#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.services.traffic.config import PROJECTS
from app.services.traffic.overview import collect_recent_entries_with_source
from app.services.traffic.persistence import _connect, _ensure_schema
from app.services.traffic.sessions import build_sessions


CREATE_SQL = """
CREATE TABLE IF NOT EXISTS traffic_session_archive (
    session_id TEXT PRIMARY KEY,
    project_slug TEXT NOT NULL,
    project_name TEXT NOT NULL,
    person_key TEXT NOT NULL,
    visitor_profile_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    classification_state TEXT NOT NULL,
    route_kind TEXT NOT NULL,
    suspicious_score INTEGER NOT NULL DEFAULT 0,
    known_automation INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

INDEX_SQL = [
    """
    CREATE INDEX IF NOT EXISTS idx_traffic_session_archive_project_ended
    ON traffic_session_archive(project_slug, ended_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_traffic_session_archive_project_class_route_ended
    ON traffic_session_archive(project_slug, classification_state, route_kind, ended_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_traffic_session_archive_person_project_ended
    ON traffic_session_archive(person_key, project_slug, ended_at DESC);
    """,
]


UPSERT_SQL = """
INSERT OR REPLACE INTO traffic_session_archive (
    session_id,
    project_slug,
    project_name,
    person_key,
    visitor_profile_id,
    first_seen_at,
    ended_at,
    classification_state,
    route_kind,
    suspicious_score,
    known_automation,
    payload_json,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""


def project_slugs(value: str) -> set[str]:
    if value == "all":
        return {project["slug"] for project in PROJECTS}
    wanted = {part.strip() for part in value.split(",") if part.strip()}
    known = {project["slug"] for project in PROJECTS}
    unknown = wanted - known
    if unknown:
        raise SystemExit(f"Unknown project slug(s): {', '.join(sorted(unknown))}")
    return wanted


def compact_payload(session: dict[str, Any]) -> str:
    return json.dumps(session, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Rebuild persisted Traffic session archive.")
    parser.add_argument("--project", default="aoe2hdbets", help="Project slug, comma list, or all")
    parser.add_argument("--replace", action="store_true", help="Delete existing archive rows for selected projects first")
    args = parser.parse_args()

    selected_slugs = project_slugs(args.project)
    now = datetime.now(timezone.utc).isoformat()

    print("selected_projects:", ",".join(sorted(selected_slugs)))

    entries, source_mode = collect_recent_entries_with_source(
        window_hours=None,
        project_slugs=selected_slugs,
    )
    print("source_mode:", source_mode)
    print("entries:", len(entries))

    sessions = build_sessions(entries)
    print("sessions:", len(sessions))

    rows = []
    for session in sessions:
        rows.append(
            (
                session["session_id"],
                session["project_slug"],
                session.get("project_name", ""),
                session["person_key"],
                session.get("visitor_profile_id", ""),
                session["first_seen_at"],
                session["ended_at"],
                session["classification_state"],
                session.get("route_kind", ""),
                int(session.get("suspicious_score", 0) or 0),
                1 if session.get("known_automation") else 0,
                compact_payload(session),
                now,
            )
        )

    with _connect() as connection:
        _ensure_schema(connection)
        connection.execute(CREATE_SQL)
        for sql in INDEX_SQL:
            connection.execute(sql)

        if args.replace:
            for slug in selected_slugs:
                connection.execute(
                    "DELETE FROM traffic_session_archive WHERE project_slug = ?",
                    (slug,),
                )

        connection.executemany(UPSERT_SQL, rows)
        connection.commit()

    print("upserted:", len(rows))
    print("updated_at:", now)


if __name__ == "__main__":
    main()
