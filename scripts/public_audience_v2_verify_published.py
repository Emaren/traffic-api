#!/usr/bin/env python3
"""Read-only production verifier: public Traffic DB, FastAPI and AoE2WAR API.

Only reports VERIFIED if the expected 131 full UTC days and exact canonical
counts agree across all three layers. Never writes data or changes services.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from scripts import public_audience_v2_release_manifest as manifest
from scripts import public_audience_v2_atomic_publish as publisher

EXPECTED = manifest.days_between(manifest.START, manifest.END_EXCLUSIVE)


def require(condition: bool, reason: str) -> None:
    publisher.require(condition, reason)


def fetch_json(url: str, *, timeout: float = 12) -> dict:
    require(url.startswith("http://127.0.0.1:")
            or url.startswith("https://aoe2war.com/"),
            "unapproved audience API origin")
    req = Request(url, headers={"Accept": "application/json",
                                "Cache-Control": "no-cache"})
    with urlopen(req, timeout=timeout) as response:
        require(response.status == 200,
                "audience API returned non-200 response")
        require(int(response.headers.get("Content-Length", "0")) < 5_000_000,
                "audience API response unexpectedly large")
        payload = response.read(5_000_001)
        require(len(payload) <= 5_000_000, "audience API response oversized")
        obj = json.loads(payload)
        require(isinstance(obj, dict), "audience API invalid JSON object")
        return obj


def verify_api_points(data: dict, *, frontend: bool) -> dict[str, list[int]]:
    require(data.get("ok") is True, "audience API reported not OK")
    dates = data.get("points")
    require(isinstance(dates, list) and len(dates) == 131,
            "published audience point count mismatch")
    if frontend:
        require(data.get("startDate") == "2026-06-11"
                and data.get("coverageEndedAt") == "2026-10-19",
                "AoE2WAR frontend coverage mismatch")
    else:
        require(data.get("project_slug") == publisher.PROJECT
                and data.get("coverage_started_at") == "2026-06-11"
                and data.get("coverage_ended_at") == "2026-10-19",
                "Traffic API coverage mismatch")
    result = {}
    for row in dates:
        require(isinstance(row, dict), "non-object audience point")
        day = row.get("date")
        values = row.get("values")
        require(isinstance(values, dict)
                and all(type(values.get(k)) is int for k in (
                    "totalTraffic", "suspectedHuman", "confirmedHuman"
                )), "invalid audience counts")
        require(day not in result and day in EXPECTED,
                "duplicate, unknown or partial UTC audience day")
        result[day] = [
            values["totalTraffic"], values["suspectedHuman"],
            values["confirmedHuman"],
        ]
        require(result[day][0] >= result[day][1]
                >= result[day][2] >= 0,
                "invalid audience hierarchy")
        if not frontend:
            calculated = datetime.fromisoformat(row["calculatedAt"])
            require(calculated.tzinfo is not None
                    and calculated.astimezone(timezone.utc)
                    >= datetime.combine(
                        date.fromisoformat(day) + timedelta(days=1),
                        datetime.min.time(), tzinfo=timezone.utc
                    ), "backend point published before UTC day was complete")
    require(sorted(result) == EXPECTED,
            "audience API has missing or shuffled dates")
    require(manifest.sha(result) == publisher.EXPECTED_CANDIDATE_SHA,
            "published audience API checksum mismatch")
    return result


def verify(source: Path, backend_url: str, frontend_url: str) -> dict:
    require(source.is_file() and not source.is_symlink(),
            "Traffic database missing or symlink")
    with closing(sqlite3.connect(
        f"file:{source.resolve().as_posix()}?mode=ro",
        uri=True, timeout=3,
    )) as db:
        db.execute("PRAGMA query_only=ON")
        rows = publisher.public_rows(db)
    require(len(rows) == 131, "Traffic DB public day count mismatch")
    matrix = publisher.audience_matrix(rows)
    require(manifest.sha(matrix) == publisher.EXPECTED_CANDIDATE_SHA,
            "Traffic DB published day/count SHA mismatch")
    backend = verify_api_points(fetch_json(backend_url), frontend=False)
    frontend = verify_api_points(fetch_json(frontend_url), frontend=True)
    require(matrix == backend == frontend,
            "Traffic DB/backend/AoE2WAR API audience mismatched")
    return {
        "status": "VERIFIED_PUBLISHED",
        "coverage_first": "2026-06-11", "coverage_last": "2026-10-19",
        "days": 131,
        "daily_sha256": publisher.EXPECTED_CANDIDATE_SHA,
        "totals": [sum(row[i] for row in matrix.values()) for i in range(3)],
        "same_as_canonical_checkpoint": True,
        "no_partial_day": True,
        "current_utc_daily_maintenance": False,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, required=True)
    cli.add_argument(
        "--backend", default="http://127.0.0.1:3345/api/projects/aoe2hdbets/public-audience-series")
    cli.add_argument(
        "--frontend", default="https://aoe2war.com/api/traffic/public")
    opts = cli.parse_args()
    try:
        print(json.dumps(verify(opts.source, opts.backend, opts.frontend),
                         sort_keys=True))
        return 0
    except Exception as exc:
        print("VERIFICATION FAILED:", type(exc).__name__, str(exc),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
