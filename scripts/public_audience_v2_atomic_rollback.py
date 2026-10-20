#!/usr/bin/env python3
"""Operator-only rollback of precisely the AoE2WAR V2 public-audience cutover.

Not a scheduled job. Requires pinned release commit, private preimage receipt
from the initial transaction, unchanged 131-day published matrix and both
project-service/canary locks. Restores only AoE2WAR rows in one transaction.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

from scripts import public_audience_v2_atomic_publish as publication
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_release_manifest as manifest

ROLLBACK_PHRASE = "RESTORE AOE2WAR PRE-PUBLICATION 128-DAY AUDIENCE"


def require(condition: bool, message: str) -> None:
    guard.require(condition, message)


def verified_preimage(path: Path, private_directory: Path) -> list[dict[str, Any]]:
    require(path.is_file() and not path.is_symlink(),
            "private pre-publication rollback receipt absent")
    require(path.parent.resolve() == private_directory.resolve(),
            "rollback receipt must reside in private canary directory")
    require(path.name.startswith("v2-public-audience-preimage-")
            and path.suffix == ".json", "unexpected rollback receipt filename")
    require(path.stat().st_mode & 0o777 == 0o600,
            "rollback receipt must be private mode 0600")
    require(path.stat().st_size < 512 * 1024,
            "rollback receipt unreasonably large")
    record = json.loads(path.read_text())
    require(record.get("kind") == "pre-publication-public-audience-table-only"
            and record.get("project") == publication.PROJECT
            and record.get("publication") == "preimage-not-authorization",
            "rollback receipt is not the original public-row preimage")
    rows = record["rows"]
    require(isinstance(rows, list) and len(rows) == 128,
            "unexpected old public audience row count")
    require(all(
        isinstance(row, dict)
        and set(row) == {"day", "total", "potential", "confirmed", "updated_at"}
        and isinstance(row["day"], str)
        and isinstance(row["updated_at"], str)
        and all(type(row[k]) is int for k in ("total", "potential", "confirmed"))
        and row["total"] >= row["potential"] >= row["confirmed"] >= 0
        for row in rows
    ), "invalid old public audience row structure")
    require(
        [row["day"] for row in rows]
        == sorted(row["day"] for row in rows),
        "old audience preimage is not strictly date ordered",
    )
    require(len({row["day"] for row in rows}) == 128
            and rows[0]["day"] == "2026-06-09"
            and rows[-1]["day"] == "2026-10-14",
            "invalid old historical coverage")
    prior_matrix = publication.audience_matrix(rows)
    require(record.get("day_count") == 128
            and record.get("matrix_sha256") == publication.EXPECTED_LEGACY_SHA
            and manifest.sha(prior_matrix) == publication.EXPECTED_LEGACY_SHA
            and record.get("rows_sha256") == manifest.sha(rows),
            "original pre-publication content proof mismatch")
    return rows


def transactional_restore(
    db: sqlite3.Connection, old_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Atomic CAS against proposed V2 after-image or exact idempotent no-op."""
    require(len(old_rows) == 128
            and manifest.sha(publication.audience_matrix(old_rows))
            == publication.EXPECTED_LEGACY_SHA,
            "invalid historical rollback target")
    db.execute("BEGIN IMMEDIATE")
    try:
        current_rows = publication.public_rows(db)
        current = manifest.sha(publication.audience_matrix(current_rows))
        if current == publication.EXPECTED_LEGACY_SHA:
            require(current_rows == old_rows,
                    "old day counts match but timestamps changed")
            db.rollback()
            return {"result": "ALREADY_RESTORED",
                    "after_sha256": current, "written_days": 0}
        require(current == publication.EXPECTED_CANDIDATE_SHA
                and len(current_rows) == publication.RELEASE_COUNT,
                "unexpected changed public archive, rollback refused")
        db.execute(
            "DELETE FROM traffic_public_daily_audience_rollups WHERE project_slug=?",
            (publication.PROJECT,),
        )
        db.executemany(
            """INSERT INTO traffic_public_daily_audience_rollups
               (project_slug,bucket_day,total_traffic,suspected_human,
                confirmed_human,updated_at) VALUES(?,?,?,?,?,?)""",
            [
                (publication.PROJECT, row["day"], row["total"], row["potential"],
                 row["confirmed"], row["updated_at"])
                for row in old_rows
            ],
        )
        actual = publication.public_rows(db)
        require(actual == old_rows and len(actual) == 128,
                "pre-publication rows not exactly restored")
        db.commit()
        return {
            "result": "RESTORED_OLD_PUBLIC_AUDIENCE",
            "before_sha256": current,
            "after_sha256": publication.EXPECTED_LEGACY_SHA,
            "written_days": 128,
        }
    except BaseException:
        db.rollback()
        raise


def execute(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(__file__).resolve().parents[1]
    require(guard.cmd_output("git", "rev-parse", "HEAD", cwd=repo) == args.require_sha,
            "wrong release revision")
    require(not guard.cmd_output("git", "status", "--porcelain", cwd=repo),
            "dirty Traffic release checkout")
    require(args.approval_phrase == ROLLBACK_PHRASE,
            "explicit rollback operator approval required")
    require(args.source.is_file() and not args.source.is_symlink(),
            "live source database missing or symlink")
    require(args.private_dir.is_dir() and not args.private_dir.is_symlink()
            and args.private_dir.stat().st_mode & 0o077 == 0,
            "insecure private backup directory")
    old_rows = verified_preimage(args.preimage, args.private_dir)
    guard.require_worker_priority()
    guard.resource_headroom(args.private_dir / "checkpoint.sqlite3", 12, 6)

    with publication.exclusive_file_lock(args.private_dir / ".canary.lock"):
        with publication.exclusive_file_lock(publication.ROLLUP_LOCK):
            require(guard.worker_idle(), "project worker active; safe retry later")
            # Source must only be the configured Traffic DB, not a test fixture.
            with closing(sqlite3.connect(
                f"file:{args.source.resolve().as_posix()}?mode=rw",
                uri=True, timeout=5,
            )) as db:
                db.execute("PRAGMA busy_timeout=5000")
                return transactional_restore(db, old_rows)


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, required=True)
    cli.add_argument("--private-dir", type=Path, required=True)
    cli.add_argument("--preimage", type=Path, required=True)
    cli.add_argument("--require-sha", required=True)
    cli.add_argument("--approval-phrase", required=True)
    args = cli.parse_args()
    try:
        print(json.dumps(execute(args), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, OSError, KeyError, TypeError,
            sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
