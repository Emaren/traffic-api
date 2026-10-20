#!/usr/bin/env python3
"""Operator-gated, transactional public audience V2 candidate publisher.

PREVIEW is the default. Never schedule this program. The apply path is held
for separately documented explicit operator approval and production review.
No Wolo, wager, site, or systemd writes. June 11–October 19 UTC ONLY.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sqlite3
import stat
import sys
from contextlib import closing, contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from scripts import public_audience_v2_release_manifest as manifest
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions

PROJECT = "aoe2hdbets"
RELEASE_FIRST = "2026-06-11"
RELEASE_LAST = "2026-10-19"
RELEASE_COUNT = 131
EXPECTED_SOURCE_SHA = guard.FROZEN_DIGEST
EXPECTED_PRIVATE_SHA = "30701fe697faca6098cb72c82c98b8b1fed8e9effeffa9190bc104cde643b61d"
EXPECTED_CANDIDATE_SHA = "84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4"
EXPECTED_LEGACY_SHA = "61de508cb57292ca006f0beb7b535ec91d6ab84f9da1a9e2f9e0251a822bd38b"
APPROVAL_PHRASE = "APPROVE 131 FULL UTC DAYS 2026-06-11 THROUGH 2026-10-19"
ROLLUP_LOCK = Path("/run/traffic-rollups/aoe2hdbets.lock")


def require(cond: bool, message: str) -> None:
    guard.require(cond, message)


def public_rows(db: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        {
            "day": str(day),
            "total": int(total),
            "potential": int(potential),
            "confirmed": int(confirmed),
            "updated_at": str(updated),
        }
        for day, total, potential, confirmed, updated in db.execute(
            """SELECT bucket_day,total_traffic,suspected_human,confirmed_human,updated_at
               FROM traffic_public_daily_audience_rollups
               WHERE project_slug=?
               ORDER BY bucket_day""", (PROJECT,)
        )
    ]


def audience_matrix(rows: list[dict[str, Any]]) -> dict[str, list[int]]:
    result = {}
    for item in rows:
        day = item["day"]
        require(day not in result, "duplicate public audience day")
        result[day] = [item["total"], item["potential"], item["confirmed"]]
    return result


def validate_candidate(state: Path, backup: Path) -> dict[str, list[int]]:
    require(state.is_file() and not state.is_symlink(),
            "completed private checkpoint required")
    require(backup.is_file() and not backup.is_symlink(),
            "verified completed checkpoint backup required")
    require(state.resolve() != backup.resolve(), "checkpoint backup aliases original")
    for path in (state, backup):
        require(path.stat().st_mode & 0o777 == 0o600,
                "private SQLite files must be mode 0600")
    m = guard.checkpoint_info(state)
    saved = guard.checkpoint_info(backup)
    require(m == saved and m["phase"] == "PASS2_COMPLETE",
            "frozen checkpoint and independent backup metadata mismatch")
    require(m["p1_digest"] == m["p2_digest"] == EXPECTED_SOURCE_SHA,
            "complete source pass digest drift")
    full = sessions.shadow_daily(state)
    require(manifest.sha(full) == EXPECTED_PRIVATE_SHA,
            "full private shadow checksum drift")
    require(manifest.sha(sessions.shadow_daily(backup)) == EXPECTED_PRIVATE_SHA,
            "private backup daily checksum drift")
    dates = manifest.days_between(manifest.START, manifest.END_EXCLUSIVE)
    require(len(dates) == RELEASE_COUNT
            and dates[0] == RELEASE_FIRST and dates[-1] == RELEASE_LAST,
            "changed release date range")
    require(set(full) == set(dates) | {"2026-06-10"},
            "unexpected private full-day coverage")
    candidate = {day: full[day] for day in dates}
    for triplet in candidate.values():
        require(len(triplet) == 3 and all(type(v) is int for v in triplet)
                and triplet[0] > 0 and triplet[0] >= triplet[1] >= triplet[2] >= 0,
                "invalid full-day audience hierarchy")
    require(manifest.sha(candidate) == EXPECTED_CANDIDATE_SHA,
            "pinned full-day candidate digest mismatch")
    return candidate


def preimage_backup(dirpath: Path, prior: list[dict[str, Any]]) -> Path:
    """Write durable 0600 copy of the exact old public rows before deleting any."""
    require(dirpath.is_dir() and not dirpath.is_symlink(), "private backup directory missing")
    require(dirpath.stat().st_mode & 0o077 == 0,
            "private backup directory must not be accessible to others")
    record = {
        "project": PROJECT,
        "kind": "pre-publication-public-audience-table-only",
        "day_count": len(prior),
        "matrix_sha256": manifest.sha(audience_matrix(prior)),
        "rows_sha256": manifest.sha(prior),
        "rows": prior,
        "publication": "preimage-not-authorization",
    }
    path = dirpath / (
        "v2-public-audience-preimage-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    directory = os.open(dirpath, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def transactional_replace(
    db: sqlite3.Connection,
    candidate: dict[str, list[int]],
    *,
    backup_old: Callable[[list[dict[str, Any]]], Path],
    expected_previous_sha: str = EXPECTED_LEGACY_SHA,
) -> dict[str, Any]:
    """CAS + backup + same-transaction replacement, never partial public rows.

    Connection may be injected for sqlite fixture tests. Caller owns locks.
    """
    require(len(candidate) == RELEASE_COUNT and
            sorted(candidate) == manifest.days_between(manifest.START, manifest.END_EXCLUSIVE),
            "public candidate has missing or unexpected days")
    require(manifest.sha(candidate) == EXPECTED_CANDIDATE_SHA,
            "full-day candidate sha drift")

    db.execute("BEGIN IMMEDIATE")
    try:
        prior = public_rows(db)
        previous_sha = manifest.sha(audience_matrix(prior))
        if previous_sha == EXPECTED_CANDIDATE_SHA:
            db.rollback()  # exact idempotent no-op; no update timestamps
            return {
                "result": "ALREADY_PUBLISHED", "previous_sha256": previous_sha,
                "after_sha256": previous_sha, "backup_file": None,
                "written_days": 0,
            }
        require(previous_sha == expected_previous_sha,
                "public archive preimage changed (compare-and-swap failed)")
        require(len(prior) == 128 and prior[0]["day"] == "2026-06-09"
                and prior[-1]["day"] == "2026-10-14",
                "unexpected baseline public audience coverage")

        copy = backup_old(prior)
        require(copy.exists() and copy.stat().st_mode & 0o777 == 0o600,
                "old public audience preimage not durably backed up")
        stamp = datetime.now(timezone.utc).isoformat()
        db.execute(
            "DELETE FROM traffic_public_daily_audience_rollups WHERE project_slug=?",
            (PROJECT,),
        )
        db.executemany(
            """INSERT INTO traffic_public_daily_audience_rollups
               (project_slug,bucket_day,total_traffic,suspected_human,
                confirmed_human,updated_at) VALUES(?,?,?,?,?,?)""",
            [(PROJECT, day, *candidate[day], stamp) for day in sorted(candidate)],
        )
        after = public_rows(db)
        require(len(after) == RELEASE_COUNT
                and manifest.sha(audience_matrix(after)) == EXPECTED_CANDIDATE_SHA,
                "post-write public audience checksum/count mismatch")
        db.commit()
        return {
            "result": "COMMITTED", "previous_sha256": previous_sha,
            "after_sha256": EXPECTED_CANDIDATE_SHA,
            "backup_file": str(copy), "written_days": len(after),
            "updated_at": stamp,
        }
    except BaseException:
        db.rollback()
        raise


@contextmanager
def exclusive_file_lock(path: Path, *, create: bool = False) -> Iterator[None]:
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "lock path not regular")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def execute(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(__file__).resolve().parents[1]
    require(guard.cmd_output("git", "rev-parse", "HEAD", cwd=repo) == args.require_sha,
            "unpinned checkout")
    require(not guard.cmd_output("git", "status", "--porcelain", cwd=repo),
            "dirty checkout")
    require(args.source.is_file() and args.state.is_file()
            and args.backup.is_file(),
            "source/private checkpoint/private backup must exist")
    require(args.source.resolve() != args.state.resolve()
            and args.source.resolve() != args.backup.resolve(),
            "source aliases private artifacts")
    require(args.state.parent == args.backup.parent,
            "private checkpoint and backup must share guarded directory")
    require(args.require_sha == guard.cmd_output(
        "git", "rev-parse", "HEAD", cwd=repo), "source pin changed")
    if args.apply:
        require(args.approval_phrase == APPROVAL_PHRASE,
                "explicit operator approval of narrowed 131 days required")
    else:
        require(not args.approval_phrase, "approval phrase only accepted with --apply")

    guard.require_worker_priority()
    guard.resource_headroom(args.state, 12, 6)
    lock = args.state.parent / ".canary.lock"
    with exclusive_file_lock(lock):
        candidate = validate_candidate(args.state, args.backup)
        with exclusive_file_lock(ROLLUP_LOCK, create=False) if args.apply else nullcontext():
            require(guard.worker_idle(), "independent project daily worker busy")
            if args.apply:
                # The first application requires the *entire* baseline/late-source
                # release manifest. Repeats may be exact no-ops, but must not
                # change any already published rows or write timestamps.
                with closing(sqlite3.connect(
                    f"file:{args.source.resolve().as_posix()}?mode=ro",
                    uri=True, timeout=2,
                )) as existing_db:
                    previous_sha = manifest.sha(audience_matrix(
                        public_rows(existing_db)
                    ))
                if previous_sha == EXPECTED_LEGACY_SHA:
                    evidence = manifest.inspect(args.source, args.state)
                    require(evidence["full_day_sha256"] == EXPECTED_CANDIDATE_SHA
                            and evidence["legacy_sha256"] == EXPECTED_LEGACY_SHA,
                            "release manifest/legacy preimage no longer approved")
                elif previous_sha == EXPECTED_CANDIDATE_SHA:
                    # A safe repeated invocation only needs to prove the same
                    # backed-up, frozen candidate remains installed. No writes.
                    guard.verify_frozen(
                        args.source, args.state, guard.checkpoint_info(args.state)
                    )
                else:
                    raise RuntimeError(
                        "STOP: public archive changed; release CAS refused"
                    )
                with closing(sqlite3.connect(
                    f"file:{args.source.resolve().as_posix()}?mode=rw",
                    uri=True, timeout=5,
                )) as db:
                    db.execute("PRAGMA busy_timeout=5000")
                    return transactional_replace(
                        db, candidate,
                        backup_old=lambda rows: preimage_backup(args.state.parent, rows),
                    )
            else:
                with closing(sqlite3.connect(
                    f"file:{args.source.resolve().as_posix()}?mode=ro",
                    uri=True, timeout=2,
                )) as db:
                    current = audience_matrix(public_rows(db))
                current_sha = manifest.sha(current)
                require(current_sha in (EXPECTED_LEGACY_SHA, EXPECTED_CANDIDATE_SHA),
                        "unexpected current public rows; cannot preview")
                return {
                    "result": "PREVIEW_ONLY", "candidate_days": RELEASE_COUNT,
                    "first": RELEASE_FIRST, "last": RELEASE_LAST,
                    "candidate_sha256": EXPECTED_CANDIDATE_SHA,
                    "current_public_sha256": current_sha,
                    "backed_up_complete_checkpoint": True,
                    "requires_explicit_operator_approval": True,
                    "will_replace_public_table": False,
                }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--require-sha", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-phrase", default="")
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args), sort_keys=True))
        return 0
    except (RuntimeError, OSError, ValueError, sqlite3.Error, BlockingIOError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
