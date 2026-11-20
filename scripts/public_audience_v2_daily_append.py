#!/usr/bin/env python3
"""Traffic V2 atomic day publisher core; source-only, NO production CLI.

Publication is possible ONLY from separately authenticated source/classifier
finality plus an independently admitted owner install/permit. This module
does not grant that permit, open a live database, install a timer, or create
a standalone writer. Real WE2 operational wrapper and reviewed signed permit
are still required. Fixture tests exercise the actual SQLite write transaction.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Callable

from scripts import public_audience_v2_day_admission as admission
from scripts.public_audience_v2_atomic_publish import public_rows
from scripts.public_audience_v2_forward_ledger import RELEASE_SHA
from scripts.public_audience_v2_release_manifest import sha as matrix_sha

PROJECT = "aoe2hdbets"
FROZEN_FIRST = date(2026, 6, 11)
FROZEN_LAST = date(2026, 10, 19)
CERTIFIED_LEDGER = "traffic_public_audience_day_certificates_v2"
DAY_CERT_TABLE_SCHEMA = """
CREATE TABLE traffic_public_audience_day_certificates_v2(
 project_slug TEXT NOT NULL,
 bucket_day TEXT NOT NULL,
 certificate_sha256 TEXT NOT NULL,
 source_page_sha256 TEXT NOT NULL,
 signed_finality_schema TEXT NOT NULL,
 certified_at_utc TEXT NOT NULL,
 PRIMARY KEY(project_slug,bucket_day)
);
"""


def need(value: bool, reason: str) -> None:
    if not value:
        raise ValueError("TRAFFIC_V2_PUBLISH_HOLD_" + reason)


def _canonical_day(raw: Any) -> date:
    need(type(raw) is str and len(raw) == 10, "DAY_MALFORMED")
    try:
        d = date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError("TRAFFIC_V2_PUBLISH_HOLD_DAY_MALFORMED") from exc
    need(d.isoformat() == raw, "DAY_MALFORMED")
    return d


def historical_preimage(db: sqlite3.Connection) -> dict[str, list[int]]:
    """Exact 131-day digest; preserved rows are NEVER overwritten."""
    rows = public_rows(db)
    original = {}
    for row in rows:
        day = _canonical_day(row["day"])
        if day <= FROZEN_LAST:
            need(FROZEN_FIRST <= day, "PRE_ARCHIVE_ROWS_PRESENT")
            need(row["day"] not in original, "DUPLICATE_HISTORICAL_ROW")
            original[row["day"]] = [row["total"], row["potential"],
                                     row["confirmed"]]
    need(len(original) == 131
         and min(original) == FROZEN_FIRST.isoformat()
         and max(original) == FROZEN_LAST.isoformat()
         and matrix_sha(original) == RELEASE_SHA,
         "ORIGINAL_131_DAY_DIGEST_DRIFT")
    return original


def _ledger_contract(db: sqlite3.Connection) -> None:
    table = db.execute(
        "SELECT type,sql FROM sqlite_master WHERE name=?", (CERTIFIED_LEDGER,)
    ).fetchone()
    need(table is not None and table[0] == "table",
         "REVIEWED_DAY_CERTIFICATE_LEDGER_NOT_INSTALLED")
    columns = {row[1]: row for row in db.execute(
        "PRAGMA table_info(" + CERTIFIED_LEDGER + ")"
    )}
    required = {"project_slug", "bucket_day", "certificate_sha256",
                "source_page_sha256", "signed_finality_schema",
                "certified_at_utc"}
    need(required.issubset(columns), "DAY_CERTIFICATE_SCHEMA_DRIFT")
    need(all(columns[k][3] == 1 for k in required),
         "DAY_CERTIFICATE_NOTNULL_DRIFT")


def _snapshot(db: sqlite3.Connection) -> list[dict]:
    return public_rows(db)



def durable_public_preimage(directory: Path, rows: list[dict], *, day: str) -> str:
    """Persist exact old public-only rows with 0600/exclusive/fsync readback.

    Caller must use a WE2-admitted existing private 0700 directory on the
    correct data volume. This adds no private IP, user-agent or request data.
    Backup is never overwritten or deleted, even on a later failure.
    """
    _canonical_day(day)
    parent = directory.lstat()
    need(stat.S_ISDIR(parent.st_mode) and not directory.is_symlink()
         and stat.S_IMODE(parent.st_mode) == 0o700
         and parent.st_uid == os.getuid()
         and directory.resolve() == directory,
         "PREIMAGE_DIRECTORY_NOT_OWNER_PRIVATE")
    need(type(rows) is list and 131 <= len(rows) <= 5_000,
         "PREIMAGE_ROW_BOUNDS")
    payload = admission.canonical(rows)
    need(len(payload) <= 4_000_000, "PREIMAGE_BYTE_BOUNDS")
    expected = hashlib.sha256(payload).hexdigest()
    dest = directory / ("traffic-v2-prior-" + day + "-" + expected + ".json")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as backup:
            backup.write(payload)
            backup.flush()
            os.fsync(backup.fileno())
        stat_result = dest.lstat()
        need(stat.S_ISREG(stat_result.st_mode)
             and stat_result.st_uid == os.getuid()
             and stat.S_IMODE(stat_result.st_mode) == 0o600
             and stat_result.st_nlink == 1
             and hashlib.sha256(dest.read_bytes()).hexdigest() == expected,
             "DURABLE_PREIMAGE_READBACK_FAILED")
        dirfd = os.open(directory, os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        return expected
    except BaseException:
        # Preserve any actual bytes for forensic inspection. Retrying requires
        # an operator to inspect the existing exact-name private preimage.
        raise

def append_verified_day(
    db: sqlite3.Connection, *, certificate_envelope: dict,
    page_state: dict, now: datetime,
    upstream_key: bytes, classifier_key: bytes,
    upstream_key_sha256: str, classifier_key_sha256: str,
    independently_admitted_operator_permit: dict,
    durable_preimage: Callable[[list[dict]], str],
    expected_public_sha256: str, lock_proven: bool,
) -> dict:
    """Append ONE genuinely independently admitted completed UTC day.

    The caller MUST hold the existing shared Traffic project lock, run in the
    separately reviewed one-writer service, and attest the operator permit
    under root-controlled public-key trust BEFORE invoking this function.
    This function verifies day/source/classifier Ed25519 signatures itself,
    and performs a single SQLite transaction with CAS and durable backup.
    This is a core, not an exposed publisher/CLI or root permit verifier.
    """
    need(now.tzinfo is not None, "OBSERVATION_CLOCK_NAIVE")
    now = now.astimezone(timezone.utc)
    need(lock_proven is True, "PROJECT_WORKER_LOCK_MISSING")
    need(type(expected_public_sha256) is str and
         len(expected_public_sha256) == 64 and
         all(x in "0123456789abcdef" for x in expected_public_sha256),
         "PUBLIC_PREIMAGE_SHA_NOT_PINNED")
    need(type(independently_admitted_operator_permit) is dict
         and independently_admitted_operator_permit.get("status") in (
             "INDEPENDENT_OPERATOR_PERMIT_VERIFIED",
             "INDEPENDENT_DAILY_DELEGATION_VERIFIED")
         and independently_admitted_operator_permit.get("project") == PROJECT
         and independently_admitted_operator_permit.get("day") ==
         certificate_envelope.get("certificate", {}).get("day")
         and independently_admitted_operator_permit.get("certificate_sha256")
         == admission.digest(admission.canonical(
             certificate_envelope.get("certificate")))
         and independently_admitted_operator_permit.get("source_commit_sha")
         and independently_admitted_operator_permit.get("permit_signature_verified")
         is True
         and independently_admitted_operator_permit.get("permitted_public_preimage_sha256") == expected_public_sha256
         and independently_admitted_operator_permit.get("gap_aware_api_and_chart")
         is True, "INDEPENDENT_OPERATOR_AND_GAP_DISPLAY_PERMIT_ABSENT")
    proof = admission.verify_dual_witness(
        certificate_envelope, page_state, now=now,
        upstream_key=upstream_key, classifier_key=classifier_key,
        expected_upstream_key_sha256=upstream_key_sha256,
        expected_classifier_key_sha256=classifier_key_sha256,
    )
    need(proof["dual_witness_signatures_verified"]
         and not proof["public_write_authorized"]
         and not proof["day_physical_production_certified"],
         "DAY_WITNESS_SOURCE_CONTRACT_DRIFT")
    day = _canonical_day(proof["day"])
    need(FROZEN_LAST < day < now.date(), "CURRENT_OR_HISTORICAL_DAY_REFUSED")
    certsha = proof["certificate_digest_sha256"]
    candidate = proof["candidate_values"]
    need(len(candidate) == 3 and candidate[0] >= candidate[1]
         >= candidate[2] >= 0, "CANONICAL_COUNTER_HIERARCHY")
    db.execute("PRAGMA busy_timeout=1000")
    db.execute("BEGIN IMMEDIATE")
    try:
        historical_preimage(db)
        _ledger_contract(db)
        prior_rows = _snapshot(db)
        prior_matrix = {r["day"]: [r["total"], r["potential"],
                                   r["confirmed"]] for r in prior_rows}
        prior_sha = matrix_sha(prior_matrix)
        need(prior_sha == expected_public_sha256,
             "PUBLIC_DAY_PREIMAGE_MOVED")
        existing_day = next((r for r in prior_rows if r["day"] == day.isoformat()),
                            None)
        previous_cert = db.execute(
            """SELECT certificate_sha256,source_page_sha256
               FROM traffic_public_audience_day_certificates_v2
               WHERE project_slug=? AND bucket_day=?""",
            (PROJECT, day.isoformat()),
        ).fetchone()
        if existing_day:
            need(previous_cert is not None and
                 previous_cert[0] == certsha
                 and previous_cert[1] == proof["source_page_digest"]
                 and [existing_day["total"], existing_day["potential"],
                      existing_day["confirmed"]] == candidate,
                 "CONFLICTING_REPLAY_OR_UNCERTIFIED_EXISTING_DAY")
            db.rollback()
            return {
                "status": "IDEMPOTENT_ALREADY_CERTIFIED",
                "day": day.isoformat(), "public_write_count": 0,
                "previous_sha256": prior_sha, "after_sha256": prior_sha,
                "missing_days_are_unknown": True,
            }
        need(previous_cert is None, "ORPHAN_CERTIFICATE_NOT_PUBLISHED")
        # No retroactive correction or silent old-day modification, even if
        # a previously omitted gap is later supplied with a plausible token.
        future_days = [_canonical_day(r["day"]) for r in prior_rows
                       if _canonical_day(r["day"]) > FROZEN_LAST]
        need(not future_days or day > max(future_days),
             "OUT_OF_ORDER_OR_RETROACTIVE_DAY")
        before = durable_preimage(prior_rows)
        need(type(before) is str and len(before) == 64 and
             before == hashlib.sha256(admission.canonical(prior_rows)).hexdigest(),
             "DURABLE_PREIMAGE_NOT_VERIFIED")
        # Only insert ONE authenticated new day, and its durable audit row,
        # in the SAME write transaction. A failure rolls both back.
        db.execute(
            """INSERT INTO traffic_public_daily_audience_rollups
            (project_slug,bucket_day,total_traffic,suspected_human,
             confirmed_human,updated_at) VALUES(?,?,?,?,?,?)""",
            (PROJECT, day.isoformat(), *candidate, now.isoformat()),
        )
        db.execute(
            """INSERT INTO traffic_public_audience_day_certificates_v2
            (project_slug,bucket_day,certificate_sha256,source_page_sha256,
             signed_finality_schema,certified_at_utc) VALUES(?,?,?,?,?,?)""",
            (PROJECT, day.isoformat(), certsha, proof["source_page_digest"],
             admission.SCHEMA, now.isoformat()),
        )
        after_rows = _snapshot(db)
        after_matrix = {r["day"]: [r["total"], r["potential"],
                                   r["confirmed"]] for r in after_rows}
        need(len(after_rows) == len(prior_rows) + 1
             and after_matrix[day.isoformat()] == candidate,
             "POST_WRITE_ROW_COUNT_OR_VALUES")
        historical_preimage(db)
        after_sha = matrix_sha(after_matrix)
        db.commit()
        return {
            "status": "COMMITTED_ONE_SIGNED_COMPLETED_DAY",
            "day": day.isoformat(),
            "candidate": candidate,
            "previous_sha256": prior_sha, "after_sha256": after_sha,
            "source_certificate_sha256": certsha,
            "public_write_count": 1,
            "missing_days_are_unknown": True,
            "prior_131_days_sha256": RELEASE_SHA,
        }
    except BaseException:
        db.rollback()
        raise
