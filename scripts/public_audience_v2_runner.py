#!/usr/bin/env python3
"""Bounded Traffic V2 daily publisher invocation — NO AUTOINSTALL.

WE2-owned root only. There is no --config or --key override in the CLI:
--once requires root-owned /etc/aoe2war/traffic-v2/runner.json and separate
trusted keys, protected source DB, admitted systemd readback, signed upstream
delivery, independently signed canonical classifier and either a one-day
owner permit or a revocable owner-signed daily delegation.
No evidence => no DB writes. One invocation handles at most seven signed days
and retains the existing 131-day certified archive and all unknown gaps.

The source is a candidate, not evidence that WE2 installed or activated it.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
from typing import Callable, Any
from urllib.parse import quote

from scripts import public_audience_v2_day_admission as witness
from scripts import public_audience_v2_operator_permit as operator
from scripts import public_audience_v2_daily_delegation as delegation
from scripts import public_audience_v2_daily_append as append
from scripts.public_audience_v2_atomic_publish import public_rows
from scripts.public_audience_v2_release_manifest import sha as matrix_sha

CONFIG = Path("/etc/aoe2war/traffic-v2/runner.json")
SCHEMA = "traffic.public-audience.v2.root-runner.v1"
PROJECT = "aoe2hdbets"
FIELDS = {
    "schema", "project", "source_database", "source_dev", "source_inode",
    "evidence_dir", "backup_dir", "checkpoint_dir", "worker_lock",
    "upstream_key", "upstream_key_sha256",
    "classifier_key", "classifier_key_sha256",
    "operator_key", "operator_key_sha256",
    "source_commit_sha", "traffic_api_file", "traffic_api_sha256",
    "website_gap_receipt", "website_gap_renderer_sha256",
    "ingest_unit_sha256", "max_days_per_run", "run_uid", "run_gid",
    "authorization_mode", "daily_delegation", "delegation_state",
}
MAX_FILES = 366
MAX_DAYS_PER_RUN = 7


def hold(reason: str) -> None:
    raise ValueError("TRAFFIC_V2_RUNNER_HOLD_" + reason)


def need(test: bool, reason: str) -> None:
    if not test:
        hold(reason)


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def valid_hash(x: Any, *, length: int = 64) -> bool:
    return type(x) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", x) is not None


def private_file(file: Path, *, uid: int, max_bytes: int = 100_000,
                 mode: int = 0o600) -> bytes:
    need(file.is_absolute() and not file.is_symlink() and file.resolve() == file,
         "PRIVATE_FILE_PATH_ALIAS")
    fd = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == uid and stat.S_IMODE(before.st_mode) == mode
             and 0 < before.st_size <= max_bytes, "PRIVATE_FILE_OWNER_MODE_OR_BOUND")
        data = os.read(fd, max_bytes + 1)
        after = os.fstat(fd)
        need(len(data) == before.st_size and len(data) <= max_bytes
             and (before.st_dev, before.st_ino, before.st_mtime_ns,
                  before.st_size, before.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_mtime_ns,
                 after.st_size, after.st_ctime_ns),
             "PRIVATE_FILE_TORN_OR_CHANGED")
        return data
    finally:
        os.close(fd)


def strict_json(blob: bytes, *, max_bytes: int = 100_000) -> dict:
    need(len(blob) <= max_bytes, "JSON_TOO_LARGE")
    def unique(pairs: list[tuple[str, Any]]) -> dict:
        out: dict = {}
        for name, value in pairs:
            need(name not in out, "DUPLICATE_JSON_KEY")
            out[name] = value
        return out
    try:
        data = json.loads(blob, object_pairs_hook=unique,
                          parse_constant=lambda _: hold("NONFINITE_JSON"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("TRAFFIC_V2_RUNNER_HOLD_INVALID_JSON") from exc
    need(type(data) is dict, "JSON_NOT_OBJECT")
    return data


def private_dir(path: Path, *, uid: int) -> None:
    need(path.is_absolute() and not path.is_symlink()
         and path.resolve() == path, "PRIVATE_DIRECTORY_ALIAS")
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == uid
         and stat.S_IMODE(st.st_mode) == 0o700,
         "PRIVATE_DIRECTORY_OWNER_MODE")


def protected_trust_ancestors(file: Path) -> None:
    """WE2-owned public trust cannot sit under a service-writable ancestor."""
    target = file.parent
    while True:
        st = target.lstat()
        need(stat.S_ISDIR(st.st_mode) and not target.is_symlink()
             and st.st_uid == 0 and (st.st_mode & 0o022) == 0,
             "TRUST_ANCESTOR_MUTABLE_OR_NOT_ROOT")
        if target == target.parent:
            break
        target = target.parent


def config_read(file: Path, *, uid: int, trust_uid: int | None = None) -> dict:
    if trust_uid is None:  # restricted synthetic test fixture only
        trust_uid = uid
    mode = 0o644 if trust_uid == 0 else 0o600
    if trust_uid == 0:
        protected_trust_ancestors(file)
    obj = strict_json(private_file(file, uid=trust_uid,
                                   max_bytes=12000, mode=mode))
    need(set(obj) == FIELDS and obj["schema"] == SCHEMA
         and obj["project"] == PROJECT, "ROOT_CONFIG_SCHEMA_OR_PROJECT_DRIFT")
    need(obj["authorization_mode"] in ("one_day", "delegation")
         and type(obj["authorization_mode"]) is str,
         "AUTHORIZATION_MODE_NOT_PINNED")
    need(type(obj["run_uid"]) is int and obj["run_uid"] > 0
         and type(obj["run_gid"]) is int and obj["run_gid"] > 0
         and obj["run_uid"] == uid,
         "DEDICATED_NONROOT_SERVICE_IDENTITY_MISMATCH")
    need(type(obj["max_days_per_run"]) is int and
         1 <= obj["max_days_per_run"] <= MAX_DAYS_PER_RUN,
         "UNBOUNDED_CATCHUP_LIMIT")
    need(type(obj["source_dev"]) is int and obj["source_dev"] >= 0
         and type(obj["source_inode"]) is int and obj["source_inode"] > 0,
         "SOURCE_FILE_IDENTITY_MISSING")
    for key in ("upstream_key_sha256", "classifier_key_sha256",
                "operator_key_sha256", "traffic_api_sha256",
                "website_gap_renderer_sha256", "ingest_unit_sha256"):
        need(valid_hash(obj[key]), "EXPECTED_SOURCE_OR_KEY_HASH_MISSING")
    need(valid_hash(obj["source_commit_sha"], length=40)
         and len({obj["upstream_key_sha256"], obj["classifier_key_sha256"],
                  obj["operator_key_sha256"]}) == 3,
         "SOURCE_COMMIT_OR_INDEPENDENT_KEY_ROLES_INVALID")
    for k in ("source_database", "evidence_dir", "backup_dir",
              "checkpoint_dir", "worker_lock", "upstream_key",
              "classifier_key", "operator_key", "traffic_api_file",
              "website_gap_receipt", "daily_delegation",
              "delegation_state"):
        value = obj[k]
        need(type(value) is str and Path(value).is_absolute()
             and str(Path(value)) == value, "SOURCE_PATH_NOT_CANONICAL")
    for k in ("evidence_dir", "backup_dir", "checkpoint_dir"):
        private_dir(Path(obj[k]), uid=uid)
    for k in ("upstream_key", "classifier_key", "operator_key"):
        if trust_uid == 0:
            protected_trust_ancestors(Path(obj[k]))
        need(sha(private_file(Path(obj[k]), uid=trust_uid,
                              max_bytes=3000, mode=mode)) ==
             obj[k+"_sha256"], "PINNED_PUBLIC_KEY_MISMATCH")
    if obj["authorization_mode"] == "delegation":
        for k in ("daily_delegation", "delegation_state"):
            if trust_uid == 0:
                protected_trust_ancestors(Path(obj[k]))
            private_file(Path(obj[k]), uid=trust_uid, max_bytes=14000,
                         mode=mode)
    need(Path(obj["worker_lock"]).parent == Path(obj["checkpoint_dir"]),
         "SHARED_WORKER_LOCK_NOT_IN_PRIVATE_CHECKPOINT")
    need(Path(obj["source_database"]).resolve()
         != Path(obj["checkpoint_dir"]).resolve(),
         "SOURCE_AND_PRIVATE_STATE_ALIAS")
    return obj


def public_source_state(cfg: dict, *, trust_uid: int) -> tuple[int, int]:
    source = Path(cfg["source_database"])
    need(source.is_file() and not source.is_symlink()
         and source.resolve() == source, "SOURCE_DB_ALIAS")
    s = source.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
         and s.st_dev == cfg["source_dev"]
         and s.st_ino == cfg["source_inode"],
         "SOURCE_DB_IDENTITY_DRIFT")
    # Operator permit requires this exact currently installed API source.
    api = Path(cfg["traffic_api_file"])
    if trust_uid == 0:
        protected_trust_ancestors(api)
        protected_trust_ancestors(Path(cfg["website_gap_receipt"]))
    need(sha(private_file(api, uid=trust_uid, max_bytes=2_000_000,
                            mode=0o644 if trust_uid == 0 else 0o600)) ==
         cfg["traffic_api_sha256"], "TRAFFIC_API_SOURCE_DRIFT")
    # WE2 must source this protected receipt from actual Factory activation.
    # Merely naming a hash in the config cannot prove website deployment.
    render = strict_json(private_file(
        Path(cfg["website_gap_receipt"]), uid=trust_uid, max_bytes=4096,
        mode=0o644 if trust_uid == 0 else 0o600))
    need(set(render) == {"schema", "status", "renderer_sha256",
                         "approved_source_commit"}
         and render["schema"] == "aoe2war.traffic-v2.gap-renderer-readback.v1"
         and render["status"] == "WE2_ACTIVATED_GAP_RENDERER_READBACK"
         and render["renderer_sha256"] ==
         cfg["website_gap_renderer_sha256"]
         and valid_hash(render["approved_source_commit"], length=40),
         "GAP_RENDERER_ACTIVATION_NOT_ATTESTED")
    return s.st_dev, s.st_ino


def unit_readback() -> dict:
    """Only the existing ingest unit; never systemctl start/restart/install."""
    def run(*args: str) -> bytes:
        job = subprocess.run(["/usr/bin/systemctl", *args], timeout=6,
                             check=False, capture_output=True)
        need(job.returncode == 0 and len(job.stdout) <= 30_000,
             "INGEST_SYSTEMD_READBACK_UNAVAILABLE")
        return job.stdout
    return {
        "unit_bytes": run("cat", "traffic-ingest.service"),
        "loaded_environment": run("show", "traffic-ingest.service",
                                  "--property=Environment", "--value").decode(),
        "timer_active": run("is-active", "traffic-ingest.timer").strip() == b"active",
    }


def unit_check(cfg: dict, result: dict) -> None:
    need(set(result) == {"unit_bytes", "loaded_environment", "timer_active"}
         and type(result["unit_bytes"]) is bytes
         and sha(result["unit_bytes"]) == cfg["ingest_unit_sha256"]
         and result["timer_active"] is True,
         "INGEST_UNIT_TIMER_OR_POSTIMAGE_DRIFT")
    env = result["loaded_environment"].split()
    need(env.count("TRAFFIC_INGEST_RECEIPTS_ENABLED=1") == 1,
         "NATURAL_INSERT_RECEIPT_SETTING_NOT_INSTALLED")


def source_late_check(db: sqlite3.Connection, page: dict, day: str) -> None:
    """Indexed single-row check for post-snapshot backdated arrivals."""
    s = date.fromisoformat(day)
    # Original canonical sessions can start before midnight or close in
    # the next UTC day. Recheck both 31-minute boundary wings, never only
    # events whose request timestamps fall inside the calendar day.
    boundary = datetime.combine(s, datetime.min.time(),tzinfo=timezone.utc)
    start = (boundary - timedelta(minutes=31)).isoformat()
    end = (boundary + timedelta(days=1,minutes=31)).isoformat()
    prefix = page["source_snapshot_rowid"] if "source_snapshot_rowid" in page \
        else page["snapshot_rowid"]
    need(type(prefix) is int and prefix > 0, "SOURCE_WATERMARK_NOT_BOUND")
    db.set_progress_handler(lambda: 1, 200_000)
    try:
        row = db.execute(
            """SELECT rowid FROM traffic_entries
             INDEXED BY idx_traffic_entries_timestamp_line_offset
             WHERE timestamp >= ? AND timestamp < ? AND rowid > ?
             ORDER BY timestamp ASC,line_offset ASC LIMIT 1""",
            (start, end, prefix),
        ).fetchone()
        need(row is None, "BACKDATED_LATE_ARRIVAL_BEYOND_SIGNED_PREFIX")
        latest = db.execute(
            "SELECT MAX(rowid) FROM traffic_entries"
        ).fetchone()[0]
        need(type(latest) is int and latest >= prefix,
             "SOURCE_PREFIX_NO_LONGER_PRESENT")
    except sqlite3.Error as exc:
        raise ValueError("TRAFFIC_V2_RUNNER_HOLD_SOURCE_SNAPSHOT_QUERY_FAILED") from exc
    finally:
        db.set_progress_handler(None, 0)


def matrix(db: sqlite3.Connection) -> str:
    rows = public_rows(db)
    return matrix_sha({r["day"]: [r["total"], r["potential"], r["confirmed"]]
                       for r in rows})



def bounded_ingest_readback(db: sqlite3.Connection) -> dict:
    """Real indexed recent-row *sample*; never substitutes for finality."""
    db.set_progress_handler(lambda: 1, 150_000)
    try:
        rows = db.execute(
            "SELECT rowid,ingested_at_utc FROM traffic_entries "
            "ORDER BY rowid DESC LIMIT 512"
        ).fetchall()
        observed = []
        for _rowid, stamp in rows:
            if stamp is not None:
                try:
                    observed.append(witness.utc_stamp(stamp).isoformat())
                except ValueError:
                    hold("INVALID_PHYSICAL_SOURCE_INSERTION_CLOCK")
        has_state = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='traffic_ingest_state'"
        ).fetchone() is not None
        delivery = None
        if has_state:
            values = db.execute(
                "SELECT updated_at FROM traffic_ingest_state LIMIT 129"
            ).fetchall()
            need(len(values) <= 128, "UNBOUNDED_SOURCE_OFFSET_STATE")
            clocks = [witness.utc_stamp(r[0]).isoformat() for r in values]
            delivery = max(clocks, default=None)
        return {
            "sample": "latest_512_rowids_not_full_day",
            "sampled_source_rows": len(rows),
            "sampled_receipts_present": len(observed),
            "sampled_receipts_missing": len(rows)-len(observed),
            "sampled_latest_natural_insert_receipt_utc":
                max(observed, default=None),
            "last_source_delivery_state_update_utc": delivery,
            "full_utc_day_delivery_proven": False,
            "certified_from_recent_sample": False,
        }
    except sqlite3.Error as exc:
        raise ValueError("TRAFFIC_V2_RUNNER_HOLD_INGEST_SAMPLE_QUERY_FAILED") from exc
    finally:
        db.set_progress_handler(None, 0)


def current_public(db: sqlite3.Connection) -> dict:
    append.historical_preimage(db)
    rows = public_rows(db)
    future = [r["day"] for r in rows if r["day"] > "2026-10-19"]
    return {"last_published": max(future, default="2026-10-19"),
            "points": len(rows), "public_sha256": matrix(db)}


def _candidate_dirs(cfg: dict, now: datetime, *, uid: int) -> list[tuple[str, Path]]:
    folder = Path(cfg["evidence_dir"])
    private_dir(folder, uid=uid)
    candidates = []
    for index, entry in enumerate(folder.iterdir()):
        need(index < MAX_FILES, "EVIDENCE_DIRECTORY_SCAN_EXCEEDED")
        need(entry.name.isascii() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry.name)
             is not None, "UNKNOWN_EVIDENCE_DIRECTORY_ENTRY")
        private_dir(entry, uid=uid)
        day = date.fromisoformat(entry.name)
        need(day.isoformat() == entry.name, "NONCANONICAL_EVIDENCE_DAY")
        if date(2026, 10, 20) <= day < now.date():
            candidates.append((entry.name, entry))
    return sorted(candidates)


def checkpoint_receipt(folder: Path, result: dict, *, uid: int) -> None:
    """Crash after DB commit is recoverable from certificate-ledger replay."""
    private_dir(folder, uid=uid)
    key = result["day"]
    data = witness.canonical({k: result[k] for k in (
        "day", "source_certificate_sha256", "after_sha256",
        "previous_sha256", "prior_131_days_sha256"
    )})
    target = folder / ("completed-" + key + ".json")
    if target.exists():
        need(private_file(target, uid=uid) == data,
             "DURABLE_CHECKPOINT_CONFLICT")
        return
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    dir_fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def reusable_preimage(cfg: dict, rows: list[dict], *, day: str, uid: int) -> str:
    folder = Path(cfg["backup_dir"])
    payload = witness.canonical(rows)
    digest = sha(payload)
    existing = folder / ("traffic-v2-prior-"+day+"-"+digest+".json")
    if existing.exists():
        need(private_file(existing, uid=uid, max_bytes=4_000_000) == payload,
             "PREVIOUS_DURABLE_PREIMAGE_TAMPERED")
        return digest
    return append.durable_public_preimage(folder, rows, day=day)


def verified_publish_authority(cfg: dict, *, day: str,
                               folder: Path, evidence: dict,
                               public_preimage: str, now: datetime,
                               uid: int, trust_uid: int) -> dict:
    """Choose ONLY an installed root-pinned authorization mode.

    Daily delegation removes the per-day OWNER signature, NOT the upstream
    delivery or classifier independent signatures or their source checks.
    Root-owned signed state is re-opened per day to apply owner revocation.
    """
    mode = cfg["authorization_mode"]
    public_mode = 0o644 if trust_uid == 0 else 0o600
    owner_key = private_file(Path(cfg["operator_key"]), uid=trust_uid,
                             mode=public_mode, max_bytes=3000)
    source_cert_sha = sha(witness.canonical(evidence["certificate"]))
    if mode == "one_day":
        one_day = strict_json(private_file(
            folder/"owner-permit.json", uid=uid))
        need(one_day.get("permit", {}).get("day") == day,
             "OWNER_ONE_DAY_CERTIFICATE_DRIFT")
        return operator.verify_operator_permit(
            one_day, trust_public_key=owner_key,
            trusted_public_sha256=cfg["operator_key_sha256"],
            upstream_key_sha256=cfg["upstream_key_sha256"],
            classifier_key_sha256=cfg["classifier_key_sha256"],
            reviewed_source_commit_sha=cfg["source_commit_sha"],
            database_dev=cfg["source_dev"], database_ino=cfg["source_inode"],
            reviewed_ingest_unit_sha256=cfg["ingest_unit_sha256"],
            reviewed_traffic_api_sha256=cfg["traffic_api_sha256"],
            reviewed_website_gap_renderer_sha256=cfg["website_gap_renderer_sha256"],
            expected_public_preimage_sha256=public_preimage,
            certificate_sha256=source_cert_sha, now=now,
        )
    need(mode == "delegation", "AUTHORIZATION_MODE_NOT_PINNED")
    paths = [Path(cfg["daily_delegation"]), Path(cfg["delegation_state"])]
    if trust_uid == 0:
        for path in paths:
            protected_trust_ancestors(path)
    signed_scope = strict_json(private_file(
        paths[0], uid=trust_uid, mode=public_mode, max_bytes=14000))
    revocation = strict_json(private_file(
        paths[1], uid=trust_uid, mode=public_mode, max_bytes=14000))
    return delegation.verify_daily_delegation(
        signed_scope, revocation, trust_public_key=owner_key,
        trusted_public_sha256=cfg["operator_key_sha256"],
        expected_upstream_key_sha256=cfg["upstream_key_sha256"],
        expected_classifier_key_sha256=cfg["classifier_key_sha256"],
        reviewed_source_commit_sha=cfg["source_commit_sha"],
        source_database_dev=cfg["source_dev"],
        source_database_ino=cfg["source_inode"],
        reviewed_ingest_unit_sha256=cfg["ingest_unit_sha256"],
        reviewed_traffic_api_sha256=cfg["traffic_api_sha256"],
        reviewed_website_gap_renderer_sha256=cfg["website_gap_renderer_sha256"],
        expected_max_days_per_run=cfg["max_days_per_run"],
        day=day, certificate_sha256=source_cert_sha,
        public_preimage_sha256=public_preimage, now=now,
    )


def verify_and_append(db: sqlite3.Connection, cfg: dict, day: str,
                      folder: Path, now: datetime, *, uid: int,
                      trust_uid: int, observed_unit: dict) -> dict:
    evidence = strict_json(private_file(folder/"day-envelope.json", uid=uid))
    page = strict_json(private_file(folder/"page-state.json", uid=uid))
    need(evidence.get("certificate", {}).get("day") == day
         and page.get("day") == day,
         "SOURCE_EVIDENCE_DAY_IDENTITY_DRIFT")
    unit_check(cfg, observed_unit)
    source_late_check(db, page, day)
    preimage = matrix(db)
    authority = verified_publish_authority(
        cfg, day=day, folder=folder, evidence=evidence,
        public_preimage=preimage, now=now, uid=uid,
        trust_uid=trust_uid,
    )
    # The owner permit is separate from the two source and classifier roles.
    result = append.append_verified_day(
        db, certificate_envelope=evidence, page_state=page, now=now,
        upstream_key=private_file(Path(cfg["upstream_key"]), uid=trust_uid,
                                  mode=0o644 if trust_uid == 0 else 0o600),
        classifier_key=private_file(Path(cfg["classifier_key"]), uid=trust_uid,
                                    mode=0o644 if trust_uid == 0 else 0o600),
        upstream_key_sha256=cfg["upstream_key_sha256"],
        classifier_key_sha256=cfg["classifier_key_sha256"],
        independently_admitted_operator_permit=authority,
        durable_preimage=lambda rows: reusable_preimage(
            cfg, rows, day=day, uid=uid),
        expected_public_sha256=preimage, lock_proven=True,
    )
    if result["public_write_count"] == 1:
        checkpoint_receipt(Path(cfg["checkpoint_dir"]), result, uid=uid)
    return result



def reconcile_certified_checkpoints(db: sqlite3.Connection, cfg: dict,
                                    *, uid: int, trust_uid: int,
                                    now: datetime) -> dict:
    """Recover missing after-commit status files from atomic cert+preimage.

    The certificate ledger is authoritative. A process crash after a real
    committed day cannot make the publisher write the day twice. A missing
    checkpoint is reconstructed ONLY after verifying its exact durable
    before-image, public row and certificate SHA; otherwise fail closed.
    """
    append._ledger_contract(db)
    rows = public_rows(db)
    new = [r for r in rows if r["day"] > "2026-10-19"]
    need(len(new) <= MAX_FILES, "UNBOUNDED_CERTIFIED_HISTORY")
    certificates = db.execute(
        """SELECT bucket_day,certificate_sha256,source_page_sha256
           FROM traffic_public_audience_day_certificates_v2
           WHERE project_slug=? ORDER BY bucket_day""", (PROJECT,)
    ).fetchall()
    certmap = {r[0]: (r[1], r[2]) for r in certificates}
    need(len(certmap) == len(certificates)
         and set(certmap) == {r["day"] for r in new},
         "ORPHAN_OR_UNSIGNED_NEW_PUBLIC_DAY")
    recovered = []
    for row in new:
        day = row["day"]
        certsha, pagesha = certmap[day]
        need(valid_hash(certsha) and valid_hash(pagesha),
             "CERTIFICATE_LEDGER_SHA_INVALID")
        backups = list(Path(cfg["backup_dir"]).glob(
            "traffic-v2-prior-" + day + "-*.json"))
        need(len(backups) == 1, "CERTIFIED_DAY_PREIMAGE_MISSING_OR_AMBIGUOUS")
        raw = private_file(backups[0], uid=uid, max_bytes=4_000_000)
        oldsha = sha(raw)
        need(backups[0].name ==
             "traffic-v2-prior-" + day + "-" + oldsha + ".json",
             "CERTIFIED_PREIMAGE_NAME_DIGEST_DRIFT")
        def unique(pairs):
            out = {}
            for k,v in pairs:
                need(k not in out, "CERTIFIED_PREIMAGE_DUPLICATE_KEY")
                out[k] = v
            return out
        before = json.loads(raw, object_pairs_hook=unique)
        need(type(before) is list and len(before) >= 131
             and witness.canonical(before) == raw
             and before == [r for r in rows if r["day"] < day],
             "CERTIFIED_PREIMAGE_NOT_CURRENT_PREFIX")
        pre_matrix = {r["day"]: [r["total"],r["potential"],r["confirmed"]]
                      for r in before}
        pre_sha = matrix_sha(pre_matrix)
        after_matrix = dict(pre_matrix)
        after_matrix[day] = [row["total"],row["potential"],row["confirmed"]]
        after_sha = matrix_sha(after_matrix)
        saved = {
            "day": day, "source_certificate_sha256": certsha,
            "after_sha256": after_sha, "previous_sha256": pre_sha,
            "prior_131_days_sha256": append.RELEASE_SHA,
        }
        # Confirm durable certified input still agrees with SQLite journal.
        folder = Path(cfg["evidence_dir"])/day
        private_dir(folder, uid=uid)
        envelope = strict_json(private_file(folder/"day-envelope.json", uid=uid))
        page = strict_json(private_file(folder/"page-state.json", uid=uid))
        need(sha(witness.canonical(envelope["certificate"])) == certsha
             and envelope["certificate"]["page_state_sha256"] == pagesha,
             "CERTIFIED_INPUT_NO_LONGER_MATCHES_LEDGER")
        signed = witness.verify_dual_witness(
            envelope, page, now=now,
            upstream_key=private_file(Path(cfg["upstream_key"]), uid=trust_uid,
                 mode=0o644 if trust_uid == 0 else 0o600),
            classifier_key=private_file(Path(cfg["classifier_key"]), uid=trust_uid,
                 mode=0o644 if trust_uid == 0 else 0o600),
            expected_upstream_key_sha256=cfg["upstream_key_sha256"],
            expected_classifier_key_sha256=cfg["classifier_key_sha256"],
        )
        need(signed["candidate_values"] == after_matrix[day],
             "CERTIFIED_VALUES_NO_LONGER_MATCH_SIGNED_INPUT")
        receipt = Path(cfg["checkpoint_dir"])/("completed-"+day+".json")
        if receipt.exists():
            need(private_file(receipt, uid=uid) ==
                 witness.canonical(saved),
                 "CERTIFIED_DURABLE_CHECKPOINT_DRIFT")
        else:
            checkpoint_receipt(Path(cfg["checkpoint_dir"]), {
                **saved, "public_write_count": 0,
            }, uid=uid)
            recovered.append(day)
    return {"checked": len(new), "recovered_missing_receipts": recovered}


def explicit_unknown_dates(db: sqlite3.Connection, now: datetime) -> list[str]:
    cutoff = now.date() - timedelta(days=1)
    begin = date(2026,10,20)
    need((cutoff-begin).days <= MAX_FILES, "UNBOUNDED_MISSING_DATE_SCAN")
    published = {r["day"] for r in public_rows(db)}
    unknown = []
    while begin <= cutoff:
        if begin.isoformat() not in published:
            unknown.append(begin.isoformat())
        begin += timedelta(days=1)
    return unknown


def run_bounded(cfg: dict, *, now: datetime, uid: int,
                systemd_observer: Callable[[], dict],
                trust_uid: int | None = None) -> dict:
    """At most seven authenticated completed days, no self-install or timer."""
    if trust_uid is None:
        trust_uid = uid
    need(uid == cfg["run_uid"] and uid > 0 and
         os.getgid() == cfg["run_gid"],
         "DEDICATED_NONROOT_SERVICE_IDENTITY_MISMATCH")
    started = time.monotonic()
    private_dir(Path(cfg["checkpoint_dir"]), uid=uid)
    public_source_state(cfg, trust_uid=trust_uid)
    observed_unit = systemd_observer()
    unit_check(cfg, observed_unit)
    lock = Path(cfg["worker_lock"])
    fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        ls = os.fstat(fd)
        need(stat.S_ISREG(ls.st_mode) and ls.st_uid == uid
             and stat.S_IMODE(ls.st_mode) == 0o600
             and ls.st_nlink == 1, "SHARED_PROJECT_LOCK_NOT_ADMITTED")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("TRAFFIC_V2_RUNNER_HOLD_EXISTING_WORKER_BUSY") from exc
        dbpath = Path(cfg["source_database"])
        uri = "file:" + quote(dbpath.as_posix(), safe="/") + "?mode=rw"
        with closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA busy_timeout=1000")
            old = current_public(db)
            source_health = bounded_ingest_readback(db)
            restored = reconcile_certified_checkpoints(db, cfg, uid=uid,
                                                         trust_uid=trust_uid,
                                                         now=now)
            candidates = _candidate_dirs(cfg, now, uid=uid)
            count, processed = 0, []
            for day, folder in candidates:
                if count >= cfg["max_days_per_run"]:
                    break
                need(time.monotonic()-started < 90,
                     "PUBLISHER_WALL_CLOCK_BUDGET_EXCEEDED")
                # Existing certified records are idempotent; do not repeat
                # writing/checkpoint if today's permit expired postcommit.
                if day <= old["last_published"]:
                    continue
                observed_unit = systemd_observer()
                unit_check(cfg, observed_unit)
                result = verify_and_append(
                    db, cfg, day, folder, now, uid=uid,
                    trust_uid=trust_uid, observed_unit=observed_unit,
                )
                need(result["status"] == "COMMITTED_ONE_SIGNED_COMPLETED_DAY",
                     "UNEXPECTED_NONCOMMIT_RESULT")
                processed.append({"day": day, "source": result["source_certificate_sha256"],
                                  "after_public_sha256": result["after_sha256"]})
                count += 1
                old = current_public(db)
            pending = [day for day, _ in candidates if day > old["last_published"]]
            latest_complete = now.date() - timedelta(days=1)
            last = date.fromisoformat(old["last_published"])
            unknown_days = explicit_unknown_dates(db, now)
            unknown = (latest_complete-last).days
            return {
                "status": ("PUBLISHED_REAL_CERTIFIED_DAYS" if processed else
                           "HOLD_NO_ADMITTED_COMPLETED_DAY_WITNESS"),
                "new_days": processed, "new_count": count,
                "last_published_day": old["last_published"],
                "latest_completed_utc_day": latest_complete.isoformat(),
                "uncertified_lag_days": max(0, unknown),
                "uncertified_gap_count": len(unknown_days),
                "uncertified_gap_days": unknown_days,
                "reconciled_checkpoint_receipts": restored,
                "pending_signed_evidence_days": pending[:MAX_FILES],
                "original_131_day_release_intact": True,
                "last_public_sha256": old["public_sha256"],
                "source_ingest_readback": source_health,
                "authorization_mode": cfg["authorization_mode"],
                "service_installation_performed": False,
            }
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    args = argparse.ArgumentParser(description=__doc__)
    group = args.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true")
    group.add_argument("--once", action="store_true")
    parsed = args.parse_args(argv)
    if not CONFIG.is_file():
        print(json.dumps({"status": "HOLD_ROOT_OWNED_RUNNER_NOT_INSTALLED",
                          "config": str(CONFIG), "public_writes": False}))
        return 2
    try:
        now = datetime.now(timezone.utc)
        uid = os.getuid()
        cfg = config_read(CONFIG, uid=uid, trust_uid=0)
        need(uid != 0 and os.getgid() == cfg["run_gid"],
             "PINNED_NONROOT_UID_GID_REQUIRED")
        if parsed.status:
            # Status can check source/installed fingerprint without opening
            # a writable SQLite connection or touching any private data.
            public_source_state(cfg, trust_uid=0)
            unit_check(cfg, unit_readback())
            candidates = _candidate_dirs(cfg, now, uid=uid)
            uri = "file:" + quote(cfg["source_database"], safe="/") + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=1)) as db:
                db.execute("PRAGMA query_only=ON")
                published = current_public(db)
                source_health = bounded_ingest_readback(db)
                gaps = explicit_unknown_dates(db, now)
            result = {"status": "WE2_WITNESS_INPUTS_AVAILABLE_NOT_CERTIFIED",
                      "last_published_utc_day": published["last_published"],
                      "public_points": published["points"],
                      "unknown_dates": gaps,
                      "unknown_gap_count": len(gaps),
                      "source_ingest_readback": source_health,
                      "authorization_mode": cfg["authorization_mode"],
                      "candidate_days": [day for day, _ in candidates],
                      "publisher_writes": False,
                      "clock_utc": now.isoformat()}
        else:
            result = run_bounded(cfg, now=now, uid=uid,
                                 trust_uid=0,
                                 systemd_observer=unit_readback)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["status"] == "PUBLISHED_REAL_CERTIFIED_DAYS" else 2
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError,
            subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "HOLD_FAIL_CLOSED",
                          "reason": str(exc)[:300], "public_writes": False}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
