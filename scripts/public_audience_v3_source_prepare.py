"""V3 isolated read-only source preparation. NO publication or signing.

An independently acquired as-of dependency snapshot and delivery handoff
are inputs, not evidence created by this process. Output is a private
candidate; distinct physical witness review remains mandatory.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
from datetime import date, datetime, timedelta, timezone
import argparse
import hashlib
import os
import stat
import subprocess
import json
from pathlib import Path
import sqlite3
import time
from typing import Any
from unittest.mock import patch
from urllib.parse import quote

from app.services.traffic import sessions, known_visitors
from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts import public_audience_v2_daily_source_parity as parity
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_sessions as canonical_state
from scripts import public_audience_v2_day_admission as witness
from scripts import public_audience_v3_daily_observation_review as observation
from scripts import rebuild_public_audience_archive as canonical

DEPENDENCY_SCHEMA = "traffic.public-audience.v3.frozen-dependencies.v1"
DEPENDENCY_FIELDS = {"schema", "day", "as_of_utc", "source_commit_sha",
    "runtime_manifest_sha256", "geo_dataset_sha256", "identity_snapshot_sha256",
    "host_rules_sha256", "hosts", "rules", "geo_by_ip", "known_by_ip"}
DELIVERY_FIELDS = {"schema", "day", "source_prefix_rowid", "upstream_closed_through_utc",
    "writer_closed_through_utc", "upstream_eof_evidence_sha256",
    "writer_receipt_evidence_sha256", "late_arrival_evidence_sha256",
    "carry_delivery_evidence_sha256"}
DELIVERY_SCHEMA = "traffic.public-audience.v3.delivery-handoff.v1"
MAX_ROWS = 200_000


def need(ok: bool, why: str) -> None:
    if not ok:
        raise ValueError("TRAFFIC_V3_SOURCE_HOLD_" + why)


def sha(value: Any) -> str:
    return witness.digest(witness.canonical(value))


def hex64(value: Any) -> bool:
    return type(value) is str and witness.HEX.fullmatch(value) is not None


def prepare(raw: sqlite3.Connection, ledger: sqlite3.Connection, *,
            day: date, page: dict, dependencies: dict, dependency_sha256: str,
            delivery: dict, delivery_sha256: str,
            reviewed_source_commit: str, now: datetime, limit: int = MAX_ROWS,
            budget_seconds: int = 90) -> dict:
    """Use exact same source/ledger prefix, actual raw receipt clocks and
    independently pinned dependency preimage. Intended only for one isolated
    CLI process, not in web/worker threads. No ambient geo/identity lookups.
    The caller must establish origin/authority of both supplied preimages.
    """
    need(type(day) is date and witness.V3_FIRST_NEW <= day < now.date(), "DAY_SCOPE")
    need(1 <= limit <= MAX_ROWS and 1 <= budget_seconds <= 100, "RESOURCE_SCOPE")
    need(raw.in_transaction and ledger.in_transaction, "PINNED_READ_TRANSACTIONS_REQUIRED")
    need(raw.execute("PRAGMA query_only").fetchone()[0] == 1
         and ledger.execute("PRAGMA query_only").fetchone()[0] == 1, "READ_ONLY_REQUIRED")
    start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    lower = start - observation.GAP
    need(type(dependencies) is dict and set(dependencies) == DEPENDENCY_FIELDS
         and dependencies["schema"] == DEPENDENCY_SCHEMA
         and sha(dependencies) == dependency_sha256
         and dependencies["day"] == day.isoformat()
         and dependencies["as_of_utc"] == end.isoformat()
         and dependencies["source_commit_sha"] == reviewed_source_commit
         and len(reviewed_source_commit) == 40
         and all(c in "0123456789abcdef" for c in reviewed_source_commit),
         "AUTHENTIC_AS_OF_DEPENDENCIES_REQUIRED")
    need(all(hex64(dependencies[k]) for k in ("runtime_manifest_sha256",
        "geo_dataset_sha256", "identity_snapshot_sha256", "host_rules_sha256")),
        "DEPENDENCY_PINS")
    hosts, rules = dependencies["hosts"], dependencies["rules"]
    need(type(hosts) is list and 0 < len(hosts) <= 16
         and all(type(h) is str and h for h in hosts) and len(set(hosts)) == len(hosts)
         and type(rules) is list, "HOST_RULE_SCOPE")
    host_digest = hashlib.sha256(json.dumps(hosts).encode()).hexdigest()
    rule_digest = hashlib.sha256(json.dumps(rules, sort_keys=True, default=str).encode()).hexdigest()
    need(sha({"hosts":hosts,"hosts_sha256":host_digest,"rules_sha256":rule_digest}) == dependencies["host_rules_sha256"],
         "FROZEN_HOST_RULE_PREIMAGE_DRIFT")
    need(set(page) == witness.STATE_FIELDS and page.get("day") == day.isoformat() and page.get("source_prefix_exhausted") is True
         and page.get("host_rules_sha256") == dependencies["host_rules_sha256"]
         and page.get("missing_receipts") == page.get("invalid_clocks") == 0,
         "PAGE_SCOPE")
    prefix = page["snapshot_rowid"]
    need(type(prefix) is int and prefix > 0 and prefix == page["forward_prefix_rowid"],
         "PREFIX_SCOPE")
    need(type(delivery) is dict and set(delivery) == DELIVERY_FIELDS
         and delivery["schema"] == DELIVERY_SCHEMA and sha(delivery) == delivery_sha256
         and delivery["day"] == day.isoformat() and delivery["source_prefix_rowid"] == prefix,
         "DELIVERY_HANDOFF")
    need(all(hex64(delivery[k]) for k in ("upstream_eof_evidence_sha256",
        "writer_receipt_evidence_sha256", "late_arrival_evidence_sha256",
        "carry_delivery_evidence_sha256")), "DELIVERY_DIGESTS")
    upstream = witness.utc_stamp(delivery["upstream_closed_through_utc"])
    writer = witness.utc_stamp(delivery["writer_receipts_closed_through_utc"])
    need(end + observation.DELIVERY_MARGIN <= min(upstream, writer)
         and max(upstream, writer) <= now, "DELIVERY_CLOCKS")
    meta = dict(ledger.execute("SELECT key,value FROM ledger_metadata"))
    need(meta.get("phase") == "LIVE" and int(meta["live_rowid"]) >= prefix, "LEDGER_PREFIX")
    need(raw.execute("SELECT MAX(rowid) FROM traffic_entries").fetchone()[0] >= prefix,
         "SOURCE_PREFIX")
    deadline = time.monotonic() + budget_seconds
    fields = "rowid AS source_rowid,event_id,timestamp,ip,line_offset,raw_path,normalized_path,referrer_host,ua,host"
    marks = ",".join("?" for _ in hosts)
    base = f"FROM traffic_entries INDEXED BY idx_traffic_entries_timestamp_line_offset WHERE timestamp>=? AND timestamp<? AND host IN ({marks}) AND ({_non_browser_chain_firehose_sql()})"
    args = (lower.isoformat(), end.isoformat(), *hosts)
    for db in (raw, ledger):
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        need(raw.execute("SELECT rowid " + base + " AND rowid>? LIMIT 1",
                         (*args, prefix)).fetchone() is None, "LATE_ARRIVAL_AFTER_PREFIX")
        accepted = {}
        normalized = []
        all_raw_hash = hashlib.sha256()
        day_rows = 0
        count = 0
        for row in raw.execute("SELECT " + fields + ",ingested_at_utc " + base +
                    " AND rowid<=? ORDER BY timestamp,line_offset,rowid LIMIT ?",
                    (*args, prefix, limit+1)):
            count += 1
            need(count <= limit and time.monotonic() < deadline, "SOURCE_BUDGET")
            event_time = witness.utc_stamp(row["timestamp"])
            receipt = witness.utc_stamp(row["ingested_at_utc"])
            need(event_time <= receipt <= now, "INVALID_INSERTION_CLOCK")
            if event_time >= start:
                day_rows += 1
            rid, finger = parity.event_fingerprint(row)
            all_raw_hash.update(witness.canonical([rid, finger, row["ingested_at_utc"]]))
            item = canonical.normalize_row(row, rules=rules)
            if item is None:
                continue
            item["source_rowid"] = rid
            item["timestamp"] = item["timestamp"].astimezone(timezone.utc)
            item["timestamp_iso"] = item["timestamp"].isoformat()
            need(rid not in accepted, "SOURCE_DUPLICATE")
            accepted[rid] = finger
            normalized.append(item)
        need(day_rows == page["total_rows"], "PAGE_ROW_COUNT_DRIFT")
        retained = {}
        for rid, data in ledger.execute(
                "SELECT source_rowid,event_json FROM future_events WHERE timestamp>=? AND timestamp<? AND source_rowid<=? LIMIT ?",
                (lower.isoformat(), end.isoformat(), prefix, limit+1)):
            need(len(retained) < limit and time.monotonic() < deadline, "LEDGER_BUDGET")
            rec = json.loads(data)
            actual, finger = parity.event_fingerprint(rec)
            need(actual == rid and rid not in retained, "LEDGER_IDENTITY")
            retained[rid] = finger
        need(accepted == retained, "SOURCE_LEDGER_IDENTITY_DRIFT")
        geo = dependencies["geo_by_ip"]
        known = dependencies["known_by_ip"]
        ips = {e["ip"] for e in normalized if e["timestamp"] >= start}
        need(type(geo) is dict and type(known) is dict and ips <= geo.keys()
             and ips <= known.keys(), "DEPENDENCY_LOOKUP_COVERAGE")
        need(all(type(geo[ip]) is dict and set(geo[ip]) == {"country","country_code","area","city","geo_resolved"}
                 and type(geo[ip]["geo_resolved"]) is bool for ip in ips)
             and all(known[ip] is None or (type(known[ip]) is dict
                 and {"label","detail","identity_kind","confidence"} <= known[ip].keys())
                 for ip in ips), "DEPENDENCY_LOOKUP_SHAPE")
        source_body = {"day": day.isoformat(), "page_state_sha256": sha(page),
                       "raw_day_and_carry_sha256": all_raw_hash.hexdigest(),
                       "source_and_ledger_sha256": sha(sorted(accepted.items())),
                       "raw_day_and_carry_rows": count, "raw_day_rows": day_rows,
                       "delivery_handoff_sha256": delivery_sha256}
        with ExitStack() as stack:
            stack.enter_context(patch.object(sessions, "get_geo_details", side_effect=lambda ip: dict(geo[ip])))
            stack.enter_context(patch.object(known_visitors, "known_visitor_for_ip",
                                side_effect=lambda ip: known[ip]))
            result = observation.observe(day, normalized, source_prefix=prefix,
                source_evidence_sha256=sha(source_body),
                classifier_dependencies_sha256=dependency_sha256,
                upstream_closed_through=upstream, writer_closed_through=writer)
        need(time.monotonic() < deadline, "CLASSIFIER_BUDGET")
        return {**result, "source_evidence": source_body,
                "classifier_source_commit_sha": reviewed_source_commit,
                "delivery_handoff_sha256": delivery_sha256,
                "independent_origin_review_required": True}
    finally:
        for db in (raw, ledger):
            db.set_progress_handler(None, 0)


def certificate_body(candidate: dict, page: dict, delivery: dict, *, now: datetime) -> dict:
    """Unsigned exact witness body. Use only AFTER independent source review;
    this constructs no signatures, creates no request files, grants no authority.
    """
    o = candidate["observation"]
    need(sha(candidate["source_evidence"]) == o["source_evidence_sha256"]
         and candidate["source_evidence"]["delivery_handoff_sha256"] == sha(delivery)
         and candidate["source_evidence"]["page_state_sha256"] == sha(page),
         "CANDIDATE_EVIDENCE_DRIFT")
    c = {"schema": witness.V3_SCHEMA, "project_slug": "aoe2hdbets",
         "day": o["day"], "historical_release_sha256": witness.RELEASE_SHA,
         "source_epoch_sha256": page["source_epoch_sha256"],
         "host_rules_sha256": page["host_rules_sha256"], "page_state_sha256": sha(page),
         "source_snapshot_rowid": page["snapshot_rowid"], "forward_prefix_rowid": page["forward_prefix_rowid"],
         "source_rows": page["total_rows"], "source_page_chain_sha256": page["chain_sha256"],
         "missing_insertion_receipts": page["missing_receipts"], "invalid_insertion_clocks": page["invalid_clocks"],
         "upstream_log_closed_through_utc": o["upstream_closed_through_utc"],
         "writer_receipts_closed_through_utc": o["writer_closed_through_utc"],
         "observation_sha256": sha(o), "late_arrival_stability_sha256": delivery["late_arrival_evidence_sha256"],
         "classifier_source_commit_sha": candidate["classifier_source_commit_sha"],
         **{k:o[k] for k in ("daily_model_sha256","carry_sha256","classifier_dependencies_sha256",
                            "normalized_input_sha256","source_evidence_sha256")},
         **dict(zip(("total","potential","confirmed"),o["metrics"]))}
    witness.check_day_witness(c, page, now=now, observation=o)
    return c


def read_private_json(path: Path, expected: str) -> dict:
    """Exact private canonical JSON; no symlinks, hardlinks or mutable reads."""
    need(path.is_absolute() and path.resolve() == path and hex64(expected), "PRIVATE_PATH_OR_PIN")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 < before.st_size <= 32_000_000, "PRIVATE_PREIMAGE_SCOPE")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(32_000_001)
        after = os.fstat(fd)
        need((before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (after.st_size,after.st_mtime_ns,after.st_ctime_ns)
             and len(data) == before.st_size, "PRIVATE_PREIMAGE_MOVED")
        obj = json.loads(data)
        need(type(obj) is dict and data == witness.canonical(obj)
             and witness.digest(data) == expected, "PRIVATE_PREIMAGE_DIGEST_DRIFT")
        return obj
    finally:
        os.close(fd)


def run(args) -> dict:
    """Native, bounded, read-only isolated CLI; stdout is private aggregate only."""
    import fcntl
    need(args.source.is_absolute() and args.source.resolve() == args.source,
         "SOURCE_PATH")
    need(args.checkpoint.parent == args.ledger.parent and
         args.checkpoint.parent.stat().st_mode & 0o077 == 0, "PRIVATE_COHORT")
    for p in (args.checkpoint,args.ledger):
        need(p.is_absolute() and p.resolve() == p and p.is_file()
             and p.stat().st_mode & 0o777 == 0o600 and p.stat().st_nlink == 1,
             "PRIVATE_COHORT_FILE")
    # Root review must supply actual exact Git checkout, not a claimed label.
    root = Path(__file__).resolve().parents[1]
    head = subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    dirty = subprocess.check_output(["git","-C",str(root),"status","--porcelain"],text=True)
    need(head == args.source_commit and not dirty, "REVIEWED_SOURCE_CHECKOUT_DRIFT")
    page = read_private_json(args.page,args.page_sha256)
    deps = read_private_json(args.dependencies,args.dependencies_sha256)
    handoff = read_private_json(args.delivery,args.delivery_sha256)
    guard.require_worker_priority()
    need(guard.worker_idle(), "PROJECT_WORKER_BUSY")
    lockfd = os.open(args.checkpoint.parent/".canary.lock",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        need(stat.S_ISREG(os.fstat(lockfd).st_mode), "COHORT_LOCK")
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        info = guard.checkpoint_info(args.checkpoint)
        guard.verify_frozen(args.source,args.checkpoint,info)
        need(info["phase"] == "PASS2_COMPLETE", "HISTORIC_CHECKPOINT")
        hosts,rules = canonical_state.verified_state(args.source,args.checkpoint,info)
        need(deps["hosts"] == hosts and deps["rules"] == rules, "CHECKPOINT_HOST_POLICY_DRIFT")
        need(page["source_epoch_sha256"] == sha({k:info[k] for k in
             ("device","inode","watermark","canonical_sha256","p1_digest")}), "SOURCE_EPOCH_DRIFT")
        with ExitStack() as stack:
            dbs = []
            for p in (args.source,args.ledger):
                db = stack.enter_context(closing(sqlite3.connect("file:"+quote(str(p),safe="/")+"?mode=ro",
                                                     uri=True,timeout=1)))
                db.row_factory=sqlite3.Row
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                dbs.append(db)
            raw,ledger=dbs
            forward.assert_published_history(raw)
            forward.validate_ledger(forward.read_metadata(ledger),info)
            return prepare(raw,ledger,day=date.fromisoformat(args.day),page=page,dependencies=deps,
                dependency_sha256=args.dependencies_sha256,delivery=handoff,delivery_sha256=args.delivery_sha256,
                reviewed_source_commit=head,now=datetime.now(timezone.utc))
    finally:
        os.close(lockfd)


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("source","checkpoint","ledger","page","dependencies","delivery"):
        p.add_argument("--"+key,type=Path,required=True)
    for key in ("day","source-commit","page-sha256","dependencies-sha256","delivery-sha256"):
        p.add_argument("--"+key,required=True)
    try:
        result=run(p.parse_args())
        print(witness.canonical(result).decode("utf-8"))
        return 0
    except (ValueError,RuntimeError,KeyError,TypeError,OSError,sqlite3.Error,subprocess.CalledProcessError):
        # Avoid error strings that might contain private identifiers.
        print("TRAFFIC_V3_SOURCE_HOLD_NO_CANDIDATE")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
