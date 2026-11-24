"""V3 isolated read-only source preparation. NO publication or signing.

An independently acquired as-of dependency snapshot and delivery handoff
are inputs, not evidence created by this process. Output is a private
candidate; distinct physical witness review remains mandatory.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
from datetime import date, datetime, timedelta, timezone
import hashlib
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
    need(page.get("day") == day.isoformat() and page.get("source_prefix_exhausted") is True
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
         **{k:o[k] for k in ("daily_model_sha256","carry_sha256","classifier_dependencies_sha256",
                            "normalized_input_sha256","source_evidence_sha256")},
         **dict(zip(("total","potential","confirmed"),o["metrics"]))}
    witness.check_day_witness(c, page, now=now, observation=o)
    return c
