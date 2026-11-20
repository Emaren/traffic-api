#!/usr/bin/env python3
"""Traffic lane for the shared AoE2WAR Production Reconciliation Gate.

READ ONLY, nonroot. Production source row clocks, original locked ingestion
architecture, signed certificate ledger, publisher timer, BOTH public HTTP
matrices, calendar staleness and the independent Chrome graph witness are
separate gates. HTTP 200 plus 131 frozen days is explicitly FAILURE.

This does not issue certificates, create signing keys, publish, install a
service, alter a database, or replace the independent owner/WE2 review.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
import json
import hashlib
import os
from pathlib import Path
import sqlite3
import urllib.request
import subprocess
import sys

from scripts import public_audience_v2_operational_status as public
from scripts.public_audience_v2_release_manifest import sha as matrix_sha

PROJECT = "aoe2hdbets"
SOURCE = Path("/mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3")
SIGNED_RECEIPT_R0 = 51_387_589  # Original PR77 protected installation receipt.
RECEIPTS_ON_UTC_DAY = date(2026, 11, 20)
INGEST_TIMER = "traffic-ingest.timer"
INGEST_SERVICE = "traffic-ingest.service"
API_SERVICE = "traffic-api.service"
PUBLISHER_TIMER = "traffic-v2-publisher.timer"
PUBLISHER_SERVICE = "traffic-v2-publisher.service"
CERT_LEDGER = "traffic_public_audience_day_certificates_v2"
PROTECTED_RUNNER = Path("/etc/aoe2war/traffic-v2/runner.json")
FROZEN_LAST = date(2026, 10, 19)
GRAPH_PATH = "https://aoe2war.com/traffic"
MAX_AGE_MINUTES = 10
FINANCIAL_PORTS = {8092, 8093, 8094, 8095}
SIGNED_LOADED_INGEST_SHA256 = "1a700eacf9e0494706fbe32111db890a33f7f620592fdfc17ec071ae6781bea9"
SIGNED_ORIGINAL_TIMER_SHA256 = "25e477653b9ed312159177732aae5af6f2ae4acd573a96dfe74b14bc267572b2"
SIGNED_ORIGINAL_FLOCK = "/usr/bin/flock -n -E 75 /run/traffic-ingest/sync.lock"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError("TRAFFIC_PRODUCTION_RECONCILIATION_HOLD_" + reason)


def run(*argv: str, timeout: int = 7) -> str:
    p = subprocess.run(argv, check=False, capture_output=True, timeout=timeout,
                       text=True)
    require(p.returncode == 0 and len(p.stdout) <= 30000,
            "READ_ONLY_COMMAND_FAILED")
    return p.stdout


def systemd(unit: str) -> dict:
    require(unit in {INGEST_SERVICE, INGEST_TIMER, API_SERVICE,
                    PUBLISHER_SERVICE, PUBLISHER_TIMER},
            "UNALLOWLISTED_UNIT")
    fields = ("LoadState", "ActiveState", "UnitFileState", "Environment",
              "User", "Group", "ExecStart", "ExecMainStatus", "LastTriggerUSec")
    args = ["systemctl", "show", unit]
    for field in fields:
        args.extend(("-p", field))
    args.append("--no-pager")
    return dict(line.split("=", 1) for line in run(*args).splitlines()
                if "=" in line)


def source_observation(path: Path = SOURCE, r0: int = SIGNED_RECEIPT_R0) -> dict:
    require(path == SOURCE and type(r0) is int and r0 == SIGNED_RECEIPT_R0,
            "PINNED_ORIGINAL_SOURCE_IDENTITY")
    require(path.is_file() and not path.is_symlink(), "SOURCE_DB_NOT_PRESENT")
    st = path.stat()
    # 2064/131074 are actual signed-source device/inode pins, not values
    # recalculated from whatever new path appears.
    require((st.st_dev, st.st_ino) == (2064, 131074),
            "SOURCE_DB_DEVICE_INODE_CHANGED")
    candidate_day = max(RECEIPTS_ON_UTC_DAY,
                        datetime.now(timezone.utc).date())
    next_day = candidate_day + timedelta(days=1)
    with closing(sqlite3.connect("file:" + str(path) + "?mode=ro",
                                 uri=True, timeout=2)) as db:
        db.execute("PRAGMA query_only=ON")
        # Bounded newest sample; a full all-time COUNT would grow without
        # limit as the original one-writer SQLite ingester runs for years.
        row = db.execute(
            "SELECT COUNT(*), COUNT(ingested_at_utc),"
            " MAX(rowid), MAX(ingested_at_utc) FROM ("
            "SELECT rowid, ingested_at_utc FROM traffic_entries"
            " WHERE rowid > ? ORDER BY rowid DESC LIMIT 512)", (r0,)
        ).fetchone()
        before = db.execute(
            "SELECT COUNT(*),SUM(ingested_at_utc IS NOT NULL) FROM ("
            "SELECT ingested_at_utc FROM traffic_entries WHERE rowid <= ?"
            " ORDER BY rowid DESC LIMIT 1000)", (r0,)
        ).fetchone()
        current = db.execute(
            "SELECT COUNT(*),COUNT(ingested_at_utc)"
            " FROM traffic_entries INDEXED BY idx_traffic_entries_timestamp"
            " WHERE timestamp >= ? AND timestamp < ?",
            (candidate_day.isoformat(), next_day.isoformat()),
        ).fetchone()
        schemas = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN (?,?)",
            (CERT_LEDGER, "traffic_public_daily_audience_rollups"),
        )}
        ledger = []
        if CERT_LEDGER in schemas:
            ledger = db.execute(
                "SELECT bucket_day,certificate_sha256,source_page_sha256"
                " FROM traffic_public_audience_day_certificates_v2"
                " WHERE project_slug=? ORDER BY bucket_day", (PROJECT,)
            ).fetchall()
        private = db.execute(
            "SELECT bucket_day,total_traffic,suspected_human,confirmed_human"
            " FROM traffic_public_daily_audience_rollups"
            " WHERE project_slug=? ORDER BY bucket_day", (PROJECT,)
        ).fetchall()
        original_cursor = db.execute(
            "SELECT source_inode,offset,updated_at FROM traffic_ingest_state"
            " WHERE source_path=?", ("/var/log/nginx/access.log",)
        ).fetchone()
    return {
        "dev": st.st_dev, "inode": st.st_ino, "r0": r0,
        "new_rows": row[0], "new_clocked": row[1], "max_rowid": row[2],
        "latest_inserted_utc": row[3], "historic_probe_rows": before[0],
        "historic_probe_retroclocked": before[1] or 0,
        "prospective_day": candidate_day.isoformat(),
        "recent_natural_receipt_sample_limit": 512,
        "prospective_rows": current[0], "prospective_clocked": current[1],
        "certificate_ledger_present": CERT_LEDGER in schemas,
        "certificates": [list(item) for item in ledger],
        "private_published_rows": [list(item) for item in private],
        "cursor": list(original_cursor) if original_cursor else None,
    }


def host_observation() -> dict:
    names = (INGEST_TIMER, INGEST_SERVICE, API_SERVICE,
             PUBLISHER_SERVICE, PUBLISHER_TIMER)
    units = {name: systemd(name) for name in names}
    loaded = {}
    for name in (INGEST_SERVICE, INGEST_TIMER):
        p = subprocess.run(["systemctl", "cat", name], check=False,
                           capture_output=True, timeout=7)
        require(p.returncode == 0 and 0 < len(p.stdout) < 60000,
                "SIGNED_SYSTEMD_UNIT_READBACK_UNAVAILABLE")
        loaded[name] = hashlib.sha256(p.stdout).hexdigest()
    listeners = run("ss", "-H", "-ltn")
    open_financial = []
    for line in listeners.splitlines():
        words = line.split()
        if len(words) >= 4:
            port = words[3].rsplit(":", 1)[-1]
            if port.isdigit() and int(port) in FINANCIAL_PORTS:
                open_financial.append(int(port))
    return {
        "units": units,
        "original_signed_unit_sha256": loaded,
        "publisher_config_present": PROTECTED_RUNNER.is_file(),
        "financial_open_ports": sorted(set(open_financial)),
    }


def utc_stamp(raw: str) -> datetime:
    require(type(raw) is str, "CLOCK_MISSING")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("TRAFFIC_PRODUCTION_RECONCILIATION_HOLD_CLOCK_INVALID") from exc
    require(value.tzinfo is not None, "CLOCK_NAIVE")
    return value.astimezone(timezone.utc)


def independently_verify_certificates(source: dict, *, now: datetime) -> list[str]:
    """Verify genuine dual Ed25519 sources against WE2 pinned nonroot trust.

    A certificate *row alone* is never accepted as an authentic source or
    classification attestation. With no real WE2 key enrollment the result
    remains empty/failing. This function does not touch publisher state.
    """
    if not source["certificate_ledger_present"] or not source["certificates"]:
        return []
    if not PROTECTED_RUNNER.is_file():
        return []
    try:
        from scripts import public_audience_v2_runner as publisher
        from scripts import public_audience_v2_day_admission as signatures
        cfg = publisher.config_read(PROTECTED_RUNNER, uid=os.getuid(), trust_uid=0)
        if os.getuid() != cfg["run_uid"] or os.getgid() != cfg["run_gid"]:
            return []
        upstream = publisher.private_file(Path(cfg["upstream_key"]), uid=0,
                                          mode=0o644, max_bytes=3000)
        classifier = publisher.private_file(Path(cfg["classifier_key"]), uid=0,
                                            mode=0o644, max_bytes=3000)
        public_matrix = {
            day: [total, potential, confirmed]
            for day, total, potential, confirmed in source["private_published_rows"]
        }
        verified = []
        for day, cert_sha, page_sha in source["certificates"]:
            folder = Path(cfg["evidence_dir"]) / day
            publisher.private_dir(folder, uid=os.getuid())
            env = publisher.strict_json(publisher.private_file(
                folder / "day-envelope.json", uid=os.getuid()))
            page = publisher.strict_json(publisher.private_file(
                folder / "page-state.json", uid=os.getuid()))
            proof = signatures.verify_dual_witness(
                env, page, now=now,
                upstream_key=upstream, classifier_key=classifier,
                expected_upstream_key_sha256=cfg["upstream_key_sha256"],
                expected_classifier_key_sha256=cfg["classifier_key_sha256"],
            )
            if (proof["day"] != day or
                    proof["certificate_digest_sha256"] != cert_sha or
                    proof["source_page_digest"] != page_sha or
                    proof["candidate_values"] != public_matrix.get(day) or
                    proof["dual_witness_signatures_verified"] is not True):
                return []
            verified.append(day)
        return verified
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        return []


def independently_verify_revocation(now: datetime) -> bool:
    """Fresh owner-signed external ACTIVE + protected GitHub ruleset.

    Must have WE2-admitted keys/config, a real protected branch and the
    independent transition check. Never seeds a branch or trusts a fixture.
    """
    if not PROTECTED_RUNNER.is_file():
        return False
    try:
        from scripts import public_audience_v2_runner as publisher
        from scripts import public_audience_v2_daily_delegation as scope
        from scripts import public_audience_v2_revocation_external as external
        cfg = publisher.config_read(PROTECTED_RUNNER, uid=os.getuid(), trust_uid=0)
        owner_pub = publisher.private_file(
            Path(cfg["operator_key"]), uid=0, mode=0o644, max_bytes=3000)
        local = publisher.strict_json(publisher.private_file(
            Path(cfg["delegation_state"]), uid=0, mode=0o644, max_bytes=14000))
        delegation = publisher.strict_json(publisher.private_file(
            Path(cfg["daily_delegation"]), uid=0, mode=0o644, max_bytes=14000))
        current = external.current_external_state(now=now)
        external.compare_root_and_external(local, current)
        state, _ = scope.signed(
            current, value_key="state", expected_fields=scope.STATE_FIELDS,
            public_key=owner_pub, public_sha256=cfg["operator_key_sha256"])
        owner, digest = scope.signed(
            delegation, value_key="delegation",
            expected_fields=scope.DELEGATION_FIELDS,
            public_key=owner_pub, public_sha256=cfg["operator_key_sha256"])
        if (state["status"] != "ACTIVE" or state["revision"] < 1
                or state["delegation_sha256"] != digest
                or state["delegation_id"] != owner["delegation_id"]
                or owner["project"] != PROJECT):
            return False
        url = "https://api.github.com/repos/Emaren/traffic-api/rulesets/27691195"
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AoE2WAR-Traffic-ReadOnly-Production-Gate/1",
            "Cache-Control": "no-cache",
        })
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status != 200:
                return False
            payload = response.read(20_001)
        if len(payload) > 20_000:
            return False
        ruleset = json.loads(payload)
        rules = {r["type"]: r for r in ruleset["rules"]}
        return (
            ruleset["enforcement"] == "active"
            and ruleset["bypass_actors"] == []
            and ruleset["conditions"]["ref_name"]["include"]
                == ["refs/heads/traffic-v2-revocation"]
            and {"deletion", "non_fast_forward", "pull_request",
                 "required_status_checks"} <= set(rules)
            and rules["pull_request"]["parameters"]["required_approving_review_count"] >= 1
            and any(v.get("context") == "verify-traffic-v2-revocation-transition"
                    for v in rules["required_status_checks"]["parameters"][
                        "required_status_checks"])
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False


def judge(source: dict, host: dict, api_diag: dict, *, now: datetime,
          browser_observation: dict | None = None) -> dict:
    require(now.tzinfo is not None, "OBSERVATION_CLOCK_NAIVE")
    now = now.astimezone(timezone.utc)
    failed = []
    passed = []

    def gate(name: str, ok: bool, reason: str) -> None:
        (passed if ok else failed).append(name if ok else name + ":" + reason)

    current = source["max_rowid"]
    recent = source["latest_inserted_utc"]
    is_recent = (recent is not None and
                 -timedelta(minutes=1) <= now - utc_stamp(recent)
                 <= timedelta(minutes=MAX_AGE_MINUTES))
    gate("natural_ingestion_receipts",
         source["new_rows"] > 0 and source["new_rows"] == source["new_clocked"]
         and source["max_rowid"] > source["r0"] and is_recent
         and source["historic_probe_rows"] == 1000
         and source["historic_probe_retroclocked"] == 0,
         "MISSING_OR_STALE_NATURAL_INSERTS_OR_RETROCLOCKED_HISTORY")
    ingest = host["units"][INGEST_TIMER]
    ingest_svc = host["units"][INGEST_SERVICE]
    api_svc = host["units"][API_SERVICE]
    gate("original_single_ingest_configuration",
         ingest["ActiveState"] == "active"
         and ingest["UnitFileState"] == "enabled"
         and ingest_svc["Environment"].split().count(
             "TRAFFIC_INGEST_RECEIPTS_ENABLED=1") == 1
         and api_svc["Environment"].split().count(
             "TRAFFIC_DISABLE_INLINE_INGEST=1") == 1
         and host.get("original_signed_unit_sha256", {}).get(INGEST_SERVICE)
             == SIGNED_LOADED_INGEST_SHA256
         and host.get("original_signed_unit_sha256", {}).get(INGEST_TIMER)
             == SIGNED_ORIGINAL_TIMER_SHA256
         and SIGNED_ORIGINAL_FLOCK in ingest_svc.get("ExecStart", "")
         and "scripts/sync_traffic_logs.py" in ingest_svc.get("ExecStart", "")
         and not host["financial_open_ports"],
         "ONE_WRITER_CONFIGURATION_OR_FINANCIAL_ISOLATION_DRIFT")
    gate("complete_utc_day_proven",
         bool(source["certificate_ledger_present"] and source["certificates"]
              and source.get("independently_verified_certificate_days")
              == [r[0] for r in source["certificates"]]),
         "NO_INDEPENDENTLY_VERIFIED_DUAL_SIGNED_COMPLETED_DAYS")
    gate("external_owner_revocation_trust",
         source.get("protected_revocation_state_verified") is True,
         "OWNER_SIGNED_REMOTE_STATE_OR_INDEPENDENT_RULESET_NOT_ADMITTED")
    cert_days = [d for d, *_ in source["certificates"]]
    pub = {d: (a, b, c) for d, a, b, c in source["private_published_rows"]}
    future = [d for d in pub if d > FROZEN_LAST.isoformat()]
    gate("certified_published_day_parity",
         len(set(cert_days)) == len(cert_days)
         and sorted(cert_days) == sorted(future)
         and all(d in pub for d in cert_days),
         "CERTIFICATE_LEDGER_AND_PUBLIC_DAY_DIFFER")
    unit = host["units"][PUBLISHER_SERVICE]
    timer = host["units"][PUBLISHER_TIMER]
    gate("nonroot_unattended_publisher",
         unit["LoadState"] == "loaded"
         and unit["User"] not in ("", "root", "0")
         and timer["LoadState"] == "loaded"
         and timer["ActiveState"] == "active"
         and timer["UnitFileState"] == "enabled"
         and bool(timer["LastTriggerUSec"])
         and host["publisher_config_present"],
         "PUBLISHER_NOT_INSTALLED_OR_NO_NATURAL_TIMER_RECEIPT")
    private_sha = matrix_sha({d: list(v) for d, v in pub.items()})
    gate("complete_public_api_parity",
         api_diag.get("traffic_api_website_parity") is True
         and api_diag.get("historical_131_days_intact") is True
         and len(pub) == api_diag.get("published_points")
         and max(pub, default=None) == api_diag.get("last_published_utc_day")
         and api_diag.get("canonical_full_matrix_sha256") == private_sha,
         "API_PRIVATE_DATABASE_FULL_MATRIX_OR_FROZEN_HISTORY_MISMATCH")
    latest = api_diag.get("last_published_utc_day")
    target = now.date() - timedelta(days=1)
    # D+1 00:31 UTC is the earliest evidence closure. Allow until 02:00
    # UTC for an hourly publisher timer; then require the preceding day.
    # The preinstrumentation hole cannot become an invented zero date.
    expected = max(RECEIPTS_ON_UTC_DAY, now.date() - timedelta(
        days=1 if now.hour >= 2 else 2))
    age = (now.date() - date.fromisoformat(latest)).days
    gate("public_graph_freshness",
         latest >= expected.isoformat() and age <= 2,
         "STALE_" + str(age) + "_UTC_CALENDAR_DAYS_REQUIRED_"
         + expected.isoformat())
    # An actual Chrome DOM/screenshot witness is distinct from HTTP/API.
    # No unsigned machine-generated assertion can certify it.
    gate("chrome_graph_and_gap_renderer",
         browser_observation is not None
         and browser_observation.get("status") ==
             "INDEPENDENT_REAL_CHROME_GAP_RENDERER_VERIFIED"
         and browser_observation.get("latest_utc_day") == latest
         and browser_observation.get("observed_at_utc") is not None
         and timedelta(0) <= now - utc_stamp(browser_observation["observed_at_utc"])
         <= timedelta(minutes=30),
         "ACTUAL_INDEPENDENT_BROWSER_READBACK_NOT_ADMITTED")
    return {
        "schema": "aoe2war.production-reconciliation.traffic.v1",
        "lane": "TRAFFIC",
        "status": "PASS" if not failed else "FAIL",
        "severity": "P0" if failed else "none",
        "observed_utc": now.isoformat(),
        "failed_checks": failed, "passed_checks": passed,
        "source_row_watermark": current,
        "recent_postinstall_sample_rows": source["new_rows"],
        "recent_postinstall_sample_clocked": source["new_clocked"],
        "last_natural_insertion_utc": recent,
        "candidate_day": source["prospective_day"],
        "candidate_clocked_count": source["prospective_clocked"],
        "candidate_row_count": source["prospective_rows"],
        "certified_day_ids": cert_days,
        "authentic_certificate_signatures_verified":
            source.get("independently_verified_certificate_days", []) == cert_days
            and bool(cert_days),
        "owner_revocation_active_external_verified":
            source.get("protected_revocation_state_verified") is True,
        "certified_certificate_sha256": [row[1] for row in source["certificates"]],
        "publisher_high_water_utc_day": max(future, default=None),
        "last_public_utc_day": latest,
        "last_completed_utc_day": target.isoformat(),
        "freshness_target_after_hourly_grace_utc_day": expected.isoformat(),
        "publication_lag_utc_days": age,
        "api_point_count": api_diag.get("published_points"),
        "both_api_matrices_exact": api_diag.get("traffic_api_website_parity"),
        "private_db_full_matrix_sha256": private_sha,
        "api_full_matrix_sha256": api_diag.get("canonical_full_matrix_sha256"),
        "original_131_day_digest_intact": api_diag.get("historical_131_days_intact"),
        "gap_renderer_browser_verified": "chrome_graph_and_gap_renderer" in passed,
        "first_public_utc_day": min(pub, default=None),
        "publisher_service": PUBLISHER_SERVICE,
        "publisher_service_load_state": unit["LoadState"],
        "publisher_last_exit_status": unit.get("ExecMainStatus"),
        "publisher_timer": PUBLISHER_TIMER,
        "publisher_timer_active_state": timer["ActiveState"],
        "publisher_timer_last_trigger": timer["LastTriggerUSec"],
        "ingest_timer_last_trigger": ingest.get("LastTriggerUSec"),
        "ingest_last_exit_status": ingest_svc.get("ExecMainStatus"),
        "original_ingest_service_unit_sha256":
            host.get("original_signed_unit_sha256", {}).get(INGEST_SERVICE),
        "original_ingest_timer_unit_sha256":
            host.get("original_signed_unit_sha256", {}).get(INGEST_TIMER),
        "public_writes_performed_by_gate": False,
        "all_missing_days_are_unknown_not_zero": True,
        "other_product_lanes_may_ship": True,
    }


def check_once() -> dict:
    now = datetime.now(timezone.utc)
    source = source_observation()
    host = host_observation()
    upstream = public.get_json(public.SOURCE_URL)
    website = public.get_json(public.WEBSITE_URL)
    diagnostic = public.inspect(upstream, website, now=now)
    diagnostic["canonical_full_matrix_sha256"] = matrix_sha(
        public.matrix(upstream, now=now))
    source["independently_verified_certificate_days"] = (
        independently_verify_certificates(source, now=now))
    source["protected_revocation_state_verified"] = (
        independently_verify_revocation(now=now))
    return judge(source, host, diagnostic, now=now)


def main(argv=None) -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--read-only-production", action="store_true", required=True)
    parsed = args.parse_args(argv)
    try:
        out = check_once()
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error,
            subprocess.SubprocessError) as exc:
        out = {
            "schema": "aoe2war.production-reconciliation.traffic.v1",
            "lane": "TRAFFIC", "status": "FAIL", "severity": "P0",
            "failed_checks": ["EVIDENCE_COLLECTION_ERROR_" + type(exc).__name__],
            "public_writes_performed_by_gate": False,
            "other_product_lanes_may_ship": True,
        }
    print(json.dumps(out, sort_keys=True, separators=(",", ":")))
    return 0 if out["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
