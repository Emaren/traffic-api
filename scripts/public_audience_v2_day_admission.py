#!/usr/bin/env python3
"""SOURCE-ONLY dual-witness Traffic V2 completed-day admission preflight.

No live keys are enrolled here; no production publisher is exposed. A valid
cryptographic fixture is only a NECESSARY source contract, never live finality.
Remote-delivery and independent canonical-classifier signatures must come from
distinct WE2-admitted authorities with separately pinned public keys.
"""
from __future__ import annotations

import base64
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

from scripts.public_audience_v2_forward_ledger import RELEASE_SHA
from scripts.public_audience_v2_paged_evidence import STATE_FIELDS

SCHEMA = "traffic.public-audience.v2.dual-witness-day.v1"
FIRST_NEW = date(2026, 10, 20)
HEX = re.compile(r"^[0-9a-f]{64}$")
FIELDS = frozenset({
    "schema", "project_slug", "day", "historical_release_sha256",
    "source_epoch_sha256", "host_rules_sha256", "page_state_sha256",
    "source_snapshot_rowid", "forward_prefix_rowid",
    "source_rows", "source_page_chain_sha256",
    "missing_insertion_receipts", "invalid_insertion_clocks",
    "upstream_log_closed_through_utc", "writer_receipts_closed_through_utc",
    "global_ip_model_sha256", "canonical_sessions_sha256",
    "cross_midnight_carry_sha256", "late_arrival_stability_sha256",
    "total", "potential", "confirmed",
})
ENVELOPE_FIELDS = frozenset({"certificate", "upstream_signature", "classifier_signature"})


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError("TRAFFIC_V2_HOLD_" + reason)


def canonical(x: Any) -> bytes:
    return json.dumps(
        x, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def utc_stamp(value: Any) -> datetime:
    require(type(value) is str and 20 <= len(value) <= 40,
            "MALFORMED_UTC_WITNESS_CLOCK")
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("TRAFFIC_V2_HOLD_MALFORMED_UTC_WITNESS_CLOCK") from exc
    require(result.tzinfo is not None
            and result.utcoffset() == timedelta(0),
            "NON_UTC_WITNESS_CLOCK")
    return result.astimezone(timezone.utc)


def check_day_witness(certificate: dict, page: dict, *, now: datetime) -> dict:
    """Validate exact #75 source evidence binding, not a self-signed finality."""
    require(type(certificate) is dict and set(certificate) == FIELDS,
            "CERTIFICATE_FIELD_DRIFT")
    require(type(page) is dict and set(page) == STATE_FIELDS,
            "PAGED_SOURCE_SCHEMA_DRIFT")
    require(now.tzinfo is not None, "OBSERVATION_CLOCK_NAIVE")
    require(certificate["schema"] == SCHEMA
            and certificate["project_slug"] == "aoe2hdbets"
            and certificate["historical_release_sha256"] == RELEASE_SHA,
            "ORIGINAL_131_DAY_RELEASE_DRIFT")
    value = certificate["day"]
    require(type(value) is str and len(value) == 10,
            "INVALID_DAY")
    try:
        target = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("TRAFFIC_V2_HOLD_INVALID_DAY") from exc
    require(target.isoformat() == value and
            FIRST_NEW <= target < now.astimezone(timezone.utc).date(),
            "CURRENT_UNFINISHED_OR_HISTORIC_DAY")
    end = datetime.combine(target + timedelta(days=1),
                           datetime.min.time(), tzinfo=timezone.utc)
    require(page["day"] == value and page["source_prefix_exhausted"] is True
            and type(page["pages"]) is int and page["pages"] > 0,
            "SOURCE_PAGES_INCOMPLETE")
    require(digest(canonical(page)) == certificate["page_state_sha256"],
            "SOURCE_PAGE_PREIMAGE_DRIFT")
    for pfield, cfield in (
        ("source_epoch_sha256", "source_epoch_sha256"),
        ("host_rules_sha256", "host_rules_sha256"),
        ("snapshot_rowid", "source_snapshot_rowid"),
        ("forward_prefix_rowid", "forward_prefix_rowid"),
        ("total_rows", "source_rows"),
        ("missing_receipts", "missing_insertion_receipts"),
        ("invalid_clocks", "invalid_insertion_clocks"),
        ("chain_sha256", "source_page_chain_sha256"),
    ):
        require(type(page[pfield]) is type(certificate[cfield])
                and page[pfield] == certificate[cfield],
                "SOURCE_PAGE_COUNTER_OR_IDENTITY_DRIFT")
    require(page["snapshot_rowid"] == page["forward_prefix_rowid"]
            and type(page["snapshot_rowid"]) is int
            and page["snapshot_rowid"] > 0,
            "UNSETTLED_FORWARD_PREFIX")
    require(type(page["total_rows"]) is int and page["total_rows"] > 0
            and page["missing_receipts"] == 0
            and page["invalid_clocks"] == 0,
            "INSERT_RECEIPTS_INCOMPLETE")
    for field in (
        "source_epoch_sha256", "host_rules_sha256", "source_page_chain_sha256",
        "page_state_sha256", "global_ip_model_sha256",
        "canonical_sessions_sha256", "cross_midnight_carry_sha256",
        "late_arrival_stability_sha256",
    ):
        require(type(certificate[field]) is str and HEX.fullmatch(
            certificate[field]) is not None, "MISSING_MODEL_OR_SOURCE_DIGEST")
    for field in ("total", "potential", "confirmed"):
        require(type(certificate[field]) is int and certificate[field] >= 0,
                "INVALID_AUDIENCE_COUNTER")
    require(certificate["total"] > 0
            and certificate["total"] >= certificate["potential"]
            >= certificate["confirmed"], "NONCANONICAL_AUDIENCE_HIERARCHY")
    # Source receipt watermark alone cannot prove a remote stream completed.
    # Require both independently SIGNED closure claims to cover the full UTC
    # day, including the strict 30-minute canonical session expiry margin.
    margin = end + timedelta(minutes=31)
    require(utc_stamp(certificate["upstream_log_closed_through_utc"]) >= margin,
            "REMOTE_LOG_DELIVERY_NOT_CLOSED")
    require(utc_stamp(certificate["writer_receipts_closed_through_utc"]) >= margin,
            "INSERT_WRITER_NOT_CLOSED")
    return {"day": value, "end_utc": end.isoformat(),
            "page_sha256": certificate["page_state_sha256"],
            "candidate_values": [certificate["total"], certificate["potential"],
                                 certificate["confirmed"]]}


def decode_sig(raw: Any) -> bytes:
    require(type(raw) is str and len(raw) == 86
            and re.fullmatch(r"[A-Za-z0-9_-]{86}", raw) is not None,
            "MISSING_ED25519_SIGNATURE")
    try:
        signature = base64.urlsafe_b64decode(raw + "==")
    except ValueError as exc:
        raise ValueError("TRAFFIC_V2_HOLD_SIGNATURE_ENCODING") from exc
    require(len(signature) == 64, "MALFORMED_ED25519_SIGNATURE")
    return signature


def verify_openssl_signature(payload: bytes, signature: bytes, public_key: bytes,
                             *, openssl: str = "openssl") -> None:
    """Exact Ed25519 detached proof. Uses only temporary 0600 aggregate files.

    The role public keys and their expected fingerprints are furnished by a
    separately reviewed, protected operator configuration, never by envelope.
    """
    require(len(payload) <= 4096 and len(public_key) <= 2000,
            "SIGNED_AGGREGATE_BOUNDS")
    with tempfile.TemporaryDirectory(prefix="traffic-v2-dual-witness-") as temp:
        paths = [Path(temp) / name for name in ("payload", "sig", "key.pem")]
        for path, data in zip(paths, (payload, signature, public_key)):
            with path.open("xb", buffering=0) as out:
                out.write(data)
            path.chmod(0o600)
        try:
            result = subprocess.run(
                [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(paths[2]),
                 "-rawin", "-in", str(paths[0]), "-sigfile", str(paths[1])],
                timeout=4, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("TRAFFIC_V2_HOLD_SIGNATURE_VERIFIER_UNAVAILABLE") from exc
        require(result.returncode == 0, "INDEPENDENT_SIGNATURE_REFUSED")


def verify_dual_witness(envelope: dict, page: dict, *, now: datetime,
                        upstream_key: bytes, classifier_key: bytes,
                        expected_upstream_key_sha256: str,
                        expected_classifier_key_sha256: str,
                        openssl: str = "openssl") -> dict:
    require(type(envelope) is dict and set(envelope) == ENVELOPE_FIELDS,
            "ENVELOPE_FIELD_DRIFT")
    require(all(HEX.fullmatch(x or "") is not None for x in (
        expected_upstream_key_sha256, expected_classifier_key_sha256)),
        "UNPINNED_TRUST_IDENTITY")
    require(expected_upstream_key_sha256 != expected_classifier_key_sha256
            and digest(upstream_key) == expected_upstream_key_sha256
            and digest(classifier_key) == expected_classifier_key_sha256,
            "CROSS_ROLE_OR_FORGED_KEY")
    summary = check_day_witness(envelope["certificate"], page, now=now)
    body = canonical(envelope["certificate"])
    verify_openssl_signature(body, decode_sig(envelope["upstream_signature"]),
                             upstream_key, openssl=openssl)
    verify_openssl_signature(body, decode_sig(envelope["classifier_signature"]),
                             classifier_key, openssl=openssl)
    return {
        "format": "traffic.v2.dual-witness-source-contract.v1",
        "day": summary["day"],
        "source_page_digest": summary["page_sha256"],
        "dual_witness_signatures_verified": True,
        "candidate_values": summary["candidate_values"],
        "certificate_digest_sha256": digest(body),
        # No real production keys have been independently admitted. The
        # caller cannot turn a source test into a root/deploy permit.
        "production_root_permit_present": False,
        "public_write_authorized": False,
        "day_physical_production_certified": False,
        "status": "HOLD_INDEPENDENT_PRODUCTION_ADMISSION",
    }


def consecutive_candidates(first: dict, second: dict) -> dict:
    require(all(type(x) is dict
                and x.get("dual_witness_signatures_verified") is True
                and x.get("public_write_authorized") is False
                for x in (first, second)), "UNVERIFIED_CANDIDATE_PAIR")
    a, b = date.fromisoformat(first["day"]), date.fromisoformat(second["day"])
    require(b == a + timedelta(days=1), "DAYS_NOT_CONSECUTIVE")
    require(first["certificate_digest_sha256"] !=
            second["certificate_digest_sha256"], "REPLAYED_CERTIFICATE")
    return {"two_source_contract_days": [first["day"], second["day"]],
            "two_physical_production_days_certified": False,
            "public_write_authorized": False,
            "status": "HOLD_INDEPENDENT_PRODUCTION_ADMISSION"}
