#!/usr/bin/env python3
"""Separately owner-signed, revocable, narrow DAILY Traffic publication delegation.

This authorizes only a short-lived prospective nonfinancial publication lane;
it DOES NOT sign upstream source evidence, canonical classifier output, source
corrections, historical backfills, root service changes, new keys or funding.
The separately signed root-controlled state must be ACTIVE at each attempted
day. WE2 remains trusted root; replay of older state against a compromised
root requires an external monotonic anchor and is not solved by this module.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from scripts import public_audience_v2_day_admission as crypto
from scripts.public_audience_v2_forward_ledger import RELEASE_SHA

SCHEMA = "traffic.public-audience.v2.daily-delegation.v1"
STATE_SCHEMA = "traffic.public-audience.v2.delegation-revocation-state.v1"
DELEGATION_FIELDS = frozenset({
    "schema", "delegation_id", "project", "approved_by",
    "issued_at_utc", "expires_at_utc", "earliest_utc_day", "latest_utc_day",
    "max_completed_day_age_days", "max_days_per_run",
    "source_commit_sha", "source_database_dev", "source_database_ino",
    "ingest_service_loaded_sha256", "traffic_api_source_sha256",
    "website_gap_renderer_sha256", "upstream_key_sha256",
    "classifier_key_sha256", "historical_release_sha256",
    "gap_aware_api_and_chart", "no_historical_corrections",
})
STATE_FIELDS = frozenset({
    "schema", "delegation_sha256", "delegation_id", "status",
    "revision", "effective_at_utc",
})


def require(ok: bool, reason: str) -> None:
    crypto.require(ok, "DAILY_DELEGATION_" + reason)


def canonical_date(value: Any) -> date:
    require(type(value) is str and len(value) == 10, "DAY_MALFORMED")
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("TRAFFIC_V2_HOLD_DAILY_DELEGATION_DAY_MALFORMED") from exc
    require(value == parsed.isoformat(), "DAY_MALFORMED")
    return parsed


def signed(envelope: dict, *, value_key: str, expected_fields: frozenset,
           public_key: bytes, public_sha256: str) -> tuple[dict, str]:
    require(type(envelope) is dict and set(envelope) == {value_key,"signature"},
            "ENVELOPE_DRIFT")
    body = envelope[value_key]
    require(type(body) is dict and set(body) == expected_fields,
            "FIELD_DRIFT")
    require(type(public_sha256) is str and
            crypto.digest(public_key) == public_sha256,
            "OWNER_KEY_IDENTITY_DRIFT")
    payload = crypto.canonical(body)
    crypto.verify_openssl_signature(
        payload, crypto.decode_sig(envelope["signature"]), public_key)
    return body, crypto.digest(payload)


def verify_daily_delegation(
    delegation_envelope: dict, state_envelope: dict, *,
    trust_public_key: bytes, trusted_public_sha256: str,
    expected_upstream_key_sha256: str, expected_classifier_key_sha256: str,
    reviewed_source_commit_sha: str, source_database_dev: int,
    source_database_ino: int, reviewed_ingest_unit_sha256: str,
    reviewed_traffic_api_sha256: str,
    reviewed_website_gap_renderer_sha256: str, expected_max_days_per_run: int,
    day: str, certificate_sha256: str, public_preimage_sha256: str,
    now: datetime,
) -> dict:
    """Verify signed prospective owner delegation + separate signed revocation.

    A successful return is ONLY the operator approval layer. The upstream
    logger and independent classifier MUST each sign the exact completed day.
    Caller verifies actual source/DB/service/website postimage and source page,
    then passes this scope into the EXISTING atomic day publication core.
    """
    require(now.tzinfo is not None, "OBSERVATION_CLOCK_NAIVE")
    now = now.astimezone(timezone.utc)
    owner, delegation_sha = signed(
        delegation_envelope, value_key="delegation",
        expected_fields=DELEGATION_FIELDS,
        public_key=trust_public_key, public_sha256=trusted_public_sha256)
    revocation, _ = signed(
        state_envelope, value_key="state", expected_fields=STATE_FIELDS,
        public_key=trust_public_key, public_sha256=trusted_public_sha256)
    require(len({trusted_public_sha256, expected_upstream_key_sha256,
                 expected_classifier_key_sha256}) == 3,
            "CROSS_ROLE_KEY_REUSE")
    require(type(owner["delegation_id"]) is str and
            len(owner["delegation_id"]) == 64 and
            crypto.HEX.fullmatch(owner["delegation_id"]) is not None,
            "DELEGATION_ID_MALFORMED")
    require(revocation["schema"] == STATE_SCHEMA and
            revocation["delegation_sha256"] == delegation_sha and
            revocation["delegation_id"] == owner["delegation_id"] and
            type(revocation["revision"]) is int and
            revocation["revision"] > 0,
            "REVOCATION_STATUS_NOT_BOUND")
    require(revocation["status"] == "ACTIVE", "DELEGATION_REVOKED")
    effective = crypto.utc_stamp(revocation["effective_at_utc"])
    issued = crypto.utc_stamp(owner["issued_at_utc"])
    expiry = crypto.utc_stamp(owner["expires_at_utc"])
    require(effective <= now and issued <= now < expiry and
            expiry <= issued + timedelta(days=35),
            "EXPIRED_NOT_YET_ISSUED_OR_TOO_LONG")
    lower = canonical_date(owner["earliest_utc_day"])
    upper = canonical_date(owner["latest_utc_day"])
    target = canonical_date(day)
    require(lower <= target <= upper and
            upper <= expiry.date() and lower >= issued.date()-timedelta(days=1)
            and target < now.date(),
            "DAY_SUBSTITUTION_OR_HISTORICAL_BACKFILL")
    require(type(owner["max_completed_day_age_days"]) is int
            and 1 <= owner["max_completed_day_age_days"] <= 3
            and (now.date()-target).days <= owner["max_completed_day_age_days"],
            "LATE_DAY_NEEDS_SEPARATE_OWNER_APPROVAL")
    require(type(expected_max_days_per_run) is int
            and type(owner["max_days_per_run"]) is int
            and 1 <= owner["max_days_per_run"] <= expected_max_days_per_run <= 7,
            "EXCESSIVE_CATCHUP_SCOPE")
    hashes = (
        reviewed_ingest_unit_sha256, reviewed_traffic_api_sha256,
        reviewed_website_gap_renderer_sha256,
        expected_upstream_key_sha256, expected_classifier_key_sha256,
        public_preimage_sha256, certificate_sha256,
    )
    require(all(type(v) is str and crypto.HEX.fullmatch(v) is not None
                for v in hashes), "UNPINNED_SOURCE_OR_DAY_SHA")
    require(type(reviewed_source_commit_sha) is str and
            len(reviewed_source_commit_sha) == 40 and
            all(c in "0123456789abcdef" for c in reviewed_source_commit_sha),
            "INVALID_REVIEWED_SOURCE_COMMIT")
    require(owner["schema"] == SCHEMA and
            owner["project"] == "aoe2hdbets" and
            owner["approved_by"] == "Emaren" and
            owner["historical_release_sha256"] == RELEASE_SHA and
            owner["source_commit_sha"] == reviewed_source_commit_sha and
            owner["source_database_dev"] == source_database_dev and
            owner["source_database_ino"] == source_database_ino and
            type(source_database_dev) is int and source_database_dev >= 0 and
            type(source_database_ino) is int and source_database_ino > 0 and
            owner["ingest_service_loaded_sha256"] ==
                reviewed_ingest_unit_sha256 and
            owner["traffic_api_source_sha256"] ==
                reviewed_traffic_api_sha256 and
            owner["website_gap_renderer_sha256"] ==
                reviewed_website_gap_renderer_sha256 and
            owner["upstream_key_sha256"] == expected_upstream_key_sha256 and
            owner["classifier_key_sha256"] == expected_classifier_key_sha256 and
            owner["gap_aware_api_and_chart"] is True and
            owner["no_historical_corrections"] is True,
            "SIGNED_SOURCE_SCOPE_DRIFT")
    return {
        # Compatible ONLY with the existing atomic append contract after
        # verification by this source function. NEVER a standalone certificate.
        "status": "INDEPENDENT_DAILY_DELEGATION_VERIFIED",
        "authorization_method": "owner_revocable_daily_delegation_v1",
        "delegation_sha256": delegation_sha,
        "revocation_state_revision": revocation["revision"],
        "project": owner["project"], "day": day,
        "certificate_sha256": certificate_sha256,
        "source_commit_sha": reviewed_source_commit_sha,
        "gap_aware_api_and_chart": True,
        "permit_signature_verified": True,
        "permitted_public_preimage_sha256": public_preimage_sha256,
        "permitted_source_db_device": source_database_dev,
        "permitted_source_db_inode": source_database_ino,
        "permit_expires_at_utc": expiry.isoformat(),
        "live_operation_performed": False,
        "source_delivery_and_classifier_certified": False,
    }
