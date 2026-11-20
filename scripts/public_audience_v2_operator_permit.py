#!/usr/bin/env python3
"""Reviewed owner-controlled one-day operator permit verification CONTRACT.

No keys, signed owner permits or root trusted configurations are installed.
WE2 must independently qualify its exact protected unit/site identities and
signer custody before using it. Never infer approval from a local fixture.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from scripts import public_audience_v2_day_admission as day

SCHEMA = "traffic.public-audience.v2.one-day-operator-permit.v1"
FIELDS = frozenset({
    "schema", "project", "day", "certificate_sha256",
    "source_commit_sha", "public_preimage_sha256",
    "source_database_dev", "source_database_ino",
    "ingest_service_loaded_sha256", "traffic_api_source_sha256",
    "website_gap_renderer_sha256", "expires_at_utc",
    "gap_aware_api_and_chart", "approved_by",
})
ENVELOPE = frozenset({"permit", "signature"})


def verify_operator_permit(
    envelope: dict, *, trust_public_key: bytes,
    trusted_public_sha256: str, upstream_key_sha256: str,
    classifier_key_sha256: str, reviewed_source_commit_sha: str,
    database_dev: int, database_ino: int,
    reviewed_ingest_unit_sha256: str,
    reviewed_traffic_api_sha256: str,
    reviewed_website_gap_renderer_sha256: str,
    expected_public_preimage_sha256: str,
    certificate_sha256: str, now: datetime,
) -> dict:
    day.require(type(envelope) is dict and set(envelope) == ENVELOPE,
                "OPERATOR_ENVELOPE_DRIFT")
    permit = envelope["permit"]
    day.require(type(permit) is dict and set(permit) == FIELDS,
                "OPERATOR_PERMIT_FIELD_DRIFT")
    day.require(day.digest(trust_public_key) == trusted_public_sha256
                and len({trusted_public_sha256, upstream_key_sha256,
                         classifier_key_sha256}) == 3,
                "OPERATOR_ROOT_TRUST_NOT_SEPARATELY_PINNED")
    day.require(now.tzinfo is not None,
                "OPERATOR_PERMIT_OBSERVATION_CLOCK_NAIVE")
    now = now.astimezone(timezone.utc)
    expiry = day.utc_stamp(permit["expires_at_utc"])
    day.require(now < expiry <= now + timedelta(minutes=60),
                "OWNER_PERMIT_EXPIRED_OR_TOO_BROAD")
    def sha64(x: Any) -> bool:
        return type(x) is str and day.HEX.fullmatch(x) is not None
    day.require(
        permit["schema"] == SCHEMA
        and permit["project"] == "aoe2hdbets"
        and permit["approved_by"] == "Emaren"
        and type(permit["day"]) is str
        and len(permit["day"]) == 10
        and permit["gap_aware_api_and_chart"] is True
        and type(permit["source_database_dev"]) is int
        and type(permit["source_database_ino"]) is int
        and database_dev >= 0 and database_ino > 0
        and permit["source_database_dev"] == database_dev
        and permit["source_database_ino"] == database_ino
        and permit["certificate_sha256"] == certificate_sha256
        and sha64(certificate_sha256)
        and permit["public_preimage_sha256"]
            == expected_public_preimage_sha256
        and sha64(expected_public_preimage_sha256)
        and type(reviewed_source_commit_sha) is str
        and len(reviewed_source_commit_sha) == 40
        and all(k in "0123456789abcdef"
                for k in reviewed_source_commit_sha)
        and permit["source_commit_sha"] == reviewed_source_commit_sha
        and all(sha64(x) for x in (
            reviewed_ingest_unit_sha256, reviewed_traffic_api_sha256,
            reviewed_website_gap_renderer_sha256))
        and permit["ingest_service_loaded_sha256"]
            == reviewed_ingest_unit_sha256
        and permit["traffic_api_source_sha256"]
            == reviewed_traffic_api_sha256
        and permit["website_gap_renderer_sha256"]
            == reviewed_website_gap_renderer_sha256,
        "OPERATOR_SOURCE_SITE_OR_DB_IDENTITY_DRIFT",
    )
    payload = day.canonical(permit)
    day.verify_openssl_signature(
        payload, day.decode_sig(envelope["signature"]), trust_public_key,
    )
    # A cryptographically valid operator permit is not a full source replay,
    # a day certificate, a successful service install or a live root readback.
    return {
        "status": "INDEPENDENT_OPERATOR_PERMIT_VERIFIED",
        "project": permit["project"],
        "day": permit["day"],
        "certificate_sha256": permit["certificate_sha256"],
        "source_commit_sha": permit["source_commit_sha"],
        "gap_aware_api_and_chart": True,
        "permit_signature_verified": True,
        "permitted_public_preimage_sha256": permit["public_preimage_sha256"],
        "permitted_source_db_device": database_dev,
        "permitted_source_db_inode": database_ino,
        "permit_expires_at_utc": expiry.isoformat(),
        "live_operation_performed": False,
    }
