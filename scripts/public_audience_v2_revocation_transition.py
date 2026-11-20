#!/usr/bin/env python3
"""External revocation branch transition-policy source for independent CI.

Must be a REQUIRED check on a protected independent external branch; not a
replacement for branch protection, admin-bypass prevention or real owner keys.
"""
from __future__ import annotations

from scripts import public_audience_v2_daily_delegation as scope
from scripts import public_audience_v2_day_admission as crypto


def transition(previous: dict, proposed: dict, *,
               owner_public_key: bytes, trusted_owner_sha256: str) -> dict:
    """Permit ONLY authentic, increasing ACTIVE -> irreversible REVOKED.

    To renew or change trust, owner creates a NEW delegation ID/branch after
    distinct installation acceptance. Neither a signed older ACTIVE state nor
    an ACTIVE reactivation is a valid commit to this protected state branch.
    """
    old, _ = scope.signed(
        previous, value_key="state", expected_fields=scope.STATE_FIELDS,
        public_key=owner_public_key, public_sha256=trusted_owner_sha256)
    new, _ = scope.signed(
        proposed, value_key="state", expected_fields=scope.STATE_FIELDS,
        public_key=owner_public_key, public_sha256=trusted_owner_sha256)
    scope.require(old["schema"] == new["schema"] == scope.STATE_SCHEMA,
                  "REVOCATION_TRANSITION_SCHEMA")
    scope.require(old["delegation_sha256"] == new["delegation_sha256"]
                  and old["delegation_id"] == new["delegation_id"],
                  "REVOCATION_TRANSITION_FOREIGN_DELEGATION")
    scope.require(type(old["revision"]) is int
                  and type(new["revision"]) is int
                  and new["revision"] == old["revision"] + 1
                  and old["revision"] > 0,
                  "REVOCATION_TRANSITION_REVISION_NOT_MONOTONIC")
    scope.require(old["status"] == "ACTIVE"
                  and new["status"] == "REVOKED",
                  "REVOCATION_TRANSITION_TERMINAL_ONLY")
    previous_at = crypto.utc_stamp(old["effective_at_utc"])
    next_at = crypto.utc_stamp(new["effective_at_utc"])
    scope.require(previous_at < next_at,
                  "REVOCATION_TRANSITION_CLOCK_NOT_MONOTONIC")
    return {
        "status":"SIGNED_TERMINAL_REVOCATION_TRANSITION_ACCEPTABLE",
        "delegation_id":new["delegation_id"],
        "new_revision":new["revision"],
        "new_state_sha256":crypto.digest(crypto.canonical(proposed)),
        "branch_ruleset_and_external_trust_physically_admitted":False,
    }
