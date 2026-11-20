#!/usr/bin/env python3
"""External revocation readback for the narrow Traffic V2 daily delegation.

This checks a fresh, authenticated HTTPS GET of the CURRENT owner-signed state
on the separately governed GitHub revocation branch, in addition to local
root-owned state. Revoked, mismatched, inaccessible, cached/stale or altered
state halts publication. This source does NOT create the external branch,
configure branch protections, install private keys or claim immutable Github
administration. WE2 must independently qualify the separate trust domain.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import hashlib
import json
from typing import Any, Callable
from urllib.request import Request, build_opener, HTTPRedirectHandler

from scripts import public_audience_v2_day_admission as signature

URL = ("https://api.github.com/repos/Emaren/traffic-api/contents/"
       "ops/traffic-v2-revocation-current.json?ref=traffic-v2-revocation")
PATH = "ops/traffic-v2-revocation-current.json"
MODE = "github-protected-revocation-branch-v1"
MAX_API_BYTES = 20000
MAX_STATE_BYTES = 14000


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("TRAFFIC_V2_EXTERNAL_REVOCATION_REDIRECT_REFUSED")


def hold(message: str) -> None:
    raise ValueError("TRAFFIC_V2_EXTERNAL_REVOCATION_HOLD_" + message)


def strict_json(raw: bytes) -> dict:
    def unique(pairs):
        out = {}
        for name, value in pairs:
            if name in out:
                hold("DUPLICATE_JSON_KEY")
            out[name] = value
        return out
    try:
        obj = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=lambda _: hold("NONFINITE_JSON"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("TRAFFIC_V2_EXTERNAL_REVOCATION_HOLD_INVALID_JSON") from exc
    if type(obj) is not dict:
        hold("NOT_JSON_OBJECT")
    return obj


def verify_github_content(api_json: bytes, response_date: str,
                          *, now: datetime) -> dict:
    """Validate exact live Github contents response and signed state bytes.

    This is not a substitute for independent GitHub branch-protection and
    monotonic revision-policy evidence. It proves a live GET's integrity and
    association with the exact trusted external branch readback endpoint.
    """
    if now.tzinfo is None:
        hold("OBSERVATION_CLOCK_NAIVE")
    now = now.astimezone(timezone.utc)
    try:
        observed = parsedate_to_datetime(response_date).astimezone(timezone.utc)
    except (ValueError, TypeError, IndexError, OverflowError) as exc:
        raise ValueError("TRAFFIC_V2_EXTERNAL_REVOCATION_HOLD_HTTP_DATE_INVALID") from exc
    if abs((now - observed).total_seconds()) > 120:
        hold("REMOTE_HTTP_DATE_STALE_OR_FUTURE")
    if len(api_json) > MAX_API_BYTES:
        hold("GITHUB_RESPONSE_TOO_LARGE")
    obj = strict_json(api_json)
    if (obj.get("type") != "file" or obj.get("path") != PATH or
            obj.get("encoding") != "base64" or
            type(obj.get("size")) is not int or
            not 0 < obj["size"] <= MAX_STATE_BYTES or
            type(obj.get("sha")) is not str or len(obj["sha"]) != 40):
        hold("GITHUB_STATE_PATH_OR_SHAPE_DRIFT")
    raw_b64 = obj.get("content")
    if type(raw_b64) is not str or len(raw_b64) > MAX_STATE_BYTES * 2:
        hold("GITHUB_CONTENT_BASE64_INVALID")
    try:
        raw = base64.b64decode(raw_b64.strip().replace("\n", ""),
                               validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("TRAFFIC_V2_EXTERNAL_REVOCATION_HOLD_BASE64_INVALID") from exc
    if len(raw) != obj["size"]:
        hold("GITHUB_CONTENT_SIZE_DRIFT")
    actual_sha = hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if actual_sha != obj["sha"]:
        hold("GITHUB_BLOB_IDENTITY_DRIFT")
    state = strict_json(raw)
    if set(state) != {"state", "signature"}:
        hold("EXTERNAL_STATE_SIGNATURE_ENVELOPE_DRIFT")
    return state


def current_external_state(*, now: datetime,
                           opener: Callable | None = None) -> dict:
    """Fail closed: no network, stale caching, 404 or redirect => no day."""
    request = Request(URL, method="GET", headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "AoE2WAR-Traffic-V2-Revocation-Readback/1",
        "X-GitHub-Api-Version": "2022-11-28",
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
    })
    if opener is None:
        opener = build_opener(NoRedirect()).open
    try:
        with opener(request, timeout=5) as res:
            code = res.status
            date_header = res.headers.get("Date")
            content_type = res.headers.get("Content-Type", "")
            blob = res.read(MAX_API_BYTES + 1)
        if code != 200 or "json" not in content_type.lower():
            hold("GITHUB_HTTP_STATUS_OR_CONTENT_TYPE")
        return verify_github_content(blob, date_header, now=now)
    except (OSError, TimeoutError) as exc:
        raise ValueError(
            "TRAFFIC_V2_EXTERNAL_REVOCATION_HOLD_UPSTREAM_UNAVAILABLE"
        ) from exc


def compare_root_and_external(local: dict, external: dict) -> None:
    """Critical rollback guard: old signed ACTIVE local cannot beat REVOKED remote."""
    if (type(local) is not dict or type(external) is not dict or
            set(local) != {"state", "signature"} or
            set(external) != {"state", "signature"}):
        hold("LOCAL_OR_EXTERNAL_ENVELOPE_DRIFT")
    if signature.canonical(local) != signature.canonical(external):
        hold("TRUSTED_EXTERNAL_STATE_CONFLICT")
    # The caller then validates Ed25519 signature and ACTIVE status with the
    # existing daily-delegation verifier. An identical bogus envelope fails.
