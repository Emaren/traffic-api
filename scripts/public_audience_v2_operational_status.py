#!/usr/bin/env python3
"""Traffic V2 source-only, read-only public continuation diagnostics.

The current certified 131-day release stays SHA-pinned. Explicit missing UTC
days are UNKNOWN, never zero. Frontend/API parity is checked without touching
their chart appearance. Remote HTTP freshness is NOT ingestion finality.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import argparse
import json
import sys
import urllib.error
import urllib.request

from scripts.public_audience_v2_forward_ledger import RELEASE_SHA
from scripts.public_audience_v2_release_manifest import sha as matrix_sha

FIRST = date(2026, 6, 11)
FROZEN_LAST = date(2026, 10, 19)
MAX_ROWS = 500
SOURCE_URL = ("https://traffic.tokentap.ca/api/projects/"
              "aoe2hdbets/public-audience-series")
WEBSITE_URL = "https://aoe2war.com/api/traffic/public"


def require(condition, reason):
    if not condition:
        raise ValueError("TRAFFIC_V2_HOLD_" + reason)


def utc_date(raw):
    require(type(raw) is str and len(raw) == 10, "DATE_NOT_CANONICAL")
    try:
        value = date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError("TRAFFIC_V2_HOLD_DATE_NOT_CANONICAL") from exc
    require(value.isoformat() == raw, "DATE_NOT_CANONICAL")
    return value


def utc_timestamp(raw):
    require(type(raw) is str and 19 <= len(raw) <= 45,
            "TIMESTAMP_MISSING")
    try:
        value = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError("TRAFFIC_V2_HOLD_TIMESTAMP_MALFORMED") from exc
    require(value.tzinfo is not None, "TIMESTAMP_NO_ZONE")
    return value.astimezone(timezone.utc)


def matrix(payload, *, now):
    require(type(payload) is dict and payload.get("ok") is True,
            "PUBLIC_ENDPOINT_NOT_OK")
    points = payload.get("points")
    require(type(points) is list and 131 <= len(points) <= MAX_ROWS,
            "PUBLIC_POINT_COUNT")
    rows = {}
    previous = None
    for point in points:
        require(type(point) is dict, "PUBLIC_ROW_NOT_OBJECT")
        day = utc_date(point.get("date"))
        require(FIRST <= day < now.date()
                and (previous is None or day > previous),
                "PUBLIC_DATES_NOT_STRICTLY_INCREASING_OR_PARTIAL")
        values = point.get("values")
        require(type(values) is dict, "PUBLIC_VALUES_MISSING")
        counters = [values.get(k) for k in
                    ("totalTraffic", "suspectedHuman", "confirmedHuman")]
        require(all(type(n) is int and n >= 0 for n in counters)
                and counters[0] >= counters[1] >= counters[2],
                "CANONICAL_AUDIENCE_HIERARCHY")
        rows[day.isoformat()] = counters
        previous = day
    history = {k: v for k, v in rows.items() if k <= FROZEN_LAST.isoformat()}
    require(len(history) == 131 and
            sorted(history)[0] == FIRST.isoformat() and
            sorted(history)[-1] == FROZEN_LAST.isoformat() and
            matrix_sha(history) == RELEASE_SHA,
            "HISTORICAL_131_DAY_DIGEST_DRIFT")
    return rows


def inspect(source, website, *, now=None):
    now = now or datetime.now(timezone.utc)
    require(now.tzinfo is not None, "OBSERVATION_CLOCK_NAIVE")
    now = now.astimezone(timezone.utc)
    require(source.get("project_slug") == "aoe2hdbets",
            "CANONICAL_SOURCE_PROJECT_DRIFT")
    generated = utc_timestamp(source.get("generated_at"))
    require(now - timedelta(minutes=10) <= generated <= now + timedelta(minutes=5),
            "SOURCE_API_GENERATION_STALE_OR_FUTURE")
    require(utc_date(source.get("coverage_started_at")) == FIRST,
            "SOURCE_START_CHANGED")
    source_matrix = matrix(source, now=now)
    browser_matrix = matrix(website, now=now)
    require(source_matrix == browser_matrix, "WEBSITE_TRAFFIC_API_PARITY")
    last = max(source_matrix)
    require(source.get("coverage_ended_at") == last,
            "SOURCE_COVERAGE_METADATA_MISMATCH")
    archive_clock = utc_timestamp(source.get("archive_calculated_at"))
    require(archive_clock <= now + timedelta(minutes=5),
            "PUBLIC_ARCHIVE_CLOCK_FUTURE")
    published = {date.fromisoformat(day) for day in source_matrix}
    latest_possible = now.date() - timedelta(days=1)
    gaps = [
        day.isoformat() for index in range(500)
        if (day := FROZEN_LAST + timedelta(days=index+1)) <= latest_possible
        and day not in published
    ]
    require(FROZEN_LAST + timedelta(days=501) > latest_possible,
            "GAP_DIAGNOSTIC_WINDOW_EXCEEDED")
    return {
        "format": "traffic.public-audience.v2.operational-diagnostics.v1",
        "status": ("HOLD_SOURCE_FINALITY_AND_INSERT_RECEIPT_WITNESS"
                   if gaps else "OBSERVED_PUBLIC_DATA_RECENT_NOT_DAY_CERTIFICATE"),
        "project": "aoe2hdbets",
        "original_131_day_digest": RELEASE_SHA,
        "historical_131_days_intact": True,
        "traffic_api_website_parity": True,
        "published_points": len(source_matrix),
        "last_published_utc_day": last,
        "last_certified_utc_day": FROZEN_LAST.isoformat(),
        "new_day_certificates_independently_verified_here": False,
        "target_last_completed_utc_day": latest_possible.isoformat(),
        "uncertified_utc_days": gaps,
        "uncertified_gap_count": len(gaps),
        "first_uncertified_day": gaps[0] if gaps else None,
        "last_uncertified_day": gaps[-1] if gaps else None,
        "public_api_generated_at": generated.isoformat(),
        "archive_calculated_at": archive_clock.isoformat(),
        "last_source_ingestion": None,
        "insertion_receipt_freshness": None,
        "independent_remote_delivery_finality": False,
        "canonical_classifier_parity_finality": False,
        "publisher_health": "NOT_VERIFIED_FROM_ROOT",
        "delay_reason": ("MISSING_VERIFIED_INSERT_RECEIPTS_AND_UPSTREAM_DELIVERY"
                         if gaps else "INDEPENDENT_DAY_CERTIFICATION_NOT_AUDITED"),
        "current_utc_day_excluded": True,
        "missing_days_not_filled_with_zero": True,
        "production_publisher_activated_by_this_check": False,
        "public_writes": False,
        "source_permits_granted": False,
    }


def get_json(url):
    require(url in (SOURCE_URL, WEBSITE_URL), "OUTBOUND_ENDPOINT_NOT_ALLOWLISTED")
    request = urllib.request.Request(
        url, headers={"User-Agent": "Traffic-V2-Source-ReadOnly-Checker/1"}
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        require(response.status == 200, "PUBLIC_HTTP_NON200")
        raw = response.read(1_600_001)
    require(len(raw) <= 1_600_000, "PUBLIC_RESPONSE_TOO_LARGE")
    return json.loads(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read-only-public", action="store_true",
                        help="GET two hardcoded public APIs; no private ingress")
    args = parser.parse_args(argv)
    if not args.read_only_public:
        parser.error("explicit --read-only-public required")
    try:
        result = inspect(get_json(SOURCE_URL), get_json(WEBSITE_URL))
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 2 if result["uncertified_gap_count"] else 0
    except (ValueError, KeyError, TypeError, json.JSONDecodeError,
            OSError, urllib.error.URLError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
