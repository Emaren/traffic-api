#!/usr/bin/env python3
"""Exact-project canonical public Traffic archive freshness, read-only gate.

This does NOT certify audience sessions, log-delivery finality, late-ingest
bounds, historical parity or permission to publish. It prevents the healthy
API/ingest timers from concealing an old frozen canonical archive.

No SQLite writes or scans, service restarts, timers, financial routes, shell,
secrets, IP/UA/path rows or arbitrary network endpoints.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import json
import subprocess
import sys
import urllib.error
import urllib.request

PROJECT = "aoe2hdbets"
PUBLIC_LOOPBACK_URL = "http://127.0.0.1:3345/api/projects/aoe2hdbets/public-audience-series"
LEGACY_TIMER = "traffic-public-audience-aoe2hdbets.timer"
MAX_RESPONSE_BYTES = 2_000_000
MAX_POINTS = 5000
MAX_ARCHIVE_AGE_DAYS = 2


class Hold(ValueError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise Hold(reason)


def utc_day(raw: object) -> date:
    need(isinstance(raw, str) and len(raw) == 10 and
         raw[4] == "-" and raw[7] == "-", "INVALID_PUBLISHED_UTC_DAY")
    try:
        parsed = date.fromisoformat(raw)
    except ValueError as exc:
        raise Hold("INVALID_PUBLISHED_UTC_DAY") from exc
    need(parsed.isoformat() == raw, "NONCANONICAL_UTC_DAY")
    return parsed


def utc_time(raw: object) -> datetime:
    need(isinstance(raw, str) and 12 <= len(raw) <= 45,
         "INVALID_PUBLISHED_TIMESTAMP")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise Hold("INVALID_PUBLISHED_TIMESTAMP") from exc
    need(parsed.tzinfo is not None and parsed.utcoffset() is not None,
         "PUBLISHED_TIMESTAMP_WITHOUT_OFFSET")
    return parsed.astimezone(timezone.utc)


def count(raw: object) -> int:
    need(type(raw) is int and 0 <= raw <= 2**53 - 1,
         "INVALID_CANONICAL_AUDIENCE_COUNT")
    return raw


def inspect_payload(payload: object, now_utc: datetime) -> dict:
    need(now_utc.tzinfo is not None and now_utc.utcoffset() is not None,
         "OBSERVATION_CLOCK_NOT_AWARE")
    now_utc = now_utc.astimezone(timezone.utc)
    need(isinstance(payload, dict) and
         payload.get("ok") is True and payload.get("project_slug") == PROJECT,
         "UNTRUSTED_CANONICAL_PROJECT_SOURCE")
    points = payload.get("points")
    need(isinstance(points, list) and len(points) <= MAX_POINTS,
         "INVALID_CANONICAL_ARCHIVE_SIZE")
    need(points, "HOLD_CANONICAL_ARCHIVE_UNPUBLISHED")
    generated = utc_time(payload.get("generated_at"))
    need(generated <= now_utc + timedelta(minutes=5) and
         generated >= now_utc - timedelta(minutes=5),
         "CANONICAL_SOURCE_GENERATION_CLOCK_UNTRUSTED")
    published = utc_time(payload.get("archive_calculated_at"))
    need(published <= now_utc + timedelta(minutes=5),
         "PUBLISHED_TIMESTAMP_IN_FUTURE")
    first = utc_day(payload.get("coverage_started_at"))
    last = utc_day(payload.get("coverage_ended_at"))
    need(last < now_utc.date(), "PARTIAL_CURRENT_OR_FUTURE_UTC_DAY")
    prior = None
    for item in points:
        need(isinstance(item, dict), "CANONICAL_ARCHIVE_ROW_MALFORMED")
        day = utc_day(item.get("date"))
        need(day < now_utc.date(), "PARTIAL_CURRENT_OR_FUTURE_UTC_DAY")
        need(prior is None or day == prior + timedelta(days=1),
             "MISSING_DUPLICATED_OR_REORDERED_CANONICAL_DAYS")
        vals = item.get("values")
        need(isinstance(vals, dict), "MISSING_CANONICAL_COUNT_HIERARCHY")
        total = count(vals.get("totalTraffic"))
        suspected = count(vals.get("suspectedHuman"))
        confirmed = count(vals.get("confirmedHuman"))
        need(total >= suspected >= confirmed,
             "CANONICAL_HIERARCHY_VIOLATION")
        row_published = utc_time(item.get("calculatedAt"))
        need(row_published >= datetime.combine(day + timedelta(days=1),
                                                datetime.min.time(), timezone.utc) and
             row_published <= published and row_published <= now_utc + timedelta(minutes=5),
             "UNCERTIFIED_OR_FUTURE_DAY_TIMESTAMP")
        prior = day
    need(utc_day(points[0]["date"]) == first and prior == last,
         "CANONICAL_COVERAGE_METADATA_CONTRADICTS_ROWS")
    age = (now_utc.date() - last).days
    need(age >= 1, "PARTIAL_CURRENT_OR_FUTURE_UTC_DAY")
    stale = age > MAX_ARCHIVE_AGE_DAYS
    return {
        "schema": "traffic.public-audience.canonical-age-observer.v1",
        "status": "HOLD_CANONICAL_ARCHIVE_STALE" if stale
                  else "OBSERVED_CANONICAL_ARCHIVE_AGE_WITHIN_LIMIT",
        "project_slug": PROJECT,
        "last_published_utc_day": last.isoformat(),
        "archive_calculated_at": published.isoformat(),
        "reported_days": len(points),
        "age_utc_days": age,
        "maximum_allowed_age_utc_days": MAX_ARCHIVE_AGE_DAYS,
        "canonical_source_http_responding": True,
        "archive_is_stale": stale,
        "historical_classification_certified_by_this_observer": False,
        "remote_log_delivery_finality_proven": False,
        "late_ingestion_bound_proven": False,
        "daily_publisher_ready": False,
        "publication_authorized": False,
        "financial_authorized": False,
        "read_only": True,
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_payload() -> dict:
    request = urllib.request.Request(
        PUBLIC_LOOPBACK_URL, method="GET",
        headers={"Accept": "application/json",
                 "User-Agent": "traffic-canonical-age-observer/1"},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect
    )
    try:
        with opener.open(request, timeout=7) as response:
            need(response.status == 200 and response.url == PUBLIC_LOOPBACK_URL,
                 "LOCAL_TRAFFIC_CANONICAL_API_NOT_HTTP200")
            need(response.headers.get_content_type() == "application/json",
                 "LOCAL_TRAFFIC_CANONICAL_API_NOT_JSON")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            need(0 < len(raw) <= MAX_RESPONSE_BYTES,
                 "CANONICAL_API_BODY_OUT_OF_BOUND")
            data = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, OSError,
            ValueError) as exc:
        raise Hold("CANONICAL_API_REQUEST_OR_JSON_FAILED:" + type(exc).__name__) from exc
    need(isinstance(data, dict), "CANONICAL_API_RESPONSE_NOT_OBJECT")
    return data


def legacy_timer_status() -> dict:
    result = subprocess.check_output(
        ["/usr/bin/systemctl", "show", LEGACY_TIMER,
         "-p", "LoadState", "-p", "ActiveState", "-p", "UnitFileState",
         "--no-pager"],
        timeout=7, text=True,
    )
    fields = dict(line.split("=", 1) for line in result.splitlines() if "=" in line)
    need(fields.get("LoadState") == "loaded" and
         fields.get("ActiveState") == "inactive" and
         fields.get("UnitFileState") == "disabled",
         "LEGACY_FULL_HISTORY_FORGE_TIMER_NOT_HELD")
    return {"legacy_full_history_forge_timer": "INACTIVE_DISABLED_INTENTIONAL_HOLD"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("selftest", "observe"), required=True)
    opts = parser.parse_args()
    if opts.phase == "selftest":
        need(MAX_ARCHIVE_AGE_DAYS == 2 and MAX_POINTS == 5000 and
             PUBLIC_LOOPBACK_URL.startswith("http://127.0.0.1:3345/") and
             PROJECT == "aoe2hdbets",
             "CANONICAL_AGE_OBSERVER_STATIC_CONTRACT_CHANGED")
        print("PASS_CANONICAL_TRAFFIC_AGE_OBSERVER_STATIC_NO_PUBLICATION")
        return
    observed = inspect_payload(fetch_payload(), datetime.now(timezone.utc))
    observed.update(legacy_timer_status())
    print(json.dumps(observed, sort_keys=True))
    if observed["archive_is_stale"]:
        raise SystemExit(3)


if __name__ == "__main__":
    try:
        main()
    except (Hold, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({
            "schema": "traffic.public-audience.canonical-age-observer.v1",
            "status": "HOLD_CANONICAL_AGE_AUDIT",
            "reason": str(exc)[:150], "publication_authorized": False,
            "financial_authorized": False, "read_only": True,
        }, sort_keys=True))
        sys.exit(3)
