"""REVIEW ONLY: finite UTC-day observations, not operational session closure.

No database, network, signing or publication entry point. Inputs must be
normalized by the pinned source and independently reconciled before real use.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import json
from typing import Any, Iterable

from app.services.traffic.sessions import build_ip_behavior_map
from scripts import rebuild_public_audience_archive as canonical

SCHEMA = "traffic.public-audience.v3.daily-observation.review.v1"
GAP = timedelta(minutes=30)
DELIVERY_MARGIN = timedelta(minutes=31)
MAX_EVENTS = 250_000


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def stamp(value: Any) -> datetime:
    require(isinstance(value, datetime) and value.tzinfo is not None
            and value.utcoffset() == timedelta(0), "UTC_REQUIRED")
    return value


def actor(event: dict) -> tuple[str, str, str]:
    return event["host"], event["ip"], (event["ua"] or "").lower()


def event_body(event: dict) -> dict:
    # Full normalized input identity, not just IDs or counters.
    body = dict(event)
    body["timestamp"] = stamp(body["timestamp"]).isoformat()
    return body


def observe(day: date, events: Iterable[dict], *, source_prefix: int,
            source_evidence_sha256: str, classifier_dependencies_sha256: str,
            upstream_closed_through: datetime, writer_closed_through: datetime) -> dict:
    """Pure review calculation, assuming an externally verified input cohort.

    The dates/digests are bindings, NOT verification of an independent witness.
    A zero result is an observed zero, never permission to publish.
    """
    require(type(day) is date and type(source_prefix) is int and source_prefix >= 0,
            "BAD_SCOPE")
    for value in (source_evidence_sha256, classifier_dependencies_sha256):
        require(isinstance(value, str) and len(value) == 64
                and all(ch in "0123456789abcdef" for ch in value), "BAD_DIGEST")
    start = datetime.combine(day, time.min, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    require(stamp(upstream_closed_through) >= end + DELIVERY_MARGIN
            and stamp(writer_closed_through) >= end + DELIVERY_MARGIN,
            "DELIVERY_NOT_CLOSED")
    selected = []
    seen = set()
    rowids = set()
    for event in events:
        t = stamp(event["timestamp"])
        rid = event["source_rowid"]
        require(type(rid) is int and 0 < rid <= source_prefix, "PREFIX_DRIFT")
        require(start - GAP <= t < end, "EVENT_OUTSIDE_OBSERVATION")
        require(event["timestamp_iso"] == t.isoformat(), "TIMESTAMP_DRIFT")
        require(event["event_id"] and event["event_id"] not in seen
                and rid not in rowids, "DUPLICATE_EVENT")
        require(len(selected) < MAX_EVENTS, "REVIEW_EVENT_CAP")
        seen.add(event["event_id"])
        rowids.add(rid)
        selected.append(dict(event))
    selected.sort(key=lambda x: (x["timestamp"], x["line_offset"], x["source_rowid"]))
    # Day-only model: no preceding-day or following-day evidence affects its score.
    today = [e for e in selected if e["timestamp"] >= start]
    model = build_ip_behavior_map(today)
    model_body = [[host, ip, dict(stats)] for (host, ip), stats in sorted(model.items())]
    last = {}
    chains = {}
    slices = []
    carries = []
    for event in selected:
        key = actor(event)
        t = event["timestamp"]
        if t < start:
            last[key] = t
            continue
        prev = last.get(key)
        if key not in chains or t - prev > GAP:
            if key in chains:
                slices.append(chains[key])
            chains[key] = []
            if prev is not None and prev < start and t - prev <= GAP:
                carries.append(event["event_id"])
        chains[key].append(event)
        last[key] = t
    slices.extend(chains.values())
    buckets = defaultdict(list)
    for chain in slices:
        first = chain[0]
        # Fixed clock prevents retry time from changing activity-dependent scoring.
        session = canonical.build_single_session(chain, now=end,
            ip_behavior=model.get((first["host"], first["ip"]), {}))
        require(session["first_seen_at"][:10] == day.isoformat(), "ATTRIBUTION_DRIFT")
        buckets[canonical.bucket_id(first["timestamp"])].append(session)
    daily = {}
    for key in sorted(buckets):
        canonical.finalize_bucket(buckets[key], daily)
    totals = daily.get(day.isoformat(), [0, 0, 0])
    require(totals[0] >= totals[1] >= totals[2] >= 0, "HIERARCHY_DRIFT")
    body = {
        "schema": SCHEMA, "day": day.isoformat(),
        "observation_end_exclusive_utc": end.isoformat(),
        "delivery_floor_utc": (end + DELIVERY_MARGIN).isoformat(),
        "source_prefix_rowid": source_prefix,
        "source_evidence_sha256": source_evidence_sha256,
        "classifier_dependencies_sha256": classifier_dependencies_sha256,
        "normalized_input_sha256": digest([event_body(e) for e in selected]),
        "daily_model_sha256": digest(model_body),
        "carry_sha256": digest(sorted(carries)),
        "slice_count": len(slices), "carry_in_slices": len(carries),
        "accepted_day_events": len(today), "metrics": totals,
        "upstream_closed_through_utc": upstream_closed_through.isoformat(),
        "writer_closed_through_utc": writer_closed_through.isoformat(),
    }
    return {"observation": body, "observation_sha256": digest(body),
            "publication_authorized": False, "live_finality_certified": False}


def late_disposition(*, sealed_day: date, sealed_prefix: int, event: dict) -> str:
    """No mutation: caller retains source and routes late delivery to incident review."""
    end = datetime.combine(sealed_day + timedelta(days=1), time.min, tzinfo=timezone.utc)
    t = stamp(event["timestamp"])
    require(type(event["source_rowid"]) is int and event["source_rowid"] > sealed_prefix,
            "NOT_NEW_SOURCE_ROW")
    return "LATE_SEALED_INPUT_INCIDENT" if t < end else "FUTURE_DAY_INPUT"
