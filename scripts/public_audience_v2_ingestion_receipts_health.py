#!/usr/bin/env python3
"""Bounded, read-only audit of actual SQLite INSERT-time receipts.

Never certifies remote Nginx delivery, mutable global-IP classifications,
cross-midnight sessions or publication. Historic NULL values stay UNKNOWN.
No IP, UA, path, identity, individual timestamp or raw row leaves this CLI.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import sys

MAX_SAMPLE = 10_000
CANONICAL_CUTOFF = "2026-10-19"


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def utc_datetime(raw: str, *, clock: bool = False) -> datetime:
    require(isinstance(raw, str) and 10 < len(raw) <= 40,
            "malformed stored event/ingest timestamp")
    result = datetime.fromisoformat(raw)
    require(result.tzinfo is not None,
            "event/ingest timestamp lacks UTC offset")
    offset = result.utcoffset()
    require(offset == timedelta(0) if clock else offset is not None,
            "non-UTC ingestion clock")
    return result.astimezone(timezone.utc)


def sample_health(rows: list[tuple[int, str, str | None]], *,
                  now_utc: datetime, receipts_column: bool,
                  last_certified_day: str = CANONICAL_CUTOFF) -> dict:
    require(now_utc.tzinfo is not None, "naive audit observation clock")
    now_utc = now_utc.astimezone(timezone.utc)
    require(0 <= len(rows) <= MAX_SAMPLE, "sample exceeds bounded row ceiling")
    require(last_certified_day == CANONICAL_CUTOFF,
            "unexpected published audience boundary")

    measured_ms: list[int] = []
    measured_after_canonical = 0
    negative_delay = 0
    event_after_insert = 0
    future_ingestion_clock = 0
    insertion_clock_order_reversals = 0
    # In descending ROWID order, newer INSERT receipts must not precede
    # older INSERT receipts. Equality is normal for batch inserts that share
    # SQLite's per-step millisecond clock. A reversal is not publication proof.
    previous_receipted_ingestion_utc: datetime | None = None
    previous_rowid: int | None = None
    newest_receipted_rowid: int | None = None
    null_newer_than_receipt = 0
    # Historic NULLs are allowed only as a *contiguous old prefix*.
    # Descending rowids: receipt -> NULL -> receipt demonstrates a hole
    # inside the observed writer era, not harmless pre-migration history.
    pending_older_nulls = 0
    interior_receipt_gaps = 0
    uninstrumented = 0

    for rowid, event_time, ingest_time in rows:
        require(type(rowid) is int and rowid > 0 and
                (previous_rowid is None or rowid < previous_rowid),
                "sample rowids not strictly descending")
        previous_rowid = rowid
        event = utc_datetime(event_time)
        require(event <= now_utc + timedelta(minutes=5),
                "source event timestamp implausibly future-dated")
        if ingest_time is None:
            uninstrumented += 1
            if newest_receipted_rowid is not None:
                # Tentatively permit the boundary between new instrumented
                # rows and legacy rows. A still-older stamped row disproves
                # that interpretation; count the entire intervening hole.
                pending_older_nulls += 1
            continue
        require(receipts_column, "receipt data without schema")
        if newest_receipted_rowid is not None and pending_older_nulls:
            interior_receipt_gaps += pending_older_nulls
            pending_older_nulls = 0
        ingested = utc_datetime(ingest_time, clock=True)
        if (previous_receipted_ingestion_utc is not None and
                ingested > previous_receipted_ingestion_utc):
            # The older ROWID claims a *later* insertion clock than a newer
            # row. This may indicate clock rollback, clock substitution or
            # corrupted provenance; never silently certify that sequence.
            insertion_clock_order_reversals += 1
        previous_receipted_ingestion_utc = ingested
        if newest_receipted_rowid is None:
            newest_receipted_rowid = rowid
            # All more recent rowids were missing insertion clock.
            null_newer_than_receipt = uninstrumented
        if ingested > now_utc + timedelta(minutes=5):
            future_ingestion_clock += 1
        delay_ms = int((ingested - event).total_seconds() * 1000)
        if delay_ms < 0:
            negative_delay += 1
            event_after_insert += 1
        else:
            measured_ms.append(delay_ms)
            if event.date().isoformat() > CANONICAL_CUTOFF:
                measured_after_canonical += 1

    delays = sorted(measured_ms)
    def percentile(q: float) -> int | None:
        if not delays:
            return None
        return delays[min(len(delays)-1, int((len(delays)-1)*q))]

    # Absence of stamps after a newer non-NULL row is a major operational
    # warning. Historical NULLs earlier in rowid order are expected.
    if not receipts_column:
        state = "HOLD_SOURCE_COLUMN_ABSENT"
    elif not rows:
        state = "HOLD_NO_RECENT_SOURCE_ROWS"
    elif not delays:
        state = "HOLD_NO_VALID_INGESTION_RECEIPTS"
    elif null_newer_than_receipt:
        state = "HOLD_RECENT_WRITER_MISSING_RECEIPTS"
    elif interior_receipt_gaps:
        state = "HOLD_INTERLEAVED_INGESTION_RECEIPT_GAPS"
    elif insertion_clock_order_reversals:
        state = "HOLD_INGESTION_CLOCK_ROWID_REVERSAL"
    elif negative_delay or future_ingestion_clock:
        state = "HOLD_CLOCK_CONSISTENCY"
    else:
        state = "OBSERVED_RECEIPT_SAMPLE_ONLY"

    return {
        "schema": "traffic.public-audience.ingestion-receipts-health.v1",
        "status": state,
        "baseline_only_last_published_utc_day": last_certified_day,
        "canonical_archive_integrity_verified_by_this_audit": False,
        "sampled_recent_source_rows": len(rows),
        "sampled_insert_clock_receipts": len(rows) - uninstrumented,
        "legacy_or_uninstrumented_rows": uninstrumented,
        "missing_receipts_newer_than_most_recent_receipt": null_newer_than_receipt,
        "missing_receipts_between_instrumented_rows": interior_receipt_gaps,
        "older_null_rows_with_unproven_boundary": pending_older_nulls,
        "nonnegative_ingest_delay_rows": len(delays),
        "event_time_after_insert": event_after_insert,
        "future_insert_clock_rows": future_ingestion_clock,
        "ingestion_clock_rowid_reversals": insertion_clock_order_reversals,
        "measured_post_canonical_events": measured_after_canonical,
        "observed_ingestion_delay_p50_milliseconds": percentile(0.5),
        "observed_ingestion_delay_p95_milliseconds": percentile(0.95),
        "observed_ingestion_delay_max_milliseconds": delays[-1] if delays else None,
        "observed_delays_over_30_minutes": sum(v > 30*60*1000 for v in delays),
        "observed_delays_over_6_hours": sum(v > 6*3600*1000 for v in delays),
        "observed_delays_over_24_hours": sum(v > 24*3600*1000 for v in delays),
        "sample_is_bounded_not_a_global_scan": True,
        "historic_null_timestamps_not_backfilled": True,
        "remote_log_delivery_complete": False,
        "global_ip_classification_stable": False,
        "two_complete_days_certified": False,
        "publication_authorized": False,
        "ready_to_publish_days": [],
        "sensitive_actor_data_exported": False,
    }


def audit(source: Path, *, sample: int) -> dict:
    require(1 <= sample <= MAX_SAMPLE, "invalid bounded ingestion sample")
    require(source.is_file() and not source.is_symlink(),
            "source database missing or symlink")
    source_before = source.stat()
    uri = f"file:{source.resolve().as_posix()}?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=3)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=3000")
        db.execute("BEGIN")
        cols = {str(row[1]) for row in db.execute(
            "PRAGMA table_info(traffic_entries)"
        )}
        require({"timestamp", "event_id"}.issubset(cols),
                "canonical Traffic entries schema unavailable")
        has_clock = "ingested_at_utc" in cols
        if has_clock:
            rows = db.execute(
                "SELECT rowid,timestamp,ingested_at_utc FROM traffic_entries "
                "ORDER BY rowid DESC LIMIT ?", (sample,),
            ).fetchall()
        else:
            rows = [
                (rowid, stamp, None) for rowid, stamp in db.execute(
                    "SELECT rowid,timestamp FROM traffic_entries "
                    "ORDER BY rowid DESC LIMIT ?", (sample,),
                )
            ]
        result = sample_health(
            rows, now_utc=datetime.now(timezone.utc),
            receipts_column=has_clock,
        )
        db.execute("ROLLBACK")
    finally:
        db.close()
    after = source.stat()
    require(
        (source_before.st_dev, source_before.st_ino) ==
        (after.st_dev, after.st_ino),
        "source inode changed during observation",
    )
    result["read_only_sqlite_connection"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sample", type=int, default=1000)
    parser.add_argument("--require-receipts", action="store_true",
                        help="exit 2 on HOLD rather than informational success")
    args = parser.parse_args()
    try:
        result = audit(args.source, sample=args.sample)
        print(json.dumps(result, sort_keys=True))
        if args.require_receipts and result["status"] != "OBSERVED_RECEIPT_SAMPLE_ONLY":
            return 2
        return 0
    except (OSError, sqlite3.Error, ValueError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
