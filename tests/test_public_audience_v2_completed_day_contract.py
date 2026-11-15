"""Synthetic negative contract for #31; no live source, forge or publisher.

Session labels are fixed fixtures. The original expiry, burst collapse and
daily finalizer run unchanged; this does not prove production classifier parity.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_daily_boundary_readiness as boundary
from scripts import public_audience_v2_forward_ledger as ledger
from scripts import public_audience_v2_forward_readiness as readiness
from scripts import public_audience_v2_future_session_preview as preview
from scripts import public_audience_v2_ingestion_receipts_health as receipts


NOW = datetime(2026, 11, 15, 0, 5, tzinfo=timezone.utc)


def event(stamp, rowid=1, *, actor="192.0.2.1", path="/"):
    return {
        "source_rowid": rowid, "event_id": str(rowid),
        "timestamp": datetime.fromisoformat(stamp), "timestamp_iso": stamp,
        "host": "aoe2war.com", "ip": actor, "ua": "fixture-browser",
        "normalized_path": path, "raw_path": path, "referrer_host": "",
        "line_offset": 1,
    }


def labeled_session(events, *, now, ip_behavior):
    first, last = events[0], events[-1]
    return {
        "session_id": first["event_id"], "ip": first["ip"],
        "started_at": first["timestamp_iso"], "ended_at": last["timestamp_iso"],
        "first_seen_at": first["timestamp_iso"], "route_kind": "page",
        "classification_state": "likely_human", "known_automation": False,
        "suspicious_score": 0, "project_slug": "aoe2hdbets", "source": "direct",
        "country": "Canada", "country_code": "CA", "browser": "Chrome",
        "device": "desktop", "os": "Linux", "page_count": 1,
        "event_count": len(events), "page_sequence": [first["normalized_path"]],
        "total_seconds": (last["timestamp"] - first["timestamp"]).total_seconds(),
    }


class CompletedDayAuthorityContract(unittest.TestCase):
    def test_current_and_future_utc_days_rejected_before_any_file_access(self):
        # 00:05 UTC is still the current UTC day, regardless of local timezone.
        for day in ("2026-11-15", "2026-11-16"):
            with self.subTest(day=day), patch.object(
                boundary, "datetime", wraps=datetime,
            ) as clock, patch.object(
                Path, "is_file", side_effect=AssertionError("unexpected source access"),
            ):
                clock.now.return_value = NOW
                with self.assertRaisesRegex(RuntimeError, "completed forward UTC"):
                    boundary.inspect(
                        *(Path("unused") for _ in range(4)), day=day,
                        max_window_events=10, lookahead_hours=1, budget_seconds=5,
                    )
                clock.now.assert_called_once_with(timezone.utc)

    def test_previous_utc_day_still_requires_evidence_after_calendar_check(self):
        with patch.object(boundary, "datetime", wraps=datetime) as clock, \
             patch.object(Path, "is_file", return_value=False):
            clock.now.return_value = NOW
            with self.assertRaisesRegex(RuntimeError, "evidence absent/symlink"):
                boundary.inspect(
                    *(Path("unused") for _ in range(4)), day="2026-11-14",
                    max_window_events=10, lookahead_hours=1, budget_seconds=5,
                )

    def test_historical_rows_without_insert_receipts_are_hold_not_certified(self):
        result = receipts.sample_health(
            [(2, "2026-10-20T23:59:00+00:00", None),
             (1, "2026-10-20T23:58:00+00:00", None)],
            now_utc=NOW, receipts_column=True,
        )
        self.assertEqual(result["status"], "HOLD_NO_VALID_INGESTION_RECEIPTS")
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(result["ready_to_publish_days"], [])

    def test_recent_good_receipts_do_not_certify_missing_historical_receipts(self):
        result = receipts.sample_health(
            [(2, "2026-11-14T23:00:00+00:00", "2026-11-14T23:01:00+00:00"),
             (1, "2026-10-20T23:58:00+00:00", None)],
            now_utc=NOW, receipts_column=True,
        )
        self.assertEqual(result["status"], "OBSERVED_RECEIPT_SAMPLE_ONLY")
        self.assertEqual(result["older_null_rows_with_unproven_boundary"], 1)
        self.assertFalse(result["two_complete_days_certified"])
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(result["ready_to_publish_days"], [])

    def test_caught_up_live_private_success_never_authorizes_any_day(self):
        result = readiness.report(
            {"phase": "LIVE", "captured": "1", "accepted": "1",
             "live_rowid": str(ledger.FROZEN_WATERMARK),
             "original_watermark": str(ledger.FROZEN_WATERMARK)},
            retained=1, source_max_rowid=ledger.FROZEN_WATERMARK,
            earliest_private_day="2026-10-20", last_private_day="2026-10-20",
        )
        self.assertEqual(result["result"], "PRIVATE_FORWARD_INTEGRITY_VERIFIED")
        self.assertEqual(result["unscanned_rowid_span_upper_bound"], 0)
        for name in ("canonical_day_classification_ready",
                     "utc_day_completeness_certified", "publication_authorized"):
            self.assertFalse(result[name])
        self.assertEqual(result["ready_to_publish_days"], [])


class WatermarkOverlapContract(unittest.TestCase):
    def setUp(self):
        self.source = sqlite3.connect(":memory:")
        self.source.row_factory = sqlite3.Row
        self.private = sqlite3.connect(":memory:")
        self.addCleanup(self.source.close)
        self.addCleanup(self.private.close)
        self.source.executescript("""
            CREATE TABLE traffic_entries(event_id TEXT,timestamp TEXT,ip TEXT,
              line_offset INTEGER,raw_path TEXT,normalized_path TEXT,
              referrer_host TEXT,ua TEXT,host TEXT);
            CREATE INDEX idx_traffic_entries_timestamp_line_offset
              ON traffic_entries(timestamp,line_offset);
        """)
        self.private.executescript(ledger.PRIVATE_SCHEMA)
        self.meta = ledger.initial_metadata({
            "source": "synthetic-only", "device": "1", "inode": "2",
            "hosts_sha256": "h", "rules_sha256": "r", "canonical_sha256": "c",
        })
        self.private.executemany("INSERT INTO ledger_metadata VALUES(?,?)", self.meta.items())
        self.private.commit()

    def add(self, rowid, stamp):
        self.source.execute(
            "INSERT INTO traffic_entries(rowid,event_id,timestamp,ip,line_offset,"
            "raw_path,normalized_path,referrer_host,ua,host) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rowid, str(rowid), stamp, "192.0.2.1", 1, "/", "/", "", "Mozilla", "aoe2war.com"),
        )
        self.source.commit()

    def step(self, cap=1):
        # Visibility is held fixed; the real SQL keyset/cursor transaction runs.
        with patch.object(ledger.canonical, "normalize_row", side_effect=lambda row, rules: {
            "timestamp_iso": row["timestamp"],
        }):
            return ledger.advance_one(self.source, self.private, self.meta,
                                      ["aoe2war.com"], [], cap=cap)

    def ids(self):
        return [r[0] for r in self.private.execute(
            "SELECT source_rowid FROM future_events ORDER BY source_rowid")]

    def test_overlap_ties_at_watermark_and_retry_preserve_every_oct20_input(self):
        self.add(99, "2026-10-19T23:59:59+00:00")
        for rowid in (100, 101, ledger.FROZEN_WATERMARK):
            self.add(rowid, "2026-10-20T00:01:00+00:00")
        # Arrives later in rowid order but belongs earlier in event time.
        self.add(ledger.FROZEN_WATERMARK + 1, "2026-10-20T00:00:01+00:00")
        for _ in range(6):
            result = self.step()
            self.assertFalse(result["publish_authorized"])
            self.assertFalse(result["public_audience_writes"])
        expected = [100, 101, ledger.FROZEN_WATERMARK, ledger.FROZEN_WATERMARK + 1]
        self.assertEqual(self.ids(), expected)
        before = dict(self.meta)
        self.step()
        self.assertEqual(self.ids(), expected)
        self.assertEqual(self.meta, before)

    def test_late_oct19_input_rolls_back_entire_batch_and_cursor(self):
        self.step()  # empty bootstrap finishes
        self.add(ledger.FROZEN_WATERMARK + 1, "2026-10-20T00:01:00+00:00")
        self.add(ledger.FROZEN_WATERMARK + 2, "2026-10-19T23:59:59+00:00")
        before = dict(self.meta)
        with self.assertRaisesRegex(RuntimeError, "late event"):
            self.step(cap=10)
        self.assertEqual(self.ids(), [])
        self.assertEqual(self.meta, before)
        self.assertEqual(ledger.read_metadata(self.private), before)


class SessionAndBurstContract(unittest.TestCase):
    def replay(self, events):
        with patch.object(preview.canonical, "build_single_session", side_effect=labeled_session), \
             patch.object(preview.canonical, "apply_known_visitor_confirmation", return_value=None):
            return preview.replay(events, behavior=lambda *_: {}, reference_now=NOW,
                                  deadline=time.monotonic() + 5)

    def test_exact_thirty_minutes_stays_on_first_utc_day_but_one_microsecond_splits(self):
        for suffix, expected in (("00:25:00", {"2026-10-20": [1, 1, 0]}),
                                 ("00:25:00.000001", {"2026-10-20": [1, 1, 0],
                                                        "2026-10-21": [1, 1, 0]})):
            with self.subTest(suffix=suffix):
                daily, _ = self.replay([
                    event("2026-10-20T23:55:00+00:00"),
                    event("2026-10-21T" + suffix + "+00:00", 2),
                ])
                self.assertEqual(daily, expected)

    def test_real_sixty_second_burst_edge_changes_potential_not_total_traffic(self):
        for last, expected in (("12:00:59.999999", [3, 0, 0]),
                               ("12:01:00", [3, 3, 0])):
            with self.subTest(last=last):
                daily, stats = self.replay([
                    event("2026-10-20T12:00:01+00:00", 1, actor="192.0.2.1"),
                    event("2026-10-20T12:00:02+00:00", 2, actor="192.0.2.2", path="/traffic"),
                    event("2026-10-20T" + last + "+00:00", 3, actor="192.0.2.3"),
                ])
                self.assertEqual(daily, {"2026-10-20": expected})
                self.assertEqual(stats["finalized_sessions"], 3)

    def test_late_rowid_order_is_rejected_instead_of_silently_counting_three_sessions(self):
        rows = [event("2026-10-20T23:50:00+00:00", 1),
                event("2026-10-21T01:00:00+00:00", 2, actor="192.0.2.2"),
                event("2026-10-21T00:10:00+00:00", 3)]
        with self.assertRaisesRegex(RuntimeError, "event time order regressed"):
            self.replay(rows)

    def test_timestamp_order_includes_late_arrival_in_cross_midnight_session(self):
        rows = [
            event("2026-10-20T23:50:00+00:00", 1),
            event("2026-10-21T00:10:00+00:00", 3),
            event("2026-10-21T01:00:00+00:00", 2, actor="192.0.2.2"),
        ]
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(ledger.PRIVATE_SCHEMA)
            for row in rows:
                raw = {**row, "timestamp": row["timestamp_iso"]}
                db.execute("INSERT INTO future_events VALUES(?,?,?)",
                           (row["source_rowid"], json.dumps(raw), raw["timestamp"]))
            with patch.object(preview.canonical, "normalize_row", side_effect=lambda row, rules: {
                **row, "timestamp": datetime.fromisoformat(row["timestamp"]),
            }):
                ordered = list(preview.read_canonical_inputs(
                    db, rules=[], max_rowid=3, max_events=3,
                    deadline=time.monotonic() + 5,
                ))
        self.assertEqual([row["source_rowid"] for row in ordered], [1, 3, 2])
        daily, stats = self.replay(ordered)
        self.assertEqual(daily, {"2026-10-20": [1, 1, 0], "2026-10-21": [1, 1, 0]})
        self.assertEqual(stats["finalized_sessions"], 2)

    def test_equal_event_timestamps_remain_valid(self):
        _, stats = self.replay([
            event("2026-10-20T12:00:00+00:00", 1),
            event("2026-10-20T12:00:00+00:00", 2),
        ])
        self.assertEqual(stats["finalized_sessions"], 1)


if __name__ == "__main__":
    unittest.main()
