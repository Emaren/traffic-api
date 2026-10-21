from __future__ import annotations

import json
import sqlite3
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from scripts import public_audience_v2_daily_boundary_readiness as readiness


def stamp(value):
    return datetime.fromisoformat(value)


def event(value, actor="actor"):
    return {
        "timestamp": stamp(value), "host": "aoe2war.com",
        "ip": actor, "ua": "mozilla",
    }


class DailyBoundaryReadinessTests(unittest.TestCase):
    def setUp(self):
        self.boundary = stamp("2026-10-21T00:00:00+00:00")
        self.deadline = time.monotonic() + 10

    def run_case(self, tail, future, through):
        return readiness.examine_trailing_sessions(
            tail, iter(future), boundary=self.boundary,
            scanned_through=stamp(through), deadline=self.deadline,
        )

    def test_cross_midnight_actor_expires_observationally(self):
        receipt = self.run_case(
            [event("2026-10-20T23:55:00+00:00")],
            [event("2026-10-21T00:04:00+00:00")],
            "2026-10-21T01:00:00+00:00",
        )
        self.assertEqual(receipt["actor_keys_observed_continuing_across_midnight"], 1)
        self.assertEqual(receipt["actor_keys_observationally_inactive_after_gap"], 1)
        self.assertEqual(receipt["actor_keys_without_observed_expiry"], 0)
        self.assertFalse(receipt["day_publication_authorized"])
        self.assertNotIn("actor", json.dumps(receipt).replace("actor_keys", ""))

    def test_no_next_day_event_expired_only_on_observed_event_clock(self):
        receipt = self.run_case(
            [event("2026-10-20T23:58:00+00:00")], [],
            "2026-10-21T01:00:00+00:00",
        )
        self.assertEqual(receipt["actor_keys_observationally_inactive_after_gap"], 1)
        self.assertEqual(receipt["actor_keys_observed_continuing_across_midnight"], 0)

    def test_incomplete_future_event_clock_stays_unresolved(self):
        receipt = self.run_case(
            [event("2026-10-20T23:58:00+00:00")], [],
            "2026-10-21T00:10:00+00:00",
        )
        self.assertEqual(receipt["actor_keys_without_observed_expiry"], 1)

    def test_exact_gap_is_canonical_continuation(self):
        receipt = self.run_case(
            [event("2026-10-20T23:30:00+00:00")],
            [event("2026-10-21T00:00:00+00:00")],
            "2026-10-21T00:15:00+00:00",
        )
        self.assertEqual(receipt["actor_keys_observed_continuing_across_midnight"], 1)
        self.assertEqual(receipt["actor_keys_without_observed_expiry"], 1)

    def test_gap_over_thirty_minutes_does_not_extend_old_session(self):
        receipt = self.run_case(
            [event("2026-10-20T23:45:00+00:00")],
            [event("2026-10-21T00:16:00+00:00")],
            "2026-10-21T00:20:00+00:00",
        )
        self.assertEqual(receipt["actor_keys_observed_continuing_across_midnight"], 0)
        self.assertEqual(receipt["actor_keys_observationally_inactive_after_gap"], 1)

    def test_different_actor_cannot_extend_existing(self):
        receipt = self.run_case(
            [event("2026-10-20T23:50:00+00:00")],
            [event("2026-10-21T00:05:00+00:00", actor="different")],
            "2026-10-21T00:30:00+00:00",
        )
        self.assertEqual(receipt["actor_keys_observed_continuing_across_midnight"], 0)
        self.assertEqual(receipt["actor_keys_without_observed_expiry"], 1)

    def test_invalid_tail_outside_last_half_hour_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "out of range"):
            self.run_case(
                [event("2026-10-20T23:01:00+00:00")], [],
                "2026-10-21T01:00:00+00:00",
            )

    def test_scan_window_only_by_timestamp_and_frozen_rowid(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("""
            CREATE TABLE future_events(
                source_rowid INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL, event_json TEXT NOT NULL);
            CREATE INDEX idx_future_events_timestamp ON future_events(timestamp);
        """)
        records = [
            (1, "2026-10-20T10:00:00+00:00"),
            (2, "2026-10-20T23:50:00+00:00"),
            (3, "2026-10-20T23:51:00+00:00"),
            (4, "2026-10-20T23:52:00+00:00"),
        ]
        for rowid, time_value in records:
            db.execute(
                "INSERT INTO future_events VALUES(?,?,?)",
                (rowid, time_value, json.dumps({
                    "source_rowid": rowid, "timestamp": time_value,
                    "host": "aoe2war.com", "ip": "actor",
                })),
            )
        def normalize(record, rules):
            return {**record, "timestamp": stamp(record["timestamp"])}
        with patch.object(readiness.canonical, "normalize_row",
                          side_effect=normalize):
            got = list(readiness.canonical_window_inputs(
                db, begin=stamp("2026-10-20T23:30:00+00:00"),
                end=self.boundary, max_source_rowid=3, rules=[],
                max_events=3, deadline=self.deadline,
            ))
            self.assertEqual([x["source_rowid"] for x in got], [2, 3])
            with self.assertRaisesRegex(RuntimeError, "window cap"):
                list(readiness.canonical_window_inputs(
                    db, begin=stamp("2026-10-20T23:30:00+00:00"),
                    end=self.boundary, max_source_rowid=4, rules=[],
                    max_events=1, deadline=self.deadline,
                ))

    def test_malformed_future_evidence_fails(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("""
            CREATE TABLE future_events(
                source_rowid INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL, event_json TEXT NOT NULL);
            CREATE INDEX idx_future_events_timestamp ON future_events(timestamp);
        """)
        db.execute("INSERT INTO future_events VALUES(?,?,?)", (
            7, "2026-10-20T23:50:00+00:00",
            json.dumps({"source_rowid": 7, "timestamp": "wrong"}),
        ))
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            list(readiness.canonical_window_inputs(
                db, begin=stamp("2026-10-20T23:30:00+00:00"),
                end=self.boundary, max_source_rowid=7, rules=[],
                max_events=10, deadline=self.deadline,
            ))


if __name__ == "__main__":
    unittest.main()
