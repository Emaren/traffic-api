from __future__ import annotations

import json
import sqlite3
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from scripts import public_audience_v2_future_session_preview as preview


def sample(iso: str, *, actor: str = "a", ua: str = "ua",
           offset: int = 1, source_rowid: int = 1) -> dict:
    return {
        "event_id": str(source_rowid),
        "timestamp": datetime.fromisoformat(iso),
        "timestamp_iso": iso,
        "host": "aoe2war.com",
        "ip": actor,
        "ua": ua,
        "line_offset": offset,
        "normalized_path": "/",
        "referrer_host": "",
        "source_rowid": source_rowid,
    }


def fake_builder(events, *, now, ip_behavior):
    return {
        "session_id": str(events[0]["source_rowid"]),
        "route_kind": "page",
        "first_seen_at": events[0]["timestamp_iso"],
        "classification_state": "likely_human",
        "known_automation": False,
        "suspicious_score": 0,
        "human_confirmed": False,
    }


def fake_bucket(sessions, daily):
    for session in sessions:
        day = session["first_seen_at"][:10]
        stats = daily.setdefault(day, [0, 0, 0])
        stats[0] += 1
        stats[1] += 1
    return len(sessions)


class FutureSessionPreviewTests(unittest.TestCase):
    def setUp(self):
        build = patch.object(preview.canonical, "build_single_session",
                             side_effect=fake_builder)
        bucket = patch.object(preview.canonical, "finalize_bucket",
                              side_effect=fake_bucket)
        build.start()
        bucket.start()
        self.addCleanup(build.stop)
        self.addCleanup(bucket.stop)
        self.now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
        self.deadline = time.monotonic() + 20
        self.behavior = lambda *_args: {"request_count": 5}

    def run_stream(self, events):
        return preview.replay(
            events, behavior=self.behavior, reference_now=self.now,
            deadline=self.deadline,
        )

    def test_cross_utc_midnight_one_session(self):
        daily, stats = self.run_stream([
            sample("2026-10-20T23:55:00+00:00", source_rowid=1),
            sample("2026-10-21T00:04:00+00:00", source_rowid=2),
        ])
        self.assertEqual(daily, {"2026-10-20": [1, 1, 0]})
        self.assertEqual(stats["finalized_sessions"], 1)
        self.assertEqual(stats["accepted_future_events"], 2)

    def test_more_than_30_minute_gap_splits_sessions(self):
        daily, stats = self.run_stream([
            sample("2026-10-20T23:55:00+00:00", source_rowid=1),
            sample("2026-10-21T00:26:00+00:00", source_rowid=2),
        ])
        self.assertEqual(daily, {
            "2026-10-20": [1, 1, 0],
            "2026-10-21": [1, 1, 0],
        })
        self.assertEqual(stats["finalized_sessions"], 2)

    def test_exactly_thirty_minute_gap_stays_one_session(self):
        daily, stats = self.run_stream([
            sample("2026-10-20T23:55:00+00:00", source_rowid=1),
            sample("2026-10-21T00:25:00+00:00", source_rowid=2),
        ])
        self.assertEqual(daily, {"2026-10-20": [1, 1, 0]})
        self.assertEqual(stats["finalized_sessions"], 1)

    def test_independent_user_agents_do_not_merge(self):
        daily, stats = self.run_stream([
            sample("2026-10-20T12:00:00+00:00",
                   source_rowid=1, ua="mozilla"),
            sample("2026-10-20T12:01:00+00:00",
                   source_rowid=2, ua="other"),
        ])
        self.assertEqual(daily, {"2026-10-20": [2, 2, 0]})
        self.assertEqual(stats["finalized_sessions"], 2)

    def test_page_bucket_collapses_only_after_all_sessions_closed(self):
        # Two actors starting in the same 60-second burst:
        # the shared finalize function must get the complete bucket.
        batches = []
        def collect(sessions, daily):
            batches.append(len(sessions))
            return fake_bucket(sessions, daily)
        with patch.object(preview.canonical, "finalize_bucket",
                          side_effect=collect):
            daily, stats = self.run_stream([
                sample("2026-10-20T12:00:03+00:00",
                       actor="a", source_rowid=1),
                sample("2026-10-20T12:00:04+00:00",
                       actor="b", source_rowid=2),
                sample("2026-10-20T12:45:00+00:00",
                       actor="c", source_rowid=3),
            ])
        self.assertEqual(batches, [2, 1])
        self.assertEqual(stats["finalized_sessions"], 3)
        self.assertEqual(daily["2026-10-20"], [3, 3, 0])

    def test_wall_budget_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "time budget"):
            preview.replay(
                [sample("2026-10-20T01:00:00+00:00",
                        actor=str(i), source_rowid=i+1)
                 for i in range(128)],
                behavior=self.behavior, reference_now=self.now,
                deadline=time.monotonic() - 1,
            )

    def test_timestamp_line_offset_order_matches_historical(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("""
            CREATE TABLE future_events (
              source_rowid INTEGER PRIMARY KEY,
              event_json TEXT NOT NULL,
              timestamp TEXT NOT NULL);
            CREATE INDEX idx_future_events_timestamp ON future_events(timestamp);
        """)
        stamp = "2026-10-20T04:01:00+00:00"
        records = [
            {"source_rowid": 3, "timestamp": stamp, "line_offset": 80},
            {"source_rowid": 2, "timestamp": stamp, "line_offset": 2},
            {"source_rowid": 1, "timestamp": stamp, "line_offset": 2},
        ]
        for event in records:
            db.execute("INSERT INTO future_events VALUES (?,?,?)",
                       (event["source_rowid"], json.dumps(event), stamp))
        with patch.object(preview.canonical, "normalize_row",
                          side_effect=lambda item, rules: {
                              **item, "timestamp_iso": item["timestamp"],
                          }):
            actual = list(preview.read_canonical_inputs(
                db, rules=[], max_rowid=3, max_events=3,
                deadline=time.monotonic() + 10,
            ))
        self.assertEqual(
            [x["source_rowid"] for x in actual], [1, 2, 3],
        )

    def test_normalization_drift_stops(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("""
            CREATE TABLE future_events (
              source_rowid INTEGER PRIMARY KEY,
              event_json TEXT NOT NULL,
              timestamp TEXT NOT NULL);
            CREATE INDEX idx_future_events_timestamp ON future_events(timestamp);
        """)
        stamp = "2026-10-20T04:01:00+00:00"
        db.execute("INSERT INTO future_events VALUES (?,?,?)",
                   (1, json.dumps({
                       "source_rowid": 1, "timestamp": stamp, "line_offset": 1,
                   }), stamp))
        with patch.object(preview.canonical, "normalize_row", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "normalization drift"):
                list(preview.read_canonical_inputs(
                    db, rules=[], max_rowid=1, max_events=10,
                    deadline=time.monotonic() + 10,
                ))

    def test_bounded_max_events_enforced(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("""
            CREATE TABLE future_events (
              source_rowid INTEGER PRIMARY KEY,
              event_json TEXT NOT NULL,
              timestamp TEXT NOT NULL);
            CREATE INDEX idx_future_events_timestamp ON future_events(timestamp);
        """)
        stamp = "2026-10-20T04:01:00+00:00"
        for i in (1, 2):
            db.execute("INSERT INTO future_events VALUES(?,?,?)",
                       (i, json.dumps({
                           "source_rowid": i, "timestamp": stamp,
                           "line_offset": i,
                       }), stamp))
        with self.assertRaisesRegex(RuntimeError, "cap exceeded"):
            list(preview.read_canonical_inputs(
                db, rules=[], max_rowid=2, max_events=1,
                deadline=time.monotonic() + 10,
            ))


if __name__ == "__main__":
    unittest.main()
