from __future__ import annotations

import json
import sqlite3
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from scripts import public_audience_v2_forward_ip_shadow as shadow
from scripts import public_audience_v2_future_session_preview as preview


def db(schema):
    db = sqlite3.connect(":memory:")
    db.executescript(schema)
    return db


def normalize(record, rules):
    stamp = datetime.fromisoformat(record["timestamp"])
    return {
        **record, "timestamp": stamp, "timestamp_iso": record["timestamp"],
        "category": "human", "route_kind": "page",
    }


def fake_builder(events, *, now, ip_behavior):
    return {
        "session_id": str(events[0]["source_rowid"]),
        "first_seen_at": events[0]["timestamp_iso"],
        "route_kind": "page",
        "classification_state": "likely_human",
        "human_confirmed": False,
        "suspicious_score": 0, "known_automation": False,
    }


def finalize(sessions, daily):
    for session in sessions:
        day = session["first_seen_at"][:10]
        values = daily.setdefault(day, [0, 0, 0])
        values[0] += 1
        values[1] += 1
    return len(sessions)


class OriginalCanonicalStreamABTests(unittest.TestCase):
    def setUp(self):
        self.ledger = db(
            "CREATE TABLE future_events (source_rowid INTEGER PRIMARY KEY,"
            "event_json TEXT NOT NULL,timestamp TEXT NOT NULL);"
            "CREATE INDEX idx_future_events_timestamp "
            "ON future_events(timestamp);"
        )
        for rowid, stamp in [
            (20, "2026-10-20T23:58:00+00:00"),
            (21, "2026-10-21T00:03:00+00:00"),
        ]:
            record = {
                "source_rowid": rowid, "timestamp": stamp,
                "line_offset": rowid, "host": "aoe2war.com",
                "ip": "actor-fixture", "ua": "browser",
                "event_id": str(rowid), "referrer_host": "",
                "normalized_path": "/", "raw_path": "/",
            }
            self.ledger.execute(
                "INSERT INTO future_events VALUES (?,?,?)",
                (rowid, json.dumps(record), stamp),
            )
        self.history = db(shadow.SCHEMA)
        self.future = db(shadow.SCHEMA)
        self.future.execute(
            "INSERT INTO ip_counts VALUES (?,?,?,?)",
            ("aoe2war.com", "actor-fixture", 2, 2),
        )
        self.future.execute(
            "INSERT INTO ip_uas VALUES(?,?,?)",
            ("aoe2war.com", "actor-fixture", "browser"),
        )
        self.future.execute(
            "INSERT INTO ip_paths VALUES(?,?,?)",
            ("aoe2war.com", "actor-fixture", "/"),
        )
        self.ledger.commit()
        self.future.commit()
        for conn in (self.ledger, self.history, self.future):
            self.addCleanup(conn.close)
        for target, name, replacement in [
            (preview.canonical, "normalize_row", normalize),
            (preview.canonical, "build_single_session", fake_builder),
            (preview.canonical, "finalize_bucket", finalize),
        ]:
            p = patch.object(target, name, side_effect=replacement)
            p.start()
            self.addCleanup(p.stop)
        self.now = datetime(2026, 10, 21, 4, tzinfo=timezone.utc)

    def check(self, daily, stats):
        return preview.compare_original_stream(
            self.ledger, self.history, self.future, rules=[],
            prefix_cursor=21, max_events=10,
            deadline=time.monotonic() + 10,
            snapshot_now=self.now, expected_daily=daily,
            expected_stats=stats,
        )

    def test_cross_midnight_reference_matches_one_canonical_session(self):
        receipt = self.check(
            {"2026-10-20": [1, 1, 0]},
            {"accepted_future_events": 2,
             "finalized_sessions": 1,
             "page_sessions": 1},
        )
        self.assertEqual(
            receipt["result"], "PRIVATE_FUTURE_SESSION_AB_PARITY_VERIFIED"
        )
        self.assertEqual(receipt["input_events_compared"], 2)
        self.assertFalse(receipt["publication_authorized"])
        self.assertFalse(receipt["late_ingestion_watermark_certified"])
        self.assertNotIn("actor-fixture", json.dumps(receipt))

    def test_wrong_daily_candidate_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "daily distributions"):
            self.check(
                {"2026-10-20": [2, 2, 0]},
                {"accepted_future_events": 2,
                 "finalized_sessions": 1, "page_sessions": 1},
            )

    def test_wrong_session_count_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "session count"):
            self.check(
                {"2026-10-20": [1, 1, 0]},
                {"accepted_future_events": 2,
                 "finalized_sessions": 2, "page_sessions": 1},
            )

    def test_wrong_event_count_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "raw input"):
            self.check(
                {"2026-10-20": [1, 1, 0]},
                {"accepted_future_events": 3,
                 "finalized_sessions": 1, "page_sessions": 1},
            )

    def test_expired_time_budget_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "time budget"):
            preview.compare_original_stream(
                self.ledger, self.history, self.future, rules=[],
                prefix_cursor=21, max_events=10,
                deadline=time.monotonic() - 1,
                snapshot_now=self.now, expected_daily={},
                expected_stats={"accepted_future_events": 2,
                                "finalized_sessions": 1, "page_sessions": 1},
            )


if __name__ == "__main__":
    unittest.main()
