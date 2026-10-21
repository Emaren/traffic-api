from __future__ import annotations

import sqlite3
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from scripts import public_audience_v2_future_session_preview as preview

NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
START = datetime(2026, 10, 20, 23, 55, tzinfo=timezone.utc)


def events(n, *, interval_seconds=1, first=START, actor="fixture",
           ua="fixture-browser"):
    for i in range(n):
        stamp = first + timedelta(seconds=i * interval_seconds)
        yield {
            "host": "aoe2war.com", "ip": actor, "ua": ua,
            "event_id": str(i), "source_rowid": i + 1,
            "timestamp": stamp, "timestamp_iso": stamp.isoformat(),
            "normalized_path": "/match", "category": "human",
            "route_kind": "page", "referrer_host": "",
        }


def classify(items, *, now, ip_behavior):
    # A strict test stand-in: canonical builder must see ALL events
    # in the correct order, never segment the logical session.
    assert all(x["timestamp"].tzinfo is not None for x in items)
    assert all(
        items[i]["timestamp"] <= items[i+1]["timestamp"]
        for i in range(len(items)-1)
    )
    return {
        "session_id": items[0]["event_id"],
        "first_seen_at": items[0]["timestamp_iso"],
        "route_kind": "page",
        "known_automation": False, "suspicious_score": 0,
        "classification_state": "likely_human",
        "human_confirmed": False,
        "event_count": len(items),
    }


def count_bucket(batch, daily):
    for session in batch:
        day = session["first_seen_at"][:10]
        result = daily.setdefault(day, [0, 0, 0])
        result[0] += 1
        result[1] += 1
    return len(batch)


class InMemorySegmentedCanonicalTests(unittest.TestCase):
    def setUp(self):
        mock_builder = patch.object(
            preview.canonical, "build_single_session",
            side_effect=classify,
        )
        mock_finalize = patch.object(
            preview.canonical, "finalize_bucket",
            side_effect=count_bucket,
        )
        mock_builder.start()
        mock_finalize.start()
        self.addCleanup(mock_builder.stop)
        self.addCleanup(mock_finalize.stop)

    def test_measured_29016_event_session_kept_intact(self):
        day, stats = preview.replay(
            events(29016),
            behavior=lambda host, ip: {"request_count": 29016},
            reference_now=NOW, deadline=time.monotonic()+30,
        )
        self.assertEqual(day, {"2026-10-20": [1, 1, 0]})
        self.assertEqual(stats["finalized_sessions"], 1)
        self.assertEqual(stats["longest_session_events"], 29016)
        self.assertEqual(stats["accepted_future_events"], 29016)
        self.assertTrue(stats["ephemeral_database_only"])
        self.assertGreater(stats["ephemeral_event_segments_written"], 100)

    def test_exact_gap_preserves_cross_midnight_session(self):
        day, stats = preview.replay(
            iter([*events(1), *events(
                1, first=START + timedelta(minutes=30),
            )]),
            behavior=lambda *_args: {},
            reference_now=NOW, deadline=time.monotonic()+10,
        )
        self.assertEqual(day, {"2026-10-20": [1, 1, 0]})
        self.assertEqual(stats["finalized_sessions"], 1)

    def test_oversized_session_under_global_cap_not_split(self):
        day, stats = preview.replay(
            events(26863), behavior=lambda *_args: {},
            reference_now=NOW, deadline=time.monotonic()+30,
        )
        self.assertEqual(day, {"2026-10-20": [1, 1, 0]})
        self.assertEqual(stats["longest_session_events"], 26863)
        self.assertEqual(stats["finalized_sessions"], 1)

    def test_separate_user_agents_remain_distinct(self):
        items = [*events(2, ua="one"), *events(
            2, ua="two", first=START+timedelta(seconds=4),
        )]
        items.sort(key=lambda item: item["timestamp"])
        day, stats = preview.replay(
            items, behavior=lambda *_args: {},
            reference_now=NOW, deadline=time.monotonic()+10,
        )
        self.assertEqual(day, {"2026-10-20": [2, 2, 0]})
        self.assertEqual(stats["finalized_sessions"], 2)

    def test_bounded_budget_does_not_publish(self):
        with self.assertRaisesRegex(RuntimeError, "time budget"):
            preview.replay(
                events(128), behavior=lambda *_args: {},
                reference_now=NOW, deadline=time.monotonic()-1,
            )

    def test_spool_does_not_create_disk_files(self):
        # Preview only constructs sqlite3.connect(':memory:'); it never
        # creates a persistence path for session event segments.
        with patch.object(preview.sqlite3, "connect", wraps=sqlite3.connect) as connect:
            day, _ = preview.replay(
                events(4), behavior=lambda *_args: {},
                reference_now=NOW, deadline=time.monotonic()+10,
            )
        self.assertEqual(connect.call_args.args, (":memory:",))
        self.assertEqual(day, {"2026-10-20": [1, 1, 0]})


if __name__ == "__main__":
    unittest.main()
