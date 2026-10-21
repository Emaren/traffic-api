from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from scripts import public_audience_v2_forward_boundary_audit as audit

B = datetime(2026, 10, 20, tzinfo=timezone.utc)


def event(stamp, ip="example-actor", ua="browser", host="aoe2war.com"):
    return {"timestamp": stamp, "host": host, "ip": ip, "ua": ua}


class EpochBoundaryReadOnlyAuditTests(unittest.TestCase):
    def inspect(self, historical, future, max_rows=50):
        return audit.analyze_boundary(
            historical, future, boundary=B, max_rows=max_rows,
        )

    def test_five_minute_cross_boundary_continuation_blocks_isolation(self):
        report = self.inspect(
            [event(B-timedelta(minutes=2))],
            [event(B+timedelta(minutes=3))],
        )
        self.assertEqual(report["canonical_session_continuations"], 1)
        self.assertEqual(report["closest_cross_epoch_gap_seconds"], 300)
        self.assertFalse(report["release_boundary_isolation_observed"])
        self.assertFalse(report["historical_cross_epoch_day_certified"])
        self.assertFalse(report["publication_authorized"])
        self.assertNotIn("example-actor", json.dumps(report))

    def test_exact_thirty_minute_session_continues(self):
        report = self.inspect(
            [event(B-timedelta(minutes=15))],
            [event(B+timedelta(minutes=15))],
        )
        self.assertEqual(report["canonical_session_continuations"], 1)
        self.assertEqual(report["exact_30_minute_continuations"], 1)

    def test_beyond_thirty_minutes_does_not_continue(self):
        report = self.inspect(
            [event(B-timedelta(minutes=16))],
            [event(B+timedelta(minutes=15))],
        )
        self.assertEqual(report["canonical_session_continuations"], 0)
        self.assertEqual(report["cross_epoch_actor_overlap"], 1)
        self.assertTrue(report["release_boundary_isolation_observed"])

    def test_original_host_and_lowercase_ua_semantics(self):
        report = self.inspect(
            [event(B-timedelta(seconds=20), ua="MoZiLla")],
            [event(B+timedelta(seconds=5), ua="mozilla")],
        )
        self.assertEqual(report["canonical_session_continuations"], 1)

    def test_different_host_is_not_same_actor(self):
        report = self.inspect(
            [event(B-timedelta(minutes=1), host="aoe2war.com")],
            [event(B+timedelta(minutes=1), host="other.example")],
        )
        self.assertEqual(report["cross_epoch_actor_overlap"], 0)

    def test_outside_historical_boundary_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "historical event outside"):
            self.inspect([event(B-timedelta(minutes=31))], [])

    def test_outside_future_boundary_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "future event outside"):
            self.inspect([], [event(B+timedelta(minutes=30))])

    def test_cap_refuses_incomplete_scan(self):
        with self.assertRaisesRegex(RuntimeError, "event cap exceeded"):
            self.inspect([event(B-timedelta(minutes=1))] * 2,
                         [], max_rows=1)

    def test_empty_future_does_not_certify_day(self):
        report = self.inspect([event(B-timedelta(minutes=1))], [])
        self.assertTrue(report["release_boundary_isolation_observed"])
        self.assertFalse(report["historical_cross_epoch_day_certified"])
        self.assertFalse(report["late_ingestion_watermark_certified"])

    def test_more_than_one_earlier_event_uses_latest_before_boundary(self):
        report = self.inspect(
            [event(B-timedelta(minutes=25)),
             event(B-timedelta(minutes=2))],
            [event(B+timedelta(minutes=25))],
        )
        self.assertEqual(report["canonical_session_continuations"], 1)
        self.assertEqual(report["closest_cross_epoch_gap_seconds"], 27*60)


if __name__ == "__main__":
    unittest.main()
