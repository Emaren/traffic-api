from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from scripts import public_audience_v2_ingestion_order_audit as audit


UTC = timezone.utc
NOW = datetime(2026, 10, 21, 4, tzinfo=UTC)


class PrivateIngestionOrderAuditTests(unittest.TestCase):
    def observe(self, pairs, cap=200):
        return audit.ordered_event_diagnostic(
            pairs, now_utc=NOW, cap=cap,
        )

    def test_strictly_chronological_rows_have_no_inversions(self):
        result = self.observe([
            (3, "2026-10-20T01:00:00+00:00"),
            (5, "2026-10-20T02:00:00+00:00"),
            (8, "2026-10-21T01:00:00+00:00"),
        ])
        self.assertEqual(result["events_ordered_by_insert_rowid"], 3)
        self.assertEqual(result["events_earlier_than_previously_seen_event_time"], 0)
        self.assertEqual(result["event_dates_retained_counts"],
                         {"2026-10-20": 2, "2026-10-21": 1})
        self.assertTrue(result["relative_order_only_no_per_event_ingestion_time"])

    def test_backdated_event_detected_after_next_day_arrived(self):
        result = self.observe([
            (11, "2026-10-20T12:00:00+00:00"),
            (12, "2026-10-21T02:00:00+00:00"),
            (13, "2026-10-20T10:00:00+00:00"),
        ])
        self.assertEqual(result["events_earlier_than_previously_seen_event_time"], 1)
        self.assertEqual(
            result["events_for_prior_utc_day_after_later_day_already_seen"], 1,
        )
        self.assertEqual(result["largest_event_time_inversion_seconds"], 16*3600)
        self.assertEqual(result["events_over_6_hours_behind_seen_event_time"], 1)
        self.assertEqual(result["events_over_24_hours_behind_seen_event_time"], 0)
        self.assertNotIn("203.0.113", json.dumps(result))

    def test_older_than_24h_event_time_inversion(self):
        result = self.observe([
            (10, "2026-10-21T03:00:00+00:00"),
            (11, "2026-10-20T01:00:00+00:00"),
        ])
        self.assertEqual(result["events_over_30_minutes_behind_seen_event_time"], 1)
        self.assertEqual(result["events_over_24_hours_behind_seen_event_time"], 1)
        self.assertEqual(result["largest_event_time_inversion_seconds"], 26*3600)

    def test_repeated_rowid_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "strictly ascending"):
            self.observe([
                (10, "2026-10-20T01:00:00+00:00"),
                (10, "2026-10-20T01:00:01+00:00"),
            ])

    def test_reversed_rowid_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "strictly ascending"):
            self.observe([
                (10, "2026-10-20T01:00:00+00:00"),
                (9, "2026-10-20T01:00:01+00:00"),
            ])

    def test_invalid_cap_cannot_be_used_to_bypass_bound(self):
        with self.assertRaisesRegex(RuntimeError, "cap exceeded"):
            self.observe([(1, "2026-10-20T01:00:00+00:00"),
                          (2, "2026-10-20T02:00:00+00:00")], cap=1)

    def test_empty_evidence_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "no retained"):
            self.observe([])

    def test_naive_timestamp_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "timezone"):
            self.observe([(1, "2026-10-20T01:00:00")])

    def test_future_timestamp_is_flagged_not_silently_ignored(self):
        result = self.observe([(1, "2026-10-22T05:00:00+00:00")])
        self.assertEqual(result["events_timestamped_in_future"], 1)


if __name__ == "__main__":
    unittest.main()
