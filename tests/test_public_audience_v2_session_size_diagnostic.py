from __future__ import annotations

import json
import time
import unittest
from datetime import datetime, timedelta, timezone

from scripts import public_audience_v2_future_session_preview as future

UTC = timezone.utc
ORIGIN = datetime(2026, 10, 20, 23, 45, tzinfo=UTC)


def item(stamp, *, host="aoe2war.com", ip="fixture-ip", ua="browser"):
    return {"timestamp": stamp, "host": host, "ip": ip, "ua": ua}


class PrivateSessionSizeDiagnosticTests(unittest.TestCase):
    def metrics(self, events):
        return future.diagnose_session_sizes(
            events, deadline=time.monotonic() + 15,
        )

    def test_exact_thirty_minute_gap_keeps_single_session(self):
        result = self.metrics([item(ORIGIN), item(ORIGIN+timedelta(minutes=30))])
        self.assertEqual(result["sessions_by_exact_30min_gap"], 1)
        self.assertEqual(result["largest_session_event_count"], 2)
        self.assertFalse(result["publication_authorized"])

    def test_over_thirty_minutes_closes_session(self):
        result = self.metrics([item(ORIGIN), item(ORIGIN+timedelta(minutes=31))])
        self.assertEqual(result["sessions_by_exact_30min_gap"], 2)
        self.assertEqual(result["largest_session_event_count"], 1)

    def test_midnight_crossing_remains_one_session(self):
        result = self.metrics([item(ORIGIN), item(ORIGIN+timedelta(minutes=16))])
        self.assertEqual(result["cross_midnight_session_chains"], 1)
        self.assertEqual(result["sessions_by_exact_30min_gap"], 1)

    def test_different_user_agents_have_distinct_sessions(self):
        result = self.metrics([item(ORIGIN, ua="Moz"), item(
            ORIGIN + timedelta(seconds=1), ua="Other",
        )])
        self.assertEqual(result["sessions_by_exact_30min_gap"], 2)

    def test_diagnoses_large_session_without_materializing_all_events(self):
        count = 20501
        stamp = ORIGIN
        result = self.metrics(item(stamp+timedelta(seconds=i*2))
                              for i in range(count))
        self.assertEqual(result["source_events_examined"], count)
        self.assertEqual(result["largest_session_event_count"], count)
        self.assertEqual(result["sessions_over_20000_events"], 1)
        self.assertEqual(result["largest_five_session_event_counts"], [count])
        self.assertFalse(result["classification_performed"])
        self.assertEqual(result["certified_utc_days"], [])
        self.assertNotIn("fixture-ip", json.dumps(result))

    def test_time_order_regression_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "regressed"):
            self.metrics([item(ORIGIN), item(ORIGIN-timedelta(seconds=1))])

    def test_expired_budget_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "time budget"):
            future.diagnose_session_sizes(
                [item(ORIGIN)], deadline=time.monotonic() - 1,
            )


if __name__ == "__main__":
    unittest.main()
