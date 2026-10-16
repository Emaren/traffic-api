"""Regression coverage for bounded, privacy-safe cold snapshot diagnostics."""

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from app.services.traffic import overview


class ColdSnapshotDiagnosticTests(unittest.TestCase):
    def test_slow_load_and_session_build_emit_separate_stage_timings(self):
        entry = {"timestamp": datetime(2026, 10, 16, tzinfo=timezone.utc)}
        fake_snapshot = {"source_mode": "durable_store", "sessions": []}

        with (
            patch.object(overview, "perf_counter", side_effect=[0.0, 4.0, 8.0]),
            patch.object(
                overview,
                "collect_recent_entries_with_source",
                return_value=([entry], "durable_store"),
            ),
            patch.object(overview, "build_sessions", return_value=[]),
            patch.object(overview, "_store_session_snapshot", return_value=fake_snapshot),
            patch.object(overview.logging, "getLogger") as get_logger,
        ):
            result = overview._rebuild_session_snapshot(window_hours=12)
            self.assertIs(result, fake_snapshot)
            self.assertEqual(get_logger.call_count, 2)
            warnings = [
                item.args for item in get_logger.return_value.warning.call_args_list
            ]
            self.assertIn("traffic_snapshot_load_slow", warnings[0][0])
            self.assertIn("traffic_snapshot_sessions_slow", warnings[1][0])
            self.assertIn("entries=%d", warnings[0][0])
            self.assertIn("sessions=%d", warnings[1][0])
            self.assertEqual(warnings[0][-1], 4.0)
            self.assertEqual(warnings[1][-1], 4.0)
            # Never include request records, IP addresses, or user-agent strings.
            for warning in warnings:
                self.assertNotIn("ip=", warning[0])
                self.assertNotIn("visitor=", warning[0])
                self.assertNotIn("ua=", warning[0])

    def test_fast_snapshot_is_silent(self):
        with (
            patch.object(overview, "perf_counter", side_effect=[0.0, 0.1, 0.2]),
            patch.object(
                overview, "collect_recent_entries_with_source", return_value=([], "durable_store")
            ),
            patch.object(overview, "build_sessions", return_value=[]),
            patch.object(overview, "_store_session_snapshot", return_value={}),
            patch.object(overview.logging, "getLogger") as get_logger,
        ):
            overview._rebuild_session_snapshot(window_hours=12)
            get_logger.assert_not_called()


if __name__ == "__main__":
    unittest.main()
