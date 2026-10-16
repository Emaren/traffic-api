"""Cold graph builder timing diagnostics must be bounded and privacy-safe."""

import unittest
from unittest.mock import patch

from app.services.traffic import overview


class GraphBuilderDiagnosticsTests(unittest.TestCase):
    def test_slow_builder_reports_stage_durations_without_visitor_data(self):
        snapshot = {
            "sessions": [],
            "source_mode": "durable_store",
            "earliest_entry_at": None,
        }
        with (
            patch.object(overview, "PROJECTS", []),
            patch.object(overview, "_build_session_snapshot", return_value=snapshot),
            patch.object(overview, "perf_counter", side_effect=[0.0, 1.0, 2.0, 3.0, 5.5]),
            patch.object(overview.logging, "getLogger") as get_logger,
        ):
            payload = overview.build_project_human_series(range_key="all")
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["projects"], [])
            get_logger.assert_called_once_with("uvicorn.error")
            warning = get_logger.return_value.warning
            warning.assert_called_once()
            fmt, *args = warning.call_args.args
            self.assertIn("traffic_graph_build_slow", fmt)
            self.assertIn("snapshot_s", fmt)
            self.assertIn("raw_buckets_s", fmt)
            self.assertIn("session_signals_s", fmt)
            self.assertIn("project_output_s", fmt)
            self.assertEqual(args[:6], ("all", 5.5, 1.0, 1.0, 1.0, 2.5))
            self.assertEqual(args[6:], [0, 0])
            self.assertNotIn("ip", fmt.lower())
            self.assertNotIn("visitor", fmt.lower())

    def test_fast_builder_does_not_log(self):
        snapshot = {
            "sessions": [],
            "source_mode": "durable_store",
            "earliest_entry_at": None,
        }
        with (
            patch.object(overview, "PROJECTS", []),
            patch.object(overview, "_build_session_snapshot", return_value=snapshot),
            patch.object(overview, "perf_counter", side_effect=[0.0, .1, .2, .3, .4]),
            patch.object(overview.logging, "getLogger") as get_logger,
        ):
            overview.build_project_human_series(range_key="all")
            get_logger.assert_not_called()


if __name__ == "__main__":
    unittest.main()
