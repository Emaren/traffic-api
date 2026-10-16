"""Stage-one independent ingestion worker and timer contracts.

This phase deliberately leaves all interactive API sync semantics unchanged.
"""
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import sync_traffic_logs


ROOT = Path(__file__).resolve().parents[1]


class TrafficIngestWorkerTests(unittest.TestCase):
    def test_success_preserves_existing_sync_engine_without_leaking_paths(self):
        with (
            patch.object(sync_traffic_logs, "persistence_enabled", return_value=True),
            patch.object(
                sync_traffic_logs,
                "sync_configured_logs_to_persistence",
                return_value=[
                    {"mode": "persisted", "inserted": 3, "offset": 99},
                    {"mode": "missing", "inserted": 0, "offset": 0},
                ],
            ) as sync,
            patch.object(sync_traffic_logs, "perf_counter", side_effect=[0.0, 2.5]),
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(sync_traffic_logs.main(), 0)
            sync.assert_called_once_with()
            self.assertIn("status=ok", output.getvalue())
            self.assertIn("persisted_sources=1", output.getvalue())
            self.assertIn("processed_rows=3", output.getvalue())
            self.assertNotIn("offset=", output.getvalue())

    def test_disabled_and_missing_logs_fail_visibly(self):
        with (
            patch.object(sync_traffic_logs, "persistence_enabled", return_value=False),
            patch.object(sync_traffic_logs, "sync_configured_logs_to_persistence") as sync,
        ):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(sync_traffic_logs.main(), 2)
            sync.assert_not_called()

        with (
            patch.object(sync_traffic_logs, "persistence_enabled", return_value=True),
            patch.object(
                sync_traffic_logs,
                "sync_configured_logs_to_persistence",
                return_value=[{"mode": "missing", "inserted": 0, "offset": 0}],
            ),
        ):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(sync_traffic_logs.main(), 2)

    def test_timer_is_bounded_and_not_enabled_by_code(self):
        service = (ROOT / "ops/systemd/traffic-ingest.service").read_text()
        timer = (ROOT / "ops/systemd/traffic-ingest.timer").read_text()
        self.assertIn("User=tony", service)
        self.assertIn("EnvironmentFile=/etc/traffic-api.env", service)
        self.assertIn("CPUQuota=50%", service)
        self.assertIn("MemoryMax=1024M", service)
        self.assertIn("TimeoutStartSec=600", service)
        self.assertIn("flock -n -E 75", service)
        self.assertIn("OnUnitInactiveSec=2min", timer)
        self.assertIn("Unit=traffic-ingest.service", timer)


if __name__ == "__main__":
    unittest.main()
