from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.services.traffic import performance


class PerformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.original_db_path = performance.PERFORMANCE_DB_PATH
        self.original_schema_ready = performance._SCHEMA_READY
        self.original_last_retention_run = performance._LAST_RETENTION_RUN
        performance.PERFORMANCE_DB_PATH = Path(self.tmp.name) / "traffic-test.sqlite3"
        performance._SCHEMA_READY = False
        performance._LAST_RETENTION_RUN = 0.0

    def tearDown(self) -> None:
        performance.PERFORMANCE_DB_PATH = self.original_db_path
        performance._SCHEMA_READY = self.original_schema_ready
        performance._LAST_RETENTION_RUN = self.original_last_retention_run
        self.tmp.cleanup()

    def _sample(self, **overrides):
        sample = {
            "sample_id": "SPD_SAMPLE_0001",
            "occurred_at": "2026-07-19T13:00:00+00:00",
            "host": "aoe2war.com",
            "route": "/contact-emaren?user=SECRET_USER",
            "build_version": "9246b85",
            "traffic_visitor_id": "visitor-1",
            "traffic_session_id": "session-1",
            "journey_session_id": "journey-1",
            "user_uid": "user-uid-1",
            "user_display_name": "Jim",
            "navigation_kind": "internal",
            "navigation_start_source": "link_click",
            "ready_source": "route_paint",
            "ready_ms": 420.5,
            "ttfb_ms": 90.2,
            "lcp_ms": 610.0,
            "valid_for_aggregation": True,
            "details": {
                "top_resources": [
                    {
                        "name": "https://aoe2war.com/api/rivalries?token=TOP_SECRET",
                        "duration_ms": 3210.0,
                        "transfer_bytes": 1234,
                        "initiator_type": "fetch",
                    }
                ],
                "top_api_requests": [
                    {
                        "name": "/api/rivalries?user=PRIVATE",
                        "duration_ms": 3210.0,
                    }
                ],
            },
        }
        sample.update(overrides)
        return sample

    def test_sample_ingest_is_idempotent_and_strips_query_strings(self) -> None:
        result = performance.record_performance_sample(self._sample())
        self.assertTrue(result["ok"])
        self.assertEqual(result["route"], "/contact-emaren")

        performance.record_performance_sample(
            self._sample(
                ready_ms=None,
                lcp_ms=777.0,
                inp_ms=42.0,
                user_display_name="",
            )
        )

        stored = performance.get_performance_sample("SPD_SAMPLE_0001")
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored["route"], "/contact-emaren")
        self.assertEqual(stored["ready_ms"], 420.5)
        self.assertEqual(stored["lcp_ms"], 777.0)
        self.assertEqual(stored["inp_ms"], 42.0)
        self.assertEqual(stored["user_display_name"], "Jim")

        encoded = str(stored["details"])
        self.assertNotIn("TOP_SECRET", encoded)
        self.assertNotIn("PRIVATE", encoded)
        self.assertEqual(
            stored["details"]["top_resources"][0]["name"],
            "/api/rivalries",
        )
        self.assertEqual(
            stored["details"]["top_api_requests"][0]["name"],
            "/api/rivalries",
        )

    def test_overview_computes_percentiles_and_route_groups(self) -> None:
        for index, ready in enumerate((100.0, 200.0, 300.0, 400.0), start=1):
            performance.record_performance_sample(
                self._sample(
                    sample_id=f"SPD_SAMPLE_000{index}",
                    route=f"/challenge/{index}",
                    ready_ms=ready,
                    lcp_ms=ready + 100,
                )
            )

        overview = performance.build_performance_overview(
            project_slug="aoe2hdbets",
            since_hours=24,
        )
        self.assertEqual(overview["samples"], 4)
        self.assertEqual(overview["metrics"]["ready_ms"]["p50"], 250.0)
        self.assertEqual(overview["metrics"]["ready_ms"]["p75"], 325.0)
        challenge = next(
            row for row in overview["routes"] if row["route_group"] == "/challenge/:id"
        )
        self.assertEqual(challenge["samples"], 4)

    def test_speed_report_lifecycle(self) -> None:
        performance.record_performance_sample(self._sample())
        created = performance.create_speed_report(
            {
                "report_id": "SPD-RPT-ABC123",
                "sample_id": "SPD_SAMPLE_0001",
                "host": "aoe2war.com",
                "route": "/rivalries?user=SECRET",
                "build_version": "9246b85",
                "user_uid": "user-uid-1",
                "user_display_name": "Jim",
                "diagnostic_snapshot": {
                    "note": "Felt slow",
                    "ready_ms": 4100,
                    "slowest_api_path": "/api/rivalries?token=SECRET_TOKEN",
                    "slowest_api_ms": 3210,
                },
                "recent_sample_ids": ["SPD_SAMPLE_0001"],
            }
        )
        self.assertEqual(created["status"], "open")

        report = performance.get_speed_report("SPD-RPT-ABC123")
        self.assertIsNotNone(report)
        assert report is not None
        self.assertEqual(report["route"], "/rivalries")
        self.assertEqual(report["diagnostic_snapshot"]["slowest_api_path"], "/api/rivalries")
        self.assertNotIn("SECRET_TOKEN", str(report))

        updated = performance.update_speed_report_status("SPD-RPT-ABC123", "resolved")
        self.assertEqual(updated["status"], "resolved")
        self.assertIsNotNone(updated["resolved_at"])


if __name__ == "__main__":
    unittest.main()

