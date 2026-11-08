"""Adversarial proof of bounded read-only canonical public-audience stale detection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT / "scripts/public_audience_v2_publication_freshness.py"
spec = importlib.util.spec_from_file_location("public_age", CODE)
assert spec and spec.loader
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)

NOW = datetime(2026, 11, 8, 2, 40, 0, tzinfo=timezone.utc)


def valid_payload(last="2026-11-07"):
    day = datetime.fromisoformat(last + "T00:00:00+00:00")
    first = day - timedelta(days=2)
    points = []
    for n in range(3):
        when = first + timedelta(days=n)
        points.append({
            "date": when.date().isoformat(),
            "calculatedAt": (when + timedelta(days=1, hours=1)).isoformat(),
            "values": {"totalTraffic": 100+n, "suspectedHuman": 25+n,
                       "confirmedHuman": 8+n},
        })
    return {
        "ok": True, "project_slug": "aoe2hdbets",
        "coverage_started_at": points[0]["date"],
        "coverage_ended_at": points[-1]["date"],
        "archive_calculated_at": points[-1]["calculatedAt"],
        "generated_at": NOW.isoformat(), "points": points,
    }


class TestAgeClassification(unittest.TestCase):
    def test_current_completed_day_is_observation_not_certification(self):
        result = observer.inspect_payload(valid_payload(), NOW)
        self.assertEqual(result["status"], "OBSERVED_CANONICAL_ARCHIVE_AGE_WITHIN_LIMIT")
        self.assertEqual(result["age_utc_days"], 1)
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["historical_classification_certified_by_this_observer"])
        self.assertFalse(result["late_ingestion_bound_proven"])

    def test_one_day_lag_allowed(self):
        result = observer.inspect_payload(valid_payload("2026-11-06"), NOW)
        self.assertFalse(result["archive_is_stale"])
        self.assertEqual(result["age_utc_days"], 2)

    def test_three_day_lag_holds(self):
        result = observer.inspect_payload(valid_payload("2026-11-05"), NOW)
        self.assertEqual(result["status"], "HOLD_CANONICAL_ARCHIVE_STALE")
        self.assertEqual(result["age_utc_days"], 3)

    def test_real_october_19_is_twenty_days_old(self):
        result = observer.inspect_payload(valid_payload("2026-10-19"), NOW)
        self.assertEqual(result["status"], "HOLD_CANONICAL_ARCHIVE_STALE")
        self.assertEqual(result["age_utc_days"], 20)
        self.assertFalse(result["remote_log_delivery_finality_proven"])

    def test_bogus_project_identity_holds(self):
        data = valid_payload()
        data["project_slug"] = "other"
        with self.assertRaisesRegex(observer.Hold, "UNTRUSTED_CANONICAL_PROJECT"):
            observer.inspect_payload(data, NOW)

    def test_no_rows_never_became_zero_sessions(self):
        data = valid_payload()
        data["points"] = []
        data["coverage_started_at"] = None
        data["coverage_ended_at"] = None
        with self.assertRaisesRegex(observer.Hold, "UNPUBLISHED"):
            observer.inspect_payload(data, NOW)

    def test_current_day_is_not_completed(self):
        data = valid_payload("2026-11-08")
        data["archive_calculated_at"] = NOW.isoformat()
        with self.assertRaisesRegex(observer.Hold, "PARTIAL_CURRENT"):
            observer.inspect_payload(data, NOW)

    def test_future_timestamp_refused(self):
        data = valid_payload()
        data["archive_calculated_at"] = "2026-11-20T00:00:00+00:00"
        with self.assertRaisesRegex(observer.Hold, "PUBLISHED_TIMESTAMP_IN_FUTURE"):
            observer.inspect_payload(data, NOW)

    def test_stale_origin_generation_clock_holds(self):
        data = valid_payload()
        data["generated_at"] = "2026-11-07T02:40:00Z"
        with self.assertRaisesRegex(observer.Hold, "GENERATION_CLOCK_UNTRUSTED"):
            observer.inspect_payload(data, NOW)

    def test_missing_point_metadata_holds(self):
        data = valid_payload()
        data["coverage_ended_at"] = "2026-10-19"
        with self.assertRaisesRegex(observer.Hold, "METADATA_CONTRADICTS_ROWS"):
            observer.inspect_payload(data, NOW)

    def test_duplicate_days_holds(self):
        data = valid_payload()
        data["points"][1]["date"] = data["points"][0]["date"]
        with self.assertRaisesRegex(observer.Hold, "MISSING_DUPLICATED_OR_REORDERED"):
            observer.inspect_payload(data, NOW)

    def test_missing_middle_day_holds(self):
        data = valid_payload()
        data["points"].pop(1)
        with self.assertRaisesRegex(observer.Hold, "MISSING_DUPLICATED_OR_REORDERED"):
            observer.inspect_payload(data, NOW)

    def test_negative_counts_holds(self):
        data = valid_payload()
        data["points"][0]["values"]["totalTraffic"] = -1
        with self.assertRaisesRegex(observer.Hold, "INVALID_CANONICAL_AUDIENCE_COUNT"):
            observer.inspect_payload(data, NOW)

    def test_bool_counts_holds(self):
        data = valid_payload()
        data["points"][0]["values"]["totalTraffic"] = True
        with self.assertRaisesRegex(observer.Hold, "INVALID_CANONICAL_AUDIENCE_COUNT"):
            observer.inspect_payload(data, NOW)

    def test_human_greater_than_total_holds(self):
        data = valid_payload()
        data["points"][0]["values"]["confirmedHuman"] = 200
        with self.assertRaisesRegex(observer.Hold, "CANONICAL_HIERARCHY_VIOLATION"):
            observer.inspect_payload(data, NOW)

    def test_unpublished_partial_last_day_holds(self):
        data = valid_payload()
        data["points"][-1]["calculatedAt"] = data["points"][-1]["date"] + "T08:10:00Z"
        with self.assertRaisesRegex(observer.Hold, "UNCERTIFIED_OR_FUTURE_DAY"):
            observer.inspect_payload(data, NOW)

    def test_unbounded_response_row_count_holds(self):
        data = valid_payload()
        data["points"] = [{}] * (observer.MAX_POINTS+1)
        with self.assertRaisesRegex(observer.Hold, "ARCHIVE_SIZE"):
            observer.inspect_payload(data, NOW)

    def test_timer_held_expected_state(self):
        text = "LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n"
        with patch.object(observer.subprocess, "check_output", return_value=text) as cmd:
            value = observer.legacy_timer_status()
        self.assertEqual(value["legacy_full_history_forge_timer"],
                         "INACTIVE_DISABLED_INTENTIONAL_HOLD")
        arguments = cmd.call_args.args[0]
        self.assertEqual(arguments[0], "/usr/bin/systemctl")
        self.assertEqual(arguments[1], "show")
        self.assertNotIn("start", arguments)

    def test_timer_unexpected_reactivation_refused(self):
        text = "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"
        with patch.object(observer.subprocess, "check_output", return_value=text):
            with self.assertRaisesRegex(observer.Hold, "LEGACY_FULL_HISTORY_FORGE_TIMER_NOT_HELD"):
                observer.legacy_timer_status()

    def test_restricted_loopback_only_and_no_mutation(self):
        source = CODE.read_text()
        self.assertEqual(observer.PUBLIC_LOOPBACK_URL,
                         "http://127.0.0.1:3345/api/projects/aoe2hdbets/public-audience-series")
        for forbidden in ("systemctl start", "systemctl restart", "sqlite3.connect",
                          "DELETE FROM", "INSERT INTO", "UPDATE traffic_",
                          "8092", "8093", "8094", "8095",
                          "subprocess.Popen", "os.system(", "os.kill("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
