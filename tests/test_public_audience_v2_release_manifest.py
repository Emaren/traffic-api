from __future__ import annotations

import copy
import unittest
from datetime import date, timedelta

from scripts import public_audience_v2_release_manifest as release


class ReleaseManifestQualificationTests(unittest.TestCase):
    def setUp(self):
        days = release.days_between(
            date(2026, 6, 11), date(2026, 10, 20),
        )
        self.assertEqual(len(days), 131)
        self.daily = {"2026-06-10": [987, 13, 6]}
        self.daily.update({day: [2, 1, 1] for day in days})
        self.legacy = {"2026-06-09": [90, 3, 1],
                       "2026-06-10": [2939, 21, 9]}
        self.legacy.update({
            day: self.daily[day] for day in days
            if day <= "2026-10-14"
        })
        self.assertEqual(len(self.legacy), 128)

    def test_manifest_excludes_partial_day_and_early_missing_interval(self):
        report = release.qualify(self.daily, self.legacy)
        self.assertEqual(report["status"], "CANDIDATE_ONLY")
        self.assertEqual(report["full_day_count"], 131)
        self.assertEqual(report["first_full_day"], "2026-06-11")
        self.assertEqual(report["last_full_day"], "2026-10-19")
        self.assertEqual(report["excluded_incomplete_day"], "2026-06-10")
        self.assertEqual(report["unavailable_prior_interval"],
                         ["2026-05-22", "2026-06-09"])
        self.assertEqual(report["legacy_full_day_compared"], 125)
        self.assertEqual(report["full_day_totals"], [262, 131, 131])
        self.assertNotIn("2026-06-10", report["candidate_daily"])

    def test_existing_legacy_mismatch_outside_boundary_is_blocked(self):
        legacy = copy.deepcopy(self.legacy)
        legacy["2026-08-02"][0] += 1
        with self.assertRaisesRegex(RuntimeError, "legacy discrepancy"):
            release.qualify(self.daily, legacy)

    def test_missing_or_extra_day_refused_not_zero_filled(self):
        missing = copy.deepcopy(self.daily)
        missing.pop("2026-09-18")
        with self.assertRaisesRegex(RuntimeError, "dates or gaps"):
            release.qualify(missing, self.legacy)
        extra = copy.deepcopy(self.daily)
        extra["2026-10-20"] = [1, 0, 0]
        with self.assertRaisesRegex(RuntimeError, "dates or gaps"):
            release.qualify(extra, self.legacy)

    def test_hierarchy_zero_and_incomplete_rejected(self):
        for day, values in [
            ("2026-06-11", [2, 3, 1]),
            ("2026-06-12", [0, 0, 0]),
            ("2026-10-19", [1, 1, 2]),
        ]:
            invalid = copy.deepcopy(self.daily)
            invalid[day] = values
            with self.assertRaisesRegex(RuntimeError, "invalid full-day"):
                release.qualify(invalid, self.legacy)

    def test_changed_old_baseline_is_blocked(self):
        legacy = copy.deepcopy(self.legacy)
        legacy.pop("2026-06-09")
        with self.assertRaisesRegex(RuntimeError, "legacy"):
            release.qualify(self.daily, legacy)


if __name__ == "__main__":
    unittest.main()
