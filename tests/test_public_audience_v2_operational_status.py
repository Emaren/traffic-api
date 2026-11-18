"""WE4 Traffic V2 public API continuity diagnostics, no network or private rows."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import copy
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_operational_status as status
from scripts.public_audience_v2_release_manifest import sha

NOW = datetime(2026, 11, 18, 14, 15, tzinfo=timezone.utc)


def endpoints(extra=None):
    all_days = []
    day = date(2026, 6, 11)
    while day <= date(2026, 10, 19):
        n = len(all_days)
        all_days.append({
            "date": day.isoformat(),
            "calculatedAt": "2026-10-20T21:36:55+00:00",
            "values": {"totalTraffic": 1000 + n,
                       "suspectedHuman": 200 + n,
                       "confirmedHuman": 50 + n}
        })
        day += timedelta(days=1)
    all_days.extend(extra or [])
    base = {
        "ok": True, "project_slug": "aoe2hdbets",
        "coverage_started_at": "2026-06-11",
        "coverage_ended_at": all_days[-1]["date"],
        "archive_calculated_at": "2026-10-20T21:36:55+00:00",
        "generated_at": NOW.isoformat(), "points": all_days,
    }
    website = {"ok": True, "points": copy.deepcopy(all_days)}
    history = {p["date"]: [p["values"][k] for k in
                         ("totalTraffic", "suspectedHuman", "confirmedHuman")]
               for p in all_days if p["date"] <= "2026-10-19"}
    return base, website, sha(history)


class TrafficStatusFixture(unittest.TestCase):
    def inspect(self, src, website, digest, *, now=NOW):
        with patch.object(status, "RELEASE_SHA", digest):
            return status.inspect(src, website, now=now)

    def test_exact_original_131_days_show_29_missing_unknown_not_zero(self):
        src, website, historic = endpoints()
        result = self.inspect(src, website, historic)
        self.assertEqual(result["published_points"], 131)
        self.assertEqual(result["last_certified_utc_day"], "2026-10-19")
        self.assertEqual(result["last_published_utc_day"], "2026-10-19")
        self.assertEqual(result["target_last_completed_utc_day"], "2026-11-17")
        self.assertEqual(result["uncertified_gap_count"], 29)
        self.assertEqual(result["missing_recent_completed_day_count"], 29)
        self.assertEqual(result["unknown_historical_gap_count"], 0)
        self.assertFalse(result["public_previous_completed_day_present"])
        self.assertEqual(result["public_publication_lag_days"], 29)
        self.assertEqual(result["status"],
                         "HOLD_PREVIOUS_COMPLETED_DAY_NOT_PUBLISHED")
        self.assertEqual(result["first_uncertified_day"], "2026-10-20")
        self.assertEqual(result["last_uncertified_day"], "2026-11-17")
        self.assertEqual(result["delay_reason"],
                         "MISSING_VERIFIED_INSERT_RECEIPTS_AND_UPSTREAM_DELIVERY")
        self.assertIsNone(result["last_source_ingestion"])
        self.assertIsNone(result["insertion_receipt_freshness"])
        self.assertFalse(result["public_writes"])
        self.assertFalse(result["source_permits_granted"])
        self.assertTrue(result["missing_days_not_filled_with_zero"])

    def test_later_certified_day_does_not_fabricate_unknown_intermediate_days(self):
        src, website, h = endpoints([{
            "date": "2026-11-17", "values": {
                "totalTraffic": 600, "suspectedHuman": 90, "confirmedHuman": 20}
        }])
        src["archive_calculated_at"] = NOW.isoformat()
        result = self.inspect(src, website, h)
        self.assertEqual(result["last_published_utc_day"], "2026-11-17")
        self.assertEqual(result["last_certified_utc_day"], "2026-10-19")
        self.assertFalse(result["new_day_certificates_independently_verified_here"])
        self.assertEqual(result["uncertified_gap_count"], 28)
        self.assertEqual(result["last_uncertified_day"], "2026-11-16")
        self.assertTrue(result["public_previous_completed_day_present"])
        self.assertEqual(result["missing_recent_completed_day_count"], 0)
        self.assertEqual(result["unknown_historical_gap_count"], 28)
        self.assertEqual(result["public_publication_lag_days"], 0)
        self.assertEqual(result["status"],
                         "PUBLIC_PREVIOUS_COMPLETED_DAY_PRESENT_CERTIFICATE_UNVERIFIED")
        self.assertEqual(result["delay_reason"],
                         "SOURCE_DAY_CERTIFICATE_NOT_INDEPENDENTLY_AUDITED_HERE")


    def test_new_previous_day_with_older_gap_is_current_not_backfill_blocked(self):
        fresh = [
            {"date": day, "values": {
                "totalTraffic": 600 + i,
                "suspectedHuman": 90 + i,
                "confirmedHuman": 20 + i}}
            for i, day in enumerate(("2026-11-16", "2026-11-17"))
        ]
        source, site, historic = endpoints(fresh)
        source["archive_calculated_at"] = NOW.isoformat()
        result = self.inspect(source, site, historic)
        self.assertEqual(result["published_points"], 133)
        self.assertEqual(result["last_published_utc_day"], "2026-11-17")
        self.assertEqual(result["public_publication_lag_days"], 0)
        self.assertTrue(result["public_previous_completed_day_present"])
        self.assertEqual(result["unknown_historical_gap_count"], 27)
        self.assertEqual(result["uncertified_gap_count"], 27)
        self.assertEqual(result["missing_recent_completed_day_count"], 0)
        self.assertEqual(result["unknown_historical_gap_days"][0], "2026-10-20")
        self.assertEqual(result["unknown_historical_gap_days"][-1], "2026-11-15")
        self.assertEqual(result["last_certified_utc_day"], "2026-10-19")
        self.assertFalse(result["new_day_certificates_independently_verified_here"])
        self.assertTrue(
            result["historical_unknown_does_not_block_prospective_publication"]
        )

    def test_previous_day_missing_is_real_lag_even_if_previous_day_before_it_present(self):
        source, site, historic = endpoints([{
            "date": "2026-11-16",
            "values": {
                "totalTraffic": 630, "suspectedHuman": 84,
                "confirmedHuman": 12}
        }])
        source["archive_calculated_at"] = NOW.isoformat()
        result = self.inspect(source, site, historic)
        self.assertEqual(result["last_published_utc_day"], "2026-11-16")
        self.assertEqual(result["public_publication_lag_days"], 1)
        self.assertEqual(result["missing_recent_completed_days"], ["2026-11-17"])
        self.assertEqual(result["unknown_historical_gap_count"], 27)
        self.assertEqual(result["delay_reason"],
                         "MISSING_VERIFIED_INSERT_RECEIPTS_AND_UPSTREAM_DELIVERY")
        self.assertEqual(result["status"],
                         "HOLD_PREVIOUS_COMPLETED_DAY_NOT_PUBLISHED")

    def test_mismatched_website_graph_refused(self):
        src, website, h = endpoints([{
            "date": "2026-11-17", "values": {
                "totalTraffic": 600, "suspectedHuman": 90, "confirmedHuman": 20}
        }])
        website["points"][-1]["values"]["totalTraffic"] += 1
        with self.assertRaisesRegex(ValueError, "WEBSITE_TRAFFIC_API_PARITY"):
            self.inspect(src, website, h)

    def test_original_archive_tampering_fails_digest(self):
        src, website, h = endpoints()
        src["points"][5]["values"]["confirmedHuman"] += 1
        website["points"][5]["values"]["confirmedHuman"] += 1
        with self.assertRaisesRegex(ValueError, "HISTORICAL_131_DAY_DIGEST_DRIFT"):
            self.inspect(src, website, h)

    def test_missing_duplicate_future_current_day_refused(self):
        src, website, h = endpoints()
        src["points"].pop(9)
        website["points"].pop(9)
        with self.assertRaisesRegex(ValueError, "PUBLIC_POINT_COUNT"):
            self.inspect(src, website, h)
        src, website, h = endpoints([{
            "date": "2026-11-18",
            "values": {"totalTraffic": 100, "suspectedHuman": 10,
                       "confirmedHuman": 5},
        }])
        with self.assertRaisesRegex(ValueError, "PUBLIC_DATES_NOT_STRICTLY"):
            self.inspect(src, website, h)

    def test_public_metadata_and_source_freshness_refused(self):
        src, website, h = endpoints()
        src["coverage_ended_at"] = "2026-10-20"
        with self.assertRaisesRegex(ValueError, "COVERAGE_METADATA"):
            self.inspect(src, website, h)
        src, website, h = endpoints()
        src["generated_at"] = "2026-11-17T14:00:00Z"
        with self.assertRaisesRegex(ValueError, "GENERATION_STALE"):
            self.inspect(src, website, h)
        src, website, h = endpoints()
        src["archive_calculated_at"] = "2026-11-19T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "ARCHIVE_CLOCK_FUTURE"):
            self.inspect(src, website, h)

    def test_counters_without_canonical_hierarchy_refused(self):
        src, website, h = endpoints()
        src["points"][-1]["values"]["suspectedHuman"] = 5000
        with self.assertRaisesRegex(ValueError, "CANONICAL_AUDIENCE_HIERARCHY"):
            self.inspect(src, website, h)
        src, website, h = endpoints()
        src["points"][-1]["values"]["totalTraffic"] = True
        with self.assertRaisesRegex(ValueError, "CANONICAL_AUDIENCE_HIERARCHY"):
            self.inspect(src, website, h)

    def test_exact_source_identity_and_allowlisted_public_only(self):
        src, website, h = endpoints()
        src["project_slug"] = "other"
        with self.assertRaisesRegex(ValueError, "CANONICAL_SOURCE_PROJECT_DRIFT"):
            self.inspect(src, website, h)
        with self.assertRaisesRegex(ValueError, "OUTBOUND_ENDPOINT_NOT_ALLOWLISTED"):
            status.get_json("http://127.0.0.1:9999/private-unsafe")

    def test_an_uninstrumented_remote_source_is_not_implicitly_caught_up(self):
        src, website, h = endpoints()
        got = self.inspect(src, website, h)
        self.assertEqual(got["publisher_health"], "NOT_VERIFIED_FROM_ROOT")
        self.assertFalse(got["independent_remote_delivery_finality"])
        self.assertFalse(got["canonical_classifier_parity_finality"])
        self.assertEqual(len(got["uncertified_utc_days"]), 29)


if __name__ == "__main__":
    unittest.main()
