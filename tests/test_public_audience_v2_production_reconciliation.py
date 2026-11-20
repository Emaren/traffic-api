"""Fail-closed shared Production Reconciliation Gate Traffic-lane tests.

All observations are disposable fixtures, not production day certificates.
"""
from __future__ import annotations
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_production_reconciliation as gate

NOW = datetime(2026, 11, 20, 2, 23, tzinfo=timezone.utc)
LAST = "2026-10-19"


def source():
    return {
        "r0": 51387589, "max_rowid": 51449259,
        "new_rows": 61670, "new_clocked": 61670,
        "latest_inserted_utc": "2026-11-20T02:22:00+00:00",
        "historic_probe_rows": 1000, "historic_probe_retroclocked": 0,
        "prospective_day": "2026-11-20",
        "prospective_rows": 40138, "prospective_clocked": 40138,
        "certificate_ledger_present": False, "certificates": [],
        "private_published_rows": [
            ["2026-06-11", 1265, 9, 4],
            ["2026-10-19", 10695, 615, 283],
        ],
    }


def host():
    return {
        "units": {
            "traffic-ingest.timer": {"ActiveState": "active",
                                     "UnitFileState": "enabled"},
            "traffic-ingest.service": {
                "Environment": "PYTHONUNBUFFERED=1 TRAFFIC_INGEST_RECEIPTS_ENABLED=1",
                "ExecStart": "/usr/bin/flock -n -E 75 /run/traffic-ingest/sync.lock /var/www/Traffic/traffic-api/.venv/bin/python3 scripts/sync_traffic_logs.py"},
            "traffic-api.service": {
                "Environment": "TRAFFIC_DISABLE_INLINE_INGEST=1"},
            "traffic-v2-publisher.service": {
                "LoadState": "not-found", "User": ""},
            "traffic-v2-publisher.timer": {
                "LoadState": "not-found", "ActiveState": "inactive",
                "UnitFileState": "", "LastTriggerUSec": ""},
        },
        "financial_open_ports": [],
        "original_signed_unit_sha256": {
            "traffic-ingest.service": gate.SIGNED_LOADED_INGEST_SHA256,
            "traffic-ingest.timer": gate.SIGNED_ORIGINAL_TIMER_SHA256,
        },
        "publisher_config_present": False,
    }


def api():
    return {
        "traffic_api_website_parity": True,
        "historical_131_days_intact": True,
        "published_points": 2,
        "last_published_utc_day": LAST,
        "canonical_full_matrix_sha256": gate.matrix_sha({
            "2026-06-11": [1265, 9, 4],
            "2026-10-19": [10695, 615, 283],
        }),
    }


class TrafficProductionReconciliationGateTests(unittest.TestCase):
    def evaluate(self, s=None, h=None, web=None, browser=None, when=NOW):
        return gate.judge(s or source(), h or host(), web or api(),
                          now=when, browser_observation=browser)

    def test_http_200_archive_cannot_be_reported_healthy(self):
        r = self.evaluate()
        self.assertEqual(r["lane"], "TRAFFIC")
        self.assertEqual(r["status"], "FAIL")
        self.assertGreater(r["publication_lag_utc_days"], 20)
        self.assertTrue(any(x.startswith("public_graph_freshness:STALE_")
                            for x in r["failed_checks"]))
        self.assertIn("natural_ingestion_receipts", r["passed_checks"])
        self.assertTrue(r["other_product_lanes_may_ship"])

    def test_original_ingest_unit_hash_mismatch_fails(self):
        h = host()
        h["original_signed_unit_sha256"]["traffic-ingest.service"] = "0"*64
        r = self.evaluate(h=h)
        self.assertTrue(any(x.startswith("original_single_ingest_configuration:")
                            for x in r["failed_checks"]))

    def test_original_timer_unit_hash_mismatch_fails(self):
        h = host()
        h["original_signed_unit_sha256"]["traffic-ingest.timer"] = "f"*64
        r = self.evaluate(h=h)
        self.assertTrue(any(x.startswith("original_single_ingest_configuration:")
                            for x in r["failed_checks"]))

    def test_original_flock_removed_from_service_is_fatal(self):
        h = host()
        h["units"]["traffic-ingest.service"]["ExecStart"] = "python3 scripts/sync_traffic_logs.py"
        r = self.evaluate(h=h)
        self.assertTrue(any(x.startswith("original_single_ingest_configuration:")
                            for x in r["failed_checks"]))

    def test_missing_genuine_clock_fails_independently(self):
        s = source()
        s["new_clocked"] -= 1
        self.assertTrue(any(x.startswith("natural_ingestion_receipts:")
                            for x in self.evaluate(s=s)["failed_checks"]))

    def test_historical_retroclocking_always_fails(self):
        s = source()
        s["historic_probe_retroclocked"] = 1
        self.assertTrue(any(x.startswith("natural_ingestion_receipts:")
                            for x in self.evaluate(s=s)["failed_checks"]))

    def test_missing_ledger_is_not_forged_certificate(self):
        r = self.evaluate()
        self.assertTrue(any(x.startswith("complete_utc_day_proven:")
                            for x in r["failed_checks"]))
        self.assertEqual(r["certified_day_ids"], [])

    def test_missing_natural_publisher_timer_fails(self):
        r = self.evaluate()
        self.assertTrue(any(x.startswith("nonroot_unattended_publisher:")
                            for x in r["failed_checks"]))

    def test_finance_listener_and_inline_ingest_refused(self):
        h = host()
        h["financial_open_ports"] = [8092]
        h["units"]["traffic-api.service"]["Environment"] = ""
        r = self.evaluate(h=h)
        self.assertTrue(any(x.startswith("original_single_ingest_configuration:")
                            for x in r["failed_checks"]))

    def test_orphan_published_day_with_no_certificate_refused(self):
        s = source()
        s["private_published_rows"].append(["2026-11-20", 100, 5, 2])
        r = self.evaluate(s=s)
        self.assertTrue(any(x.startswith("certified_published_day_parity:")
                            for x in r["failed_checks"]))

    def test_public_parity_200_does_not_substitute_for_source(self):
        r = self.evaluate()
        self.assertTrue(r["both_api_matrices_exact"])
        self.assertNotEqual(r["status"], "PASS")

    def test_missing_chrome_witness_fails(self):
        r = self.evaluate()
        self.assertFalse(r["gap_renderer_browser_verified"])

    def test_fake_mismatched_graph_date_does_not_pass(self):
        b = {"status": "INDEPENDENT_REAL_CHROME_GAP_RENDERER_VERIFIED",
             "latest_utc_day": "2026-11-20",
             "observed_at_utc": NOW.isoformat()}
        r = self.evaluate(browser=b)
        self.assertFalse(r["gap_renderer_browser_verified"])

    def test_naive_ingestion_clock_denied(self):
        s = source()
        s["latest_inserted_utc"] = "2026-11-20T02:22:00"
        with self.assertRaisesRegex(ValueError, "CLOCK_NAIVE"):
            self.evaluate(s=s)

    def test_late_ingestion_clock_fails(self):
        s = source()
        s["latest_inserted_utc"] = "2026-11-20T02:00:00+00:00"
        self.assertTrue(any(x.startswith("natural_ingestion_receipts:")
                            for x in self.evaluate(s=s)["failed_checks"]))

    def test_all_fixture_scenarios_no_public_writes(self):
        result = self.evaluate()
        self.assertFalse(result["public_writes_performed_by_gate"])

    def test_fake_ledger_row_without_real_dual_signatures_not_admitted(self):
        s = source()
        s["certificate_ledger_present"] = True
        s["certificates"] = [["2026-11-20", "a"*64, "b"*64]]
        s["private_published_rows"].append(["2026-11-20", 100, 5, 2])
        r = self.evaluate(s=s)
        self.assertFalse(r["authentic_certificate_signatures_verified"])
        self.assertTrue(any(x.startswith("complete_utc_day_proven:")
                            for x in r["failed_checks"]))

    def test_api_to_private_matrix_hash_mismatch_is_p0(self):
        w = api()
        w["canonical_full_matrix_sha256"] = "0"*64
        r = self.evaluate(web=w)
        self.assertTrue(any(x.startswith("complete_public_api_parity:")
                            for x in r["failed_checks"]))

    def test_missing_live_owner_revocation_is_separate_failure(self):
        r = self.evaluate()
        self.assertFalse(r["owner_revocation_active_external_verified"])
        self.assertTrue(any(x.startswith("external_owner_revocation_trust:")
                            for x in r["failed_checks"]))

    def test_grace_then_next_day_expected_freshness_rolls_forward(self):
        early = self.evaluate(when=datetime(2026, 11, 22, 1, 15,
                                            tzinfo=timezone.utc))
        late = self.evaluate(when=datetime(2026, 11, 22, 3, 15,
                                           tzinfo=timezone.utc))
        self.assertEqual(early["freshness_target_after_hourly_grace_utc_day"],
                         "2026-11-20")
        self.assertEqual(late["freshness_target_after_hourly_grace_utc_day"],
                         "2026-11-21")
        self.assertEqual(late["status"], "FAIL")

    def test_read_only_cli_red_exit(self):
        with patch.object(gate, "check_once", return_value=self.evaluate()):
            self.assertEqual(gate.main(["--read-only-production"]), 2)


if __name__ == "__main__":
    unittest.main()
