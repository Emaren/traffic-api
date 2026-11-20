"""Source-only Traffic V2 dual-authority day witness, invented-only fixtures."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import public_audience_v2_day_admission as admission
from scripts import public_audience_v2_paged_evidence as pages
from scripts.public_audience_v2_forward_ledger import RELEASE_SHA, FROZEN_WATERMARK


NOW = datetime(2026, 11, 18, 18, tzinfo=timezone.utc)


class TwoWitnessDayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("openssl") is None:
            raise RuntimeError("real independent signature verifier missing")
        cls.temp = tempfile.TemporaryDirectory(prefix="traffic-dual-keys-test-")
        cls.root = Path(cls.temp.name)
        cls.keys = []
        for i in range(2):
            priv = cls.root / ("fictional-role-" + str(i) + ".key")
            pub = cls.root / ("fictional-role-" + str(i) + ".pem")
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                            "-out", str(priv)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "pkey", "-in", str(priv),
                            "-pubout", "-out", str(pub)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cls.keys.append((priv, pub.read_bytes()))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def page(self, day="2026-11-17"):
        return {
            "day": day, "source_epoch_sha256": "a" * 64,
            "host_rules_sha256": "b" * 64,
            "snapshot_rowid": FROZEN_WATERMARK + 333,
            "forward_prefix_rowid": FROZEN_WATERMARK + 333,
            "last_key": [day+"T23:59:58+00:00", 300, FROZEN_WATERMARK+330],
            "pages": 2, "total_rows": 271,
            "missing_receipts": 0, "invalid_clocks": 0,
            "chain_sha256": "c" * 64, "source_prefix_exhausted": True,
        }

    def certificate(self, page, day="2026-11-17"):
        from datetime import date, timedelta
        next_day = (date.fromisoformat(day) + timedelta(days=1)).isoformat()
        return {
            "schema": admission.SCHEMA, "project_slug": "aoe2hdbets",
            "day": day, "historical_release_sha256": RELEASE_SHA,
            "source_epoch_sha256": page["source_epoch_sha256"],
            "host_rules_sha256": page["host_rules_sha256"],
            "page_state_sha256": admission.digest(admission.canonical(page)),
            "source_snapshot_rowid": page["snapshot_rowid"],
            "forward_prefix_rowid": page["forward_prefix_rowid"],
            "source_rows": page["total_rows"],
            "source_page_chain_sha256": page["chain_sha256"],
            "missing_insertion_receipts": page["missing_receipts"],
            "invalid_insertion_clocks": page["invalid_clocks"],
            "upstream_log_closed_through_utc": next_day+"T01:00:00+00:00",
            "writer_receipts_closed_through_utc": next_day+"T01:00:00+00:00",
            "global_ip_model_sha256": "d" * 64,
            "canonical_sessions_sha256": "e" * 64,
            "cross_midnight_carry_sha256": "f" * 64,
            "late_arrival_stability_sha256": "7" * 64,
            "total": 150, "potential": 40, "confirmed": 19,
        }

    def sign(self, body, which):
        private = self.keys[which][0]
        data = self.root / ("fictional-aggregate-" + str(which) + ".json")
        signature = self.root / ("fictional-aggregate-" + str(which) + ".sig")
        data.write_bytes(admission.canonical(body))
        subprocess.run(["openssl", "pkeyutl", "-sign",
                        "-inkey", str(private), "-rawin",
                        "-in", str(data), "-out", str(signature)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return base64.urlsafe_b64encode(signature.read_bytes()).decode().rstrip("=")

    def envelope(self, body):
        return {
            "certificate": body,
            "upstream_signature": self.sign(body, 0),
            "classifier_signature": self.sign(body, 1),
        }

    def verify(self, envelope, page, **change):
        params = dict(
            now=NOW, upstream_key=self.keys[0][1],
            classifier_key=self.keys[1][1],
            expected_upstream_key_sha256=hashlib.sha256(self.keys[0][1]).hexdigest(),
            expected_classifier_key_sha256=hashlib.sha256(self.keys[1][1]).hexdigest(),
        )
        return admission.verify_dual_witness(envelope, page, **{**params, **change})

    def assert_hold(self, envelope, page, reason):
        with self.assertRaisesRegex(ValueError, "TRAFFIC_V2_HOLD_" + reason):
            self.verify(envelope, page)

    def test_two_genuine_fixture_signatures_verify_but_do_not_authorize_public_writes(self):
        p = self.page()
        result = self.verify(self.envelope(self.certificate(p)), p)
        self.assertEqual(result["candidate_values"], [150, 40, 19])
        self.assertTrue(result["dual_witness_signatures_verified"])
        self.assertFalse(result["public_write_authorized"])
        self.assertFalse(result["day_physical_production_certified"])
        self.assertEqual(result["status"], "HOLD_INDEPENDENT_PRODUCTION_ADMISSION")

    def test_two_adjacent_signed_fixtures_not_two_production_day_certificates(self):
        p = self.page("2026-11-16")
        first = self.verify(self.envelope(self.certificate(p, "2026-11-16")), p)
        q = self.page()
        second = self.verify(self.envelope(self.certificate(q)), q)
        pair = admission.consecutive_candidates(first, second)
        self.assertEqual(pair["two_source_contract_days"],
                         ["2026-11-16", "2026-11-17"])
        self.assertFalse(pair["two_physical_production_days_certified"])
        q = self.page("2026-11-14")
        third = self.verify(self.envelope(self.certificate(q, "2026-11-14")), q)
        with self.assertRaisesRegex(ValueError, "DAYS_NOT_CONSECUTIVE"):
            admission.consecutive_candidates(third, second)

    def test_missing_insertion_receipt_blocks_regardless_of_two_valid_signers(self):
        p = self.page()
        p["missing_receipts"] = 1
        self.assert_hold(self.envelope(self.certificate(p)), p,
                         "INSERT_RECEIPTS_INCOMPLETE")

    def test_incomplete_page_or_unsettled_ledger_prefix_cannot_certify(self):
        p = self.page()
        p["source_prefix_exhausted"] = False
        self.assert_hold(self.envelope(self.certificate(p)), p,
                         "SOURCE_PAGES_INCOMPLETE")
        p = self.page()
        p["forward_prefix_rowid"] -= 1
        self.assert_hold(self.envelope(self.certificate(p)), p,
                         "UNSETTLED_FORWARD_PREFIX")

    def test_late_remote_delivery_closure_is_not_insertion_clock(self):
        p = self.page()
        c = self.certificate(p)
        c["upstream_log_closed_through_utc"] = "2026-11-18T00:05:00+00:00"
        self.assert_hold(self.envelope(c), p, "REMOTE_LOG_DELIVERY_NOT_CLOSED")
        c = self.certificate(p)
        c["writer_receipts_closed_through_utc"] = "2026-11-18T00:00:00+00:00"
        self.assert_hold(self.envelope(c), p, "INSERT_WRITER_NOT_CLOSED")

    def test_forged_aggregate_after_signing_refused(self):
        p = self.page()
        env = self.envelope(self.certificate(p))
        env["certificate"]["total"] += 1
        self.assert_hold(env, p, "INDEPENDENT_SIGNATURE_REFUSED")

    def test_wrong_key_and_cross_role_key_reuse_refused(self):
        p = self.page()
        env = self.envelope(self.certificate(p))
        self.assert_hold(env, p, "NONEXISTENT") if False else None
        with self.assertRaisesRegex(ValueError, "CROSS_ROLE_OR_FORGED_KEY"):
            self.verify(env, p, classifier_key=self.keys[0][1])
        with self.assertRaisesRegex(ValueError, "CROSS_ROLE_OR_FORGED_KEY"):
            self.verify(env, p, expected_classifier_key_sha256="f" * 64)
        env["classifier_signature"] = env["upstream_signature"]
        self.assert_hold(env, p, "INDEPENDENT_SIGNATURE_REFUSED")

    def test_changed_page_state_with_same_signatures_refused(self):
        p = self.page()
        env = self.envelope(self.certificate(p))
        p["total_rows"] += 1
        self.assert_hold(env, p, "SOURCE_PAGE_PREIMAGE_DRIFT")

    def test_changed_history_sha_or_public_authentication_not_accepted(self):
        p = self.page()
        c = self.certificate(p)
        c["historical_release_sha256"] = "0" * 64
        self.assert_hold(self.envelope(c), p, "ORIGINAL_131_DAY_RELEASE_DRIFT")
        env = self.envelope(self.certificate(p))
        env["publication_authorized"] = True
        self.assert_hold(env, p, "ENVELOPE_FIELD_DRIFT")

    def test_current_day_foreign_project_unknown_epoch_and_no_events_refused(self):
        p = self.page()
        c = self.certificate(p, "2026-11-18")
        p["day"] = "2026-11-18"
        c["page_state_sha256"] = admission.digest(admission.canonical(p))
        self.assert_hold(self.envelope(c), p,
                         "CURRENT_UNFINISHED_OR_HISTORIC_DAY")
        p = self.page()
        c = self.certificate(p)
        c["project_slug"] = "foreign"
        self.assert_hold(self.envelope(c), p, "ORIGINAL_131_DAY_RELEASE_DRIFT")
        p["total_rows"] = 0
        self.assert_hold(self.envelope(self.certificate(p)), p,
                         "INSERT_RECEIPTS_INCOMPLETE")

    def test_timestamp_and_metric_tricks_refused(self):
        p = self.page()
        for field, value, reason in (
            ("upstream_log_closed_through_utc", "2026-11-18T02:00:00-07:00",
             "NON_UTC_WITNESS_CLOCK"),
            ("total", True, "INVALID_AUDIENCE_COUNTER"),
            ("potential", 200, "NONCANONICAL_AUDIENCE_HIERARCHY"),
            ("confirmed", -1, "INVALID_AUDIENCE_COUNTER"),
        ):
            c = self.certificate(p)
            c[field] = value
            self.assert_hold(self.envelope(c), p, reason)


if __name__ == "__main__":
    unittest.main()
