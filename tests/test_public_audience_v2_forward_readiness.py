from __future__ import annotations

import unittest

from scripts import public_audience_v2_forward_readiness as reader
from scripts import public_audience_v2_forward_ledger as forward


class PrivateForwardReadinessTests(unittest.TestCase):
    def setUp(self):
        self.meta = {
            "phase": "BOOTSTRAP",
            "captured": "9000",
            "accepted": "9000",
            "live_rowid": str(forward.FROZEN_WATERMARK),
            "original_watermark": str(forward.FROZEN_WATERMARK),
        }
        self.options = {
            "retained": 9000,
            "source_max_rowid": forward.FROZEN_WATERMARK + 100_000,
            "earliest_private_day": "2026-10-20",
            "last_private_day": "2026-10-20",
        }

    def test_bootstrap_cannot_be_mistaken_for_publishable_day(self):
        data = reader.report(self.meta, **self.options)
        self.assertEqual(data["result"], "PRIVATE_FORWARD_INTEGRITY_VERIFIED")
        self.assertFalse(data["bootstrap_finished"])
        self.assertIsNone(data["unscanned_rowid_span_upper_bound"])
        self.assertEqual(data["canonical_events_retained"], 9000)
        self.assertFalse(data["canonical_day_classification_ready"])
        self.assertFalse(data["utc_day_completeness_certified"])
        self.assertFalse(data["publication_authorized"])
        self.assertEqual(data["ready_to_publish_days"], [])

    def test_live_reports_rowid_span_only_not_event_backlog(self):
        self.meta["phase"] = "LIVE"
        self.meta["live_rowid"] = str(forward.FROZEN_WATERMARK + 12)
        data = reader.report(self.meta, **self.options)
        self.assertTrue(data["bootstrap_finished"])
        self.assertEqual(data["unscanned_rowid_span_upper_bound"], 99988)
        self.assertFalse(data["publication_authorized"])

    def test_rejects_private_missing_events(self):
        with self.assertRaisesRegex(RuntimeError, "retention/cursor"):
            reader.report(self.meta, **{**self.options, "retained": 8999})

    def test_rejects_source_rowid_retreat(self):
        with self.assertRaisesRegex(RuntimeError, "source rowid ceiling"):
            reader.report(
                self.meta,
                **{**self.options, "source_max_rowid": forward.FROZEN_WATERMARK - 1},
            )

    def test_rejects_bootstrap_cursor_advance(self):
        self.meta["live_rowid"] = str(forward.FROZEN_WATERMARK + 2)
        with self.assertRaisesRegex(RuntimeError, "bootstrap unexpectedly"):
            reader.report(self.meta, **self.options)

    def test_rejects_bogus_date_boundary(self):
        with self.assertRaisesRegex(RuntimeError, "date boundaries"):
            reader.report(
                self.meta,
                **{**self.options, "earliest_private_day": "2026-10-19"},
            )

    def test_empty_ledger_is_provisional_not_ready(self):
        self.meta["captured"] = "0"
        self.meta["accepted"] = "0"
        data = reader.report(
            self.meta,
            retained=0,
            source_max_rowid=forward.FROZEN_WATERMARK + 1,
            earliest_private_day=None,
            last_private_day=None,
        )
        self.assertEqual(data["canonical_events_retained"], 0)
        self.assertFalse(data["publication_authorized"])

    def test_stable_pinned_checksum_reported(self):
        data = reader.report(self.meta, **self.options)
        self.assertEqual(
            data["sealed_historical_public_sha256"],
            "84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4",
        )


if __name__ == "__main__":
    unittest.main()
