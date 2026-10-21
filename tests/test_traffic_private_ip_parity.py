from __future__ import annotations

import json
import sqlite3
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_forward_ip_parity as verifier
from scripts import public_audience_v2_forward_ip_shadow as shadow_module


class PrivateIpParityTests(unittest.TestCase):
    def setUp(self):
        self.ledger = sqlite3.connect(":memory:")
        self.ledger.execute(
            "CREATE TABLE future_events (source_rowid INTEGER PRIMARY KEY,"
            "event_json TEXT NOT NULL,timestamp TEXT NOT NULL)"
        )
        self.shadow = sqlite3.connect(":memory:")
        self.shadow.executescript(shadow_module.SCHEMA)
        sample = dict(source_rowid=10, timestamp="2026-10-20T12:00:00+00:00",
                      host="aoe2war.com", ip="fixture-ip",
                      ua="Mozilla", normalized_path="/game", referrer_host="")
        self.ledger.execute("INSERT INTO future_events VALUES (?,?,?)",
                            (10, json.dumps(sample), sample["timestamp"]))
        self.shadow.executemany("INSERT INTO shadow_metadata VALUES (?,?)",
                                [("last_source_rowid", "10"),
                                 ("processed_inputs", "1")])
        self.shadow.execute("INSERT INTO ip_counts VALUES (?,?,?,?)",
                            ("aoe2war.com", "fixture-ip", 1, 1))
        self.shadow.execute("INSERT INTO ip_uas VALUES (?,?,?)",
                            ("aoe2war.com", "fixture-ip", "mozilla"))
        self.shadow.execute("INSERT INTO ip_paths VALUES (?,?,?)",
                            ("aoe2war.com", "fixture-ip", "/game"))
        self.ledger.commit()
        self.shadow.commit()
        self.addCleanup(self.ledger.close)
        self.addCleanup(self.shadow.close)
        normalizer = patch.object(
            verifier.canonical, "normalize_row",
            side_effect=lambda x, rules: {
                "timestamp_iso": x["timestamp"], "host": x["host"],
                "ip": x["ip"], "ua": x["ua"],
                "normalized_path": x["normalized_path"],
                "referrer_host": x["referrer_host"],
            },
        )
        normalizer.start()
        self.addCleanup(normalizer.stop)

    def check(self, cap=3):
        return verifier.compare(self.ledger, self.shadow, rules=[],
                                max_events=cap)

    def test_exact_private_canonical_parity_no_identifiers(self):
        result = self.check()
        self.assertEqual(result["source_events_compared"], 1)
        self.assertEqual(result["private_distinct_uas_compared"], 1)
        self.assertEqual(result["private_distinct_paths_compared"], 1)
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["daily_session_parity_certified"])
        self.assertNotIn("fixture-ip", json.dumps(result))

    def test_count_drift_fails(self):
        self.shadow.execute("UPDATE ip_counts SET requests=2")
        with self.assertRaisesRegex(RuntimeError, "per-actor counts"):
            self.check()

    def test_direct_referrer_drift_fails(self):
        self.shadow.execute("UPDATE ip_counts SET direct_referrers=0")
        with self.assertRaisesRegex(RuntimeError, "per-actor counts"):
            self.check()

    def test_extra_unique_ua_fails(self):
        self.shadow.execute("INSERT INTO ip_uas VALUES (?,?,?)",
                            ("aoe2war.com", "fixture-ip", "other"))
        with self.assertRaisesRegex(RuntimeError, "UA evidence"):
            self.check()

    def test_missing_path_fails(self):
        self.shadow.execute("DELETE FROM ip_paths")
        with self.assertRaisesRegex(RuntimeError, "distinct path"):
            self.check()

    def test_missing_actor_fails(self):
        self.shadow.execute("DELETE FROM ip_counts")
        with self.assertRaisesRegex(RuntimeError, "missing actor"):
            self.check()

    def test_count_prefix_mismatch_fails(self):
        self.shadow.execute("UPDATE shadow_metadata SET value='0'"
                            " WHERE key='processed_inputs'")
        with self.assertRaisesRegex(RuntimeError, "prefix and shadow"):
            self.check()

    def test_budget_cannot_be_bypassed(self):
        with self.assertRaisesRegex(RuntimeError, "row budget"):
            self.check(cap=0)

    def test_normalization_drift_fails(self):
        with patch.object(verifier.canonical, "normalize_row", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "no longer canonical"):
                self.check()


if __name__ == "__main__":
    unittest.main()
