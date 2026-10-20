from __future__ import annotations

import json
import sqlite3
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_forward_ip_shadow as ip
from scripts import public_audience_v2_forward_ledger as forward


def make_db(schema: str) -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript(schema)
    return db


FUTURE_SCHEMA = """
CREATE TABLE future_events (
  source_rowid INTEGER PRIMARY KEY,
  event_json TEXT NOT NULL,
  timestamp TEXT NOT NULL
);
"""


class ForwardIpPassOneTests(unittest.TestCase):
    def setUp(self):
        self.source = make_db(FUTURE_SCHEMA)
        self.state = make_db(ip.SCHEMA)
        self.history = make_db("""
            CREATE TABLE ip_counts (
              host TEXT, ip TEXT, requests INT, direct_referrers INT,
              PRIMARY KEY(host,ip));
            CREATE TABLE ip_uas (
              host TEXT,ip TEXT,ua TEXT,PRIMARY KEY(host,ip,ua));
            CREATE TABLE ip_paths (
              host TEXT,ip TEXT,path TEXT,PRIMARY KEY(host,ip,path));
        """)
        self.addCleanup(self.source.close)
        self.addCleanup(self.state.close)
        self.addCleanup(self.history.close)
        self.meta = {"last_source_rowid": "0", "processed_inputs": "0"}
        self.mock_normalize = patch.object(
            ip.canonical, "normalize_row",
            side_effect=lambda raw, rules: {
                "timestamp_iso": raw["timestamp"],
                "host": raw["host"], "ip": raw["ip"],
                "ua": raw["ua"], "normalized_path": raw["normalized_path"],
                "referrer_host": raw["referrer_host"],
            },
        )
        self.mock_normalize.start()
        self.addCleanup(self.mock_normalize.stop)

    def event(self, rowid: int, *, ip_addr: str = "10.0.0.1",
              ua: str = "Mozilla", path: str = "/page", referrer: str = ""):
        data = {
            "source_rowid": rowid,
            "timestamp": "2026-10-20T04:00:00+00:00",
            "host": "aoe2war.com", "ip": ip_addr, "ua": ua,
            "normalized_path": path, "referrer_host": referrer,
        }
        self.source.execute(
            "INSERT INTO future_events VALUES (?,?,?)",
            (rowid, json.dumps(data), data["timestamp"]),
        )
        self.source.commit()

    def run_step(self, phase="LIVE", cap=3):
        return ip.future_step(
            self.source, self.state, self.meta, [],
            source_phase=phase, max_rows=cap,
        )

    def test_refuses_bootstrap_before_any_write(self):
        self.event(12)
        with self.assertRaisesRegex(RuntimeError, "BOOTSTRAP"):
            self.run_step(phase="BOOTSTRAP")
        self.assertEqual(self.state.execute(
            "SELECT COUNT(*) FROM ip_counts"
        ).fetchone()[0], 0)
        self.assertEqual(self.meta["last_source_rowid"], "0")

    def test_resume_counts_distinct_ua_and_paths_exactly(self):
        # Rows are stored out of insertion order but all were inserted
        # before LIVE. Sorting by source_rowid then is safe.
        self.event(300, ua="User-Agent2", path="/b", referrer="external")
        self.event(10, ua="Mozilla", path="/a")
        self.event(30, ua="Mozilla", path="/a")
        first = self.run_step(cap=2)
        self.assertEqual(first["total_input_events_processed"], 2)
        self.assertEqual(first["last_source_rowid"], 30)
        second = self.run_step(cap=2)
        self.assertEqual(second["total_input_events_processed"], 3)
        self.assertEqual(second["last_source_rowid"], 300)
        self.assertEqual(self.run_step(cap=2)["step_input_events"], 0)
        counts = self.state.execute(
            "SELECT requests,direct_referrers FROM ip_counts"
        ).fetchone()
        self.assertEqual(tuple(counts), (3, 2))
        self.assertEqual(self.state.execute(
            "SELECT COUNT(*) FROM ip_uas"
        ).fetchone()[0], 2)
        self.assertEqual(self.state.execute(
            "SELECT COUNT(*) FROM ip_paths"
        ).fetchone()[0], 2)

    def test_historical_baseline_and_new_distinct_sets_union(self):
        self.history.execute(
            "INSERT INTO ip_counts VALUES (?,?,?,?)",
            ("aoe2war.com", "10.0.0.1", 12, 3),
        )
        self.history.execute(
            "INSERT INTO ip_uas VALUES (?,?,?)",
            ("aoe2war.com", "10.0.0.1", "mozilla"),
        )
        self.history.execute(
            "INSERT INTO ip_paths VALUES (?,?,?)",
            ("aoe2war.com", "10.0.0.1", "/page"),
        )
        self.history.commit()
        self.event(2, ua="Mozilla", path="/page")
        self.event(3, ua="Edge", path="/other", referrer="referrer")
        self.run_step()
        merged = ip.merged_ip_behavior(
            self.history, self.state, "aoe2war.com", "10.0.0.1",
        )
        self.assertEqual(merged["request_count"], 14)
        self.assertEqual(merged["unique_uas"], 2)
        self.assertEqual(merged["unique_paths"], 2)
        self.assertEqual(merged["route_bundle_paths"], ["/other", "/page"])

    def test_future_only_ip_missing_from_old_baseline(self):
        self.event(2, ip_addr="10.0.0.8", ua="moz")
        self.run_step()
        merged = ip.merged_ip_behavior(
            self.history, self.state, "aoe2war.com", "10.0.0.8",
        )
        self.assertEqual(merged["request_count"], 1)
        self.assertEqual(merged["unique_uas"], 1)

    def test_fail_closed_on_mismatched_rowid(self):
        wrong = {
            "source_rowid": 12,
            "timestamp": "2026-10-20T04:00:00+00:00",
            "host": "aoe2war.com", "ip": "10.0.0.8",
            "ua": "Mozilla", "normalized_path": "/",
            "referrer_host": "",
        }
        self.source.execute(
            "INSERT INTO future_events VALUES (?,?,?)",
            (14, json.dumps(wrong), wrong["timestamp"]),
        )
        with self.assertRaisesRegex(RuntimeError, "rowid mismatch"):
            self.run_step()
        self.assertEqual(self.meta["processed_inputs"], "0")
        self.assertEqual(self.state.execute(
            "SELECT COUNT(*) FROM ip_counts"
        ).fetchone()[0], 0)

    def test_fail_closed_on_pre_historical_timestamp(self):
        self.event(2)
        self.source.execute(
            """UPDATE future_events
               SET event_json=json_set(event_json,'$.timestamp',?)
               WHERE source_rowid=2""",
            ("2026-10-19T23:59:00+00:00",),
        )
        with self.assertRaisesRegex(RuntimeError, "historical epoch"):
            self.run_step()
        self.assertEqual(self.meta["processed_inputs"], "0")

    def test_fail_closed_when_input_normalization_drifts(self):
        self.event(2)
        with patch.object(ip.canonical, "normalize_row", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "normalization drift"):
                self.run_step()
        self.assertEqual(self.meta["last_source_rowid"], "0")

    def test_strict_row_budget(self):
        with self.assertRaisesRegex(RuntimeError, "page size"):
            self.run_step(cap=10001)

    def test_ledger_identity_pins_policy_and_watermark(self):
        baseline = {
            "source": "/private/raw.db", "device": "1", "inode": "2",
            "hosts_sha256": "h", "rules_sha256": "r",
            "canonical_sha256": "c",
        }
        expected = ip.fresh_metadata(baseline, __import__("pathlib").Path("/private/ledger.db"))
        ip.validate_metadata(expected, expected)
        bad = {**expected, "rules_sha256": "tampered"}
        with self.assertRaisesRegex(RuntimeError, "rules_sha256"):
            ip.validate_metadata(bad, expected)
        with self.assertRaisesRegex(RuntimeError, "original_watermark"):
            ip.validate_metadata({**expected, "original_watermark": "0"}, expected)

    def test_report_does_not_authorize_public_write(self):
        self.event(1)
        output = self.run_step()
        self.assertFalse(output["publication_authorized"])
        self.assertFalse(output["daily_classification_ready"])
        self.assertTrue(output["private_ip_shadow_writes_only"])


if __name__ == "__main__":
    unittest.main()
