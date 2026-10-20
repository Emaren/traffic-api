from __future__ import annotations

import unittest
import sqlite3
from unittest.mock import patch

from scripts import public_audience_v2_parity as parity


class ParityRulesTests(unittest.TestCase):
    def test_equal_historical_rows_except_last_suspect_bucket_are_comparable(self):
        dates=[f"2026-10-{d:02d}" for d in range(1,13)]
        old={day:[100,60,30] for day in dates}
        shadow={day:[100,60,30] for day in dates}
        shadow[dates[-1]]=[1000,600,300]
        shadow["2026-10-13"]=[1110,777,300]
        result=parity.compare_history(shadow,old)
        self.assertEqual(result["status"],"MATCH")
        self.assertEqual(result["compared"],11)
        self.assertTrue(result["shadow_has_legacy_last_day"])
        self.assertEqual(result["new_day_count"],1)

    def test_historical_mismatch_cannot_be_excused_as_trailing_partial_day(self):
        old={f"2026-10-{d:02d}":[100,60,30] for d in range(1,13)}
        shadow=dict(old)
        shadow["2026-10-07"]=[0,0,0]
        result=parity.compare_history(shadow,old)
        self.assertEqual(result["status"],"BLOCKED")
        self.assertEqual(result["mismatch_days"],["2026-10-07"])

    def test_small_legacy_baseline_is_not_authority(self):
        result=parity.compare_history({"2026-10-01":[1,1,1]},{
            "2026-10-01":[1,1,1]})
        self.assertEqual(result["status"],"BLOCKED")
        self.assertEqual(result["compared"],0)

    def test_invalid_shadow_hierarchy_rejected(self):
        old={f"2026-10-{d:02d}":[100,60,30] for d in range(1,13)}
        shadow=dict(old)
        shadow["2026-10-13"]=[3,4,2]
        result=parity.compare_history(shadow,old)
        self.assertEqual(result["status"],"BLOCKED")
        self.assertIn("2026-10-13",result["hierarchy_violations"])


class LateEligibleSourceTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("""
            CREATE TABLE traffic_entries (
                event_id TEXT, timestamp TEXT, ip TEXT, line_offset INTEGER,
                raw_path TEXT, normalized_path TEXT, referrer_host TEXT,
                ua TEXT, host TEXT
            )
        """)

    def tearDown(self):
        self.db.close()

    def add(self, day, host="aoe2war.com", path="/eligible"):
        self.db.execute(
            """INSERT INTO traffic_entries
               (event_id,timestamp,ip,line_offset,raw_path,normalized_path,
                referrer_host,ua,host)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            ("id", day + "T12:00:00+00:00", "127.0.0.1", 1,
             path, path, "", "Mozilla/5.0", host),
        )

    @staticmethod
    def canonical_normalizer(row, *, rules):
        return None if row["raw_path"] == "/hidden" else {"accepted": True}

    def check(self, *, max_candidates=100_000):
        return parity.has_late_eligible_source_rows(
            self.db, start="2026-05-22T00:00:00+00:00",
            end="2026-10-20T00:00:00+00:00", watermark=1,
            hosts=["aoe2war.com"], rules=[],
            max_candidates=max_candidates,
        )

    def test_other_projects_outside_window_and_hidden_events_do_not_block(self):
        self.add("2026-10-19")  # Original in-window row at frozen watermark.
        self.add("2026-10-19", "unrelated.example")
        self.add("2026-10-20")  # Current UTC day is outside frozen history.
        self.add("2026-05-21")  # Before historical start.
        self.add("2026-10-19", path="/hidden")
        with patch.object(parity.canonical, "normalize_row",
                          side_effect=self.canonical_normalizer):
            self.assertFalse(self.check())
            self.add("2026-10-19")
            self.assertTrue(self.check())

    def test_late_candidate_scan_budget_fails_closed(self):
        self.add("2026-10-18")
        self.add("2026-10-19", path="/hidden")
        self.add("2026-10-19", path="/hidden")
        with patch.object(parity.canonical, "normalize_row",
                          side_effect=self.canonical_normalizer):
            with self.assertRaisesRegex(RuntimeError, "budget exceeded"):
                self.check(max_candidates=1)

    def test_late_arrival_scan_forces_rowid_seek_with_timestamp_index_present(self):
        self.db.execute(
            "CREATE INDEX idx_traffic_entries_timestamp_line_offset "
            "ON traffic_entries(timestamp,line_offset)"
        )
        self.db.execute(
            "CREATE INDEX idx_traffic_entries_host_timestamp "
            "ON traffic_entries(host,timestamp)"
        )
        self.add("2026-06-01")
        self.add("2026-10-19")
        plan = [
            str(row[3]) for row in self.db.execute(
                "EXPLAIN QUERY PLAN "
                + parity.late_arrival_seek_sql(["aoe2war.com"]),
                (1, "2026-05-22T00:00:00+00:00",
                 "2026-10-20T00:00:00+00:00", "aoe2war.com"),
            )
        ]
        self.assertTrue(
            any("INTEGER PRIMARY KEY" in step and "rowid>?" in step.lower()
                for step in plan),
            plan,
        )
        self.assertFalse(any("TIMESTAMP_LINE_OFFSET" in step.upper()
                             for step in plan), plan)
        with patch.object(parity.canonical, "normalize_row",
                          side_effect=self.canonical_normalizer):
            self.assertTrue(self.check())

    def test_rejects_empty_hosts_or_nonpositive_budget(self):
        self.add("2026-10-19")
        with self.assertRaisesRegex(RuntimeError, "invalid late-arrival"):
            parity.has_late_eligible_source_rows(
                self.db, start="2026-05-22T00:00:00+00:00",
                end="2026-10-20T00:00:00+00:00",
                watermark=1, hosts=[], rules=[],
            )


if __name__=="__main__":
    unittest.main()
