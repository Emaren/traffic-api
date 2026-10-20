from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_checkpoint as v2


def fixture_db(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.executescript("""
        CREATE TABLE traffic_entries (
            event_id TEXT, timestamp TEXT, ip TEXT, line_offset INTEGER,
            raw_path TEXT, normalized_path TEXT, referrer_host TEXT,
            ua TEXT, host TEXT
        );
        CREATE INDEX idx_traffic_entries_timestamp_line_offset
        ON traffic_entries(timestamp,line_offset);
        """)
        db.executemany("INSERT INTO traffic_entries VALUES(?,?,?,?,?,?,?,?,?)", [
            ("a", "2026-10-16T00:00:01+00:00", "1", 1, "/", "/", "", "Mozilla", "aoe2war.com"),
            ("b", "2026-10-16T00:02:00+00:00", "1", 2, "/x", "/x", "", "Mozilla", "aoe2war.com"),
            ("c", "2026-10-17T01:00:00+00:00", "2", 3, "/", "/", "google.com", "Chrome", "aoe2war.com"),
            ("d", "2026-10-17T02:00:00+00:00", "1", 4, "/x", "/x", "", "Mozilla", "aoe2war.com"),
            ("e", "2026-10-18T00:00:00+00:00", "1", 5, "/", "/", "", "Mozilla", "aoe2war.com"),
        ])


def mock_normalize(row, *, rules):
    return {
        "host": row["host"], "ip": row["ip"], "ua": row["ua"],
        "normalized_path": row["normalized_path"],
        "referrer_host": row["referrer_host"] or v2.canonical.UNKNOWN_REFERRER,
    }


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source = Path(tmp.name) / "raw.sqlite3"
        self.state = Path(tmp.name) / "state.sqlite3"
        fixture_db(self.source)
        for target, return_value in (
            ("project_hosts", ["aoe2war.com"]),
            ("safe_list_visibility_rules", []),
        ):
            p = patch.object(v2.canonical, target, return_value=return_value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(v2.canonical, "normalize_row", side_effect=mock_normalize)
        p.start()
        self.addCleanup(p.stop)

    def step(self):
        return v2.advance(self.source, self.state,
            start="2026-10-16T00:00:00+00:00",
            end="2026-10-20T00:00:00+00:00", max_rows=2)

    def test_resume_counts_each_raw_row_once_and_keeps_public_table_absent(self):
        results = [self.step(), self.step(), self.step()]
        self.assertEqual([v["step_rows"] for v in results], [2, 2, 1])
        self.assertEqual(results[-1]["raw_scanned"], 5)
        self.assertEqual(results[-1]["phase"], "PASS1_COMPLETE")
        self.assertFalse(results[-1]["publish_authorized"])
        with sqlite3.connect(self.state) as db:
            counts = db.execute(
                "SELECT ip,requests,direct_referrers FROM ip_counts ORDER BY ip"
            ).fetchall()
            self.assertEqual(counts, [("1", 4, 4), ("2", 1, 0)])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ip_uas").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ip_paths").fetchone()[0], 3)
            self.assertIsNone(db.execute(
                "SELECT name FROM sqlite_master WHERE name='traffic_public_daily_audience_rollups'"
            ).fetchone())
        with self.assertRaisesRegex(RuntimeError, "completed checkpoint"):
            self.step()

    def test_host_policy_change_fails_closed_with_same_cursor(self):
        self.step()
        with patch.object(v2.canonical, "project_hosts", return_value=["other.host"]):
            with self.assertRaisesRegex(RuntimeError, "input identity changed"):
                self.step()
        self.assertEqual(v2.status(self.state)["raw_scanned"], 2)

    def test_exception_before_commit_rolls_back_counters_and_resume_position(self):
        self.step()
        with patch.object(v2.canonical, "normalize_row", side_effect=ValueError("failed")):
            with self.assertRaisesRegex(ValueError, "failed"):
                self.step()
        self.assertEqual(v2.status(self.state)["raw_scanned"], 2)
        self.assertEqual(self.step()["raw_scanned"], 4)

    def test_late_appended_row_is_excluded_by_frozen_max_rowid(self):
        self.step()
        with sqlite3.connect(self.source) as db:
            db.execute("INSERT INTO traffic_entries VALUES(?,?,?,?,?,?,?,?,?)",
                ("late", "2026-10-16T00:01:00+00:00", "9", 6,
                 "/", "/", "", "Mozilla", "aoe2war.com"))
        self.step()
        last = self.step()
        self.assertEqual(last["raw_scanned"], 5)
        self.assertEqual(last["accepted"], 5)

    def test_future_day_rows_excluded_despite_constant_work_global_watermark(self):
        with sqlite3.connect(self.source) as db:
            db.execute("INSERT INTO traffic_entries VALUES(?,?,?,?,?,?,?,?,?)",
                ("future", "2026-10-21T00:00:00+00:00", "9", 6,
                 "/", "/", "", "Mozilla", "aoe2war.com"))
        self.assertEqual(self.step()["source_max_rowid"], 6)
        self.step()
        last = self.step()
        self.assertEqual(last["raw_scanned"], 5)

    def test_does_not_write_private_checkpoint_inside_repository(self):
        with self.assertRaisesRegex(RuntimeError, "outside the source repository"):
            v2.advance(self.source, v2.ROOT / "private-checkpoint.sqlite3",
                start="2026-10-16T00:00:00+00:00",
                end="2026-10-20T00:00:00+00:00")
        self.assertFalse((v2.ROOT / "private-checkpoint.sqlite3").exists())

    def test_incomplete_initialization_has_explicit_stop(self):
        with sqlite3.connect(self.state) as db:
            db.executescript(v2.SCHEMA)
        with self.assertRaisesRegex(RuntimeError, "incomplete checkpoint initialization"):
            self.step()

    def test_negative_line_offset_at_exact_start_is_not_silently_skipped(self):
        # SQLite sorts an unexpected negative offset before offset 0; a
        # synthetic earliest ordering key must include it or fail closed.
        with sqlite3.connect(self.source) as db:
            db.execute("INSERT INTO traffic_entries VALUES(?,?,?,?,?,?,?,?,?)",
                ("edge", "2026-10-16T00:00:00+00:00", "8", -3,
                 "/", "/", "", "Mozilla", "aoe2war.com"))
        results = [self.step(), self.step(), self.step()]
        self.assertEqual([r["step_rows"] for r in results], [2, 2, 2])
        self.assertEqual(self.step()["raw_scanned"], 6)

    def test_raw_db_must_not_alias_state(self):
        with self.assertRaisesRegex(RuntimeError, "checkpoint aliases raw"):
            v2.advance(self.source, self.source,
                start="2026-10-16T00:00:00+00:00",
                end="2026-10-20T00:00:00+00:00")

    def test_status_on_absent_checkpoint_cannot_create_file(self):
        with self.assertRaisesRegex(RuntimeError, "no checkpoint"):
            v2.status(self.state)
        self.assertFalse(self.state.exists())


    def test_pass_one_statistics_equal_canonical_full_scan_on_same_source_snapshot(self):
        from datetime import datetime
        self.step()
        self.step()
        self.step()
        with patch.object(v2.canonical, "PERSIST_DB_PATH", self.source):
            behavior, raw, accepted = v2.canonical.build_ip_behavior(
                start=datetime.fromisoformat("2026-10-16T00:00:00+00:00"),
                end=datetime.fromisoformat("2026-10-20T00:00:00+00:00"),
                snapshot_max_rowid=5,
            )
        self.assertEqual(raw, 5)
        self.assertEqual(accepted, 5)
        with sqlite3.connect(self.state) as db:
            for (host, ip), expected in behavior.items():
                count = db.execute(
                    "SELECT requests,direct_referrers FROM ip_counts WHERE host=? AND ip=?",
                    (host, ip),
                ).fetchone()
                uas = {
                    row[0] for row in db.execute(
                        "SELECT ua FROM ip_uas WHERE host=? AND ip=?", (host, ip)
                    )
                }
                paths = {
                    row[0] for row in db.execute(
                        "SELECT path FROM ip_paths WHERE host=? AND ip=?", (host, ip)
                    )
                }
                self.assertEqual(count[0], expected["request_count"])
                self.assertEqual(len(uas), expected["unique_uas"])
                self.assertEqual(len(paths), expected["unique_paths"])
                self.assertEqual(sorted(paths), expected["route_bundle_paths"])
                self.assertEqual(count[1], 4 if ip == "1" else 0)

    def test_visibility_rule_change_invalidates_existing_checkpoint(self):
        self.step()
        with patch.object(v2.canonical, "safe_list_visibility_rules",
                          return_value=[{"rule_type": "fixture", "active": True}]):
            with self.assertRaisesRegex(RuntimeError, "input identity changed"):
                self.step()
        self.assertEqual(v2.status(self.state)["raw_scanned"], 2)

    def test_same_timestamp_and_offset_rows_resume_by_rowid_tiebreak(self):
        with sqlite3.connect(self.source) as db:
            db.execute(
                "UPDATE traffic_entries SET timestamp=?,line_offset=? WHERE event_id='b'",
                ("2026-10-16T00:00:01+00:00", 1),
            )
        one = self.step()
        self.assertEqual(one["step_rows"], 2)
        self.assertEqual(self.step()["raw_scanned"], 4)
        self.assertEqual(self.step()["raw_scanned"], 5)
        with sqlite3.connect(self.state) as db:
            self.assertEqual(db.execute("SELECT SUM(requests) FROM ip_counts").fetchone()[0], 5)



if __name__ == "__main__":
    unittest.main()
