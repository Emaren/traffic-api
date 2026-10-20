from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import public_audience_v2_checkpoint as stage1
from scripts import public_audience_v2_sessions as stage2
from scripts import rebuild_public_audience_archive as canonical
from app.services.traffic import sessions as actual_sessions


def normalized(row, *, rules):
    return {
        "host": row["host"], "ip": row["ip"], "ua": row["ua"],
        "category": "human", "route_kind": "page",
        "timestamp": datetime.fromisoformat(row["timestamp"]),
        "timestamp_iso": row["timestamp"],
        "normalized_path": row["normalized_path"],
        "raw_path": row["raw_path"], "referrer_host": row["referrer_host"],
        "line_offset": int(row["line_offset"]), "event_id": row["event_id"],
    }


def deterministic_session(events, *, now, ip_behavior):
    first = events[0]
    assert ip_behavior["request_count"] >= len(events)
    return {
        "session_id": first["event_id"],
        "first_seen_at": first["timestamp"].isoformat(),
        "started_at": first["timestamp"].isoformat(),
        "ip": first["ip"], "route_kind": "page",
        "classification_state": "human_confirmed",
        "known_automation": False, "suspicious_score": 0,
    }


class CanonicalStreamingParityTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.raw = Path(temp.name) / "raw.db"
        self.checkpoint = Path(temp.name) / "private.db"
        with sqlite3.connect(self.raw) as db:
            db.executescript("""
                CREATE TABLE traffic_entries (
                    event_id TEXT, timestamp TEXT, ip TEXT, line_offset INTEGER,
                    raw_path TEXT, normalized_path TEXT, referrer_host TEXT,
                    ua TEXT, host TEXT
                );
                CREATE INDEX idx_traffic_entries_timestamp_line_offset
                ON traffic_entries(timestamp,line_offset);
            """)
            rows = [
                ("a", "2026-10-16T00:00:01+00:00", "1", 1, "/", "/", "", "Mozilla", "aoe2war.com"),
                ("b", "2026-10-16T00:02:00+00:00", "1", 2, "/x", "/x", "", "Mozilla", "aoe2war.com"),
                ("c", "2026-10-17T01:00:00+00:00", "2", 3, "/", "/", "", "Chrome", "aoe2war.com"),
                ("d", "2026-10-17T02:00:00+00:00", "1", 4, "/x", "/x", "", "Mozilla", "aoe2war.com"),
                ("e", "2026-10-18T00:00:00+00:00", "1", 5, "/", "/", "", "Mozilla", "aoe2war.com"),
            ]
            db.executemany("INSERT INTO traffic_entries VALUES(?,?,?,?,?,?,?,?,?)", rows)
        mocks = [
            patch.object(canonical, "project_hosts", return_value=["aoe2war.com"]),
            patch.object(canonical, "safe_list_visibility_rules", return_value=[]),
            patch.object(canonical, "normalize_row", side_effect=normalized),
            patch.object(canonical, "PERSIST_DB_PATH", self.raw),
            patch.object(canonical, "build_single_session", side_effect=deterministic_session),
            patch.object(canonical, "collapse_distributed_bursts", side_effect=lambda sessions: sessions),
            patch.object(canonical, "_is_known_singapore_cloud_fanout", return_value=False),
            patch.object(canonical, "apply_known_visitor_confirmation", side_effect=lambda sess: None),
        ]
        for m in mocks:
            m.start()
            self.addCleanup(m.stop)

    def first_pass(self, page=2):
        while True:
            result = stage1.advance(self.raw, self.checkpoint,
                start="2026-10-16T00:00:00+00:00",
                end="2026-10-20T00:00:00+00:00", max_rows=page)
            if result["phase"] == "PASS1_COMPLETE":
                return result

    def golden(self):
        start=datetime.fromisoformat("2026-10-16T00:00:00+00:00")
        end=datetime.fromisoformat("2026-10-20T00:00:00+00:00")
        behavior, raw, accepted=canonical.build_ip_behavior(
            start=start, end=end, snapshot_max_rowid=5)
        self.assertEqual(raw, 5)
        daily, stats=canonical.stream_sessions(
            start=start, end=end, behavior=behavior, snapshot_max_rowid=5)
        self.assertEqual(stats["accepted_rows"], 5)
        return daily, stats

    def test_restartable_pass_two_equals_original_single_stream_across_multiple_page_sizes(self):
        expected, stats = self.golden()
        self.assertEqual(expected, {
            "2026-10-16": [1, 1, 1],
            "2026-10-17": [2, 2, 2],
            "2026-10-18": [1, 1, 1],
        })
        self.first_pass(page=2)
        while True:
            result=stage2.pass2_step(self.raw, self.checkpoint, max_rows=1)
            self.assertFalse(result["publication_authorized"])
            if result["phase"] == "PASS2_COMPLETE":
                break
        self.assertEqual(stage2.shadow_daily(self.checkpoint), expected)
        self.assertEqual(result["total_finalized"], stats["finalized_sessions"])
        self.assertEqual(result["total_page_sessions"], stats["page_sessions"])
        with self.assertRaisesRegex(RuntimeError, "already complete"):
            stage2.pass2_step(self.raw, self.checkpoint)

    def test_real_canonical_session_builder_and_burst_rules_match_chunked_replay(self):
        # Exercise the actual production classifier rather than the deterministic
        # stub used by the focused restart/cursor tests.
        def actual_builder(events, *, now, ip_behavior):
            return actual_sessions.build_single_session(
                events, now=now, ip_behavior=ip_behavior
            )
        with (
            patch.object(canonical, "build_single_session", side_effect=actual_builder),
            patch.object(canonical, "collapse_distributed_bursts",
                         side_effect=actual_sessions.collapse_distributed_bursts),
            patch.object(canonical, "apply_known_visitor_confirmation",
                         side_effect=actual_sessions.apply_known_visitor_confirmation),
            patch.object(canonical, "_is_known_singapore_cloud_fanout",
                         side_effect=actual_sessions._is_known_singapore_cloud_fanout),
        ):
            golden, stats = self.golden()
            self.first_pass(page=3)
            while True:
                result = stage2.pass2_step(self.raw, self.checkpoint, max_rows=2)
                if result["phase"] == "PASS2_COMPLETE":
                    break
            self.assertEqual(stage2.shadow_daily(self.checkpoint), golden)
            self.assertEqual(result["total_finalized"], stats["finalized_sessions"])
            self.assertEqual(result["total_page_sessions"], stats["page_sessions"])

    def test_failed_mid_batch_keeps_previous_cursor_and_daily_totals(self):
        self.first_pass()
        stage2.pass2_step(self.raw, self.checkpoint, max_rows=2)
        with patch.object(canonical, "normalize_row", side_effect=RuntimeError("simulated crash")):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                stage2.pass2_step(self.raw, self.checkpoint, max_rows=2)
        with sqlite3.connect(self.checkpoint) as db:
            self.assertEqual(dict(db.execute(
                "SELECT key,value FROM metadata"
            ))["p2_raw"], "2")
        while True:
            report=stage2.pass2_step(self.raw, self.checkpoint, max_rows=2)
            if report["phase"] == "PASS2_COMPLETE":
                break
        self.assertEqual(stage2.shadow_daily(self.checkpoint), self.golden()[0])

    def test_shadow_unavailable_until_final_batch_committed(self):
        self.first_pass()
        self.assertRaises(RuntimeError, stage2.shadow_daily, self.checkpoint)
        stage2.pass2_step(self.raw, self.checkpoint, max_rows=1)
        with self.assertRaisesRegex(RuntimeError, "requires complete"):
            stage2.shadow_daily(self.checkpoint)

    def test_changed_raw_row_between_passes_denies_final_shadow_result(self):
        self.first_pass()
        with sqlite3.connect(self.raw) as db:
            db.execute(
                "UPDATE traffic_entries SET normalized_path=? WHERE event_id=?",
                ("/historical-rewrite", "c"),
            )
        with self.assertRaisesRegex(RuntimeError, "source passes differ"):
            while True:
                result=stage2.pass2_step(self.raw, self.checkpoint, max_rows=2)
                if result["phase"] == "PASS2_COMPLETE":
                    break
        with self.assertRaisesRegex(RuntimeError, "requires complete"):
            stage2.shadow_daily(self.checkpoint)

    def test_changed_source_count_or_digest_after_finished_pass_denies_shadow(self):
        self.first_pass()
        while True:
            report=stage2.pass2_step(self.raw, self.checkpoint, max_rows=3)
            if report["phase"] == "PASS2_COMPLETE":
                break
        expected=stage2.shadow_daily(self.checkpoint)
        with sqlite3.connect(self.checkpoint) as db:
            db.execute("UPDATE metadata SET value=? WHERE key='p2_digest'", ("0"*64,))
        with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
            stage2.shadow_daily(self.checkpoint)
        self.assertTrue(expected)

    def test_new_append_is_out_of_scope_and_cannot_change_closed_snapshot(self):
        self.first_pass()
        with sqlite3.connect(self.raw) as db:
            db.execute("INSERT INTO traffic_entries VALUES(?,?,?,?,?,?,?,?,?)",
                ("late", "2026-10-16T01:00:00+00:00", "7", 9,
                 "/", "/", "", "Mozilla", "aoe2war.com"))
        while True:
            result=stage2.pass2_step(self.raw, self.checkpoint, max_rows=3)
            if result["phase"] == "PASS2_COMPLETE":
                break
        self.assertEqual(result["total_raw"], 5)


if __name__ == "__main__":
    unittest.main()
