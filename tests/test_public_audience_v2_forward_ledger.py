from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_forward_ledger as ledger


RAW_SCHEMA = """
CREATE TABLE traffic_entries(
    event_id TEXT, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
    line_offset INTEGER NOT NULL, raw_path TEXT, normalized_path TEXT,
    referrer_host TEXT, ua TEXT, host TEXT
);
CREATE INDEX idx_traffic_entries_timestamp_line_offset
    ON traffic_entries(timestamp,line_offset);
"""


class FutureLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = sqlite3.connect(":memory:")
        self.source.row_factory = sqlite3.Row
        self.addCleanup(self.source.close)
        self.source.executescript(RAW_SCHEMA)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript(ledger.PRIVATE_SCHEMA)
        self.meta = ledger.initial_metadata({
            "device": "1", "inode": "2",
            "hosts_sha256": "h", "rules_sha256": "r",
            "canonical_sha256": "c", "source": "/private/traffic.sqlite3",
        })
        self.db.executemany(
            "INSERT INTO ledger_metadata(key,value) VALUES (?,?)", self.meta.items(),
        )
        self.db.commit()
        self.normalize = patch.object(
            ledger.canonical, "normalize_row",
            side_effect=lambda row, rules: {"timestamp_iso": row["timestamp"]},
        )
        self.normalize.start()
        self.addCleanup(self.normalize.stop)

    def add_event(self, rowid, timestamp, *, host="aoe2war.com"):
        self.source.execute("""
            INSERT INTO traffic_entries(
                rowid,event_id,timestamp,ip,line_offset,raw_path,
                normalized_path,referrer_host,ua,host
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (
            rowid, "e" + str(rowid), timestamp, "10.0.0.1",
            rowid, "/traffic", "/traffic", "", "mozilla", host,
        ))
        self.source.commit()

    def captured_ids(self):
        return [
            row[0] for row in self.db.execute(
                "SELECT source_rowid FROM future_events ORDER BY source_rowid"
            )
        ]

    def test_bootstrap_includes_oct20_before_historical_watermark(self):
        self.add_event(100, "2026-10-20T00:01:00+00:00")
        self.add_event(101, "2026-10-20T00:02:00+00:00")
        self.add_event(ledger.FROZEN_WATERMARK + 1,
                       "2026-10-20T01:00:00+00:00")
        first = ledger.advance_one(
            self.source, self.db, self.meta, ["aoe2war.com"], [], cap=1,
        )
        self.assertEqual(first["phase"], "BOOTSTRAP")
        self.assertEqual(self.captured_ids(), [100])
        self.assertFalse(first["public_audience_writes"])
        second = ledger.advance_one(
            self.source, self.db, self.meta, ["aoe2war.com"], [], cap=5,
        )
        self.assertEqual(second["phase"], "LIVE")
        self.assertEqual(self.captured_ids(), [100, 101])
        third = ledger.advance_one(
            self.source, self.db, self.meta, ["aoe2war.com"], [], cap=5,
        )
        self.assertEqual(self.captured_ids(),
                         [100, 101, ledger.FROZEN_WATERMARK + 1])
        self.assertEqual(third["total_retained_events"], 3)
        self.assertEqual(int(self.meta["live_rowid"]),
                         ledger.FROZEN_WATERMARK + 1)

    def test_late_historical_row_fails_without_cursor_commit(self):
        self.add_event(100, "2026-10-20T00:01:00+00:00")
        ledger.advance_one(self.source, self.db, self.meta,
                           ["aoe2war.com"], [], cap=5)
        self.assertEqual(self.meta["phase"], "LIVE")
        self.add_event(ledger.FROZEN_WATERMARK + 1,
                       "2026-10-19T23:58:00+00:00")
        with self.assertRaisesRegex(RuntimeError, "late event"):
            ledger.advance_one(self.source, self.db, self.meta,
                               ["aoe2war.com"], [], cap=5)
        self.assertEqual(self.captured_ids(), [100])
        self.assertEqual(int(self.meta["live_rowid"]), ledger.FROZEN_WATERMARK)

    def test_live_no_event_advance_and_retry_no_duplicate(self):
        ledger.advance_one(self.source, self.db, self.meta,
                           ["aoe2war.com"], [], cap=5)
        self.assertEqual(self.meta["phase"], "LIVE")
        self.add_event(ledger.FROZEN_WATERMARK + 5,
                       "2026-10-20T02:00:00+00:00")
        ledger.advance_one(self.source, self.db, self.meta,
                           ["aoe2war.com"], [], cap=5)
        self.assertEqual(self.captured_ids(), [ledger.FROZEN_WATERMARK + 5])
        last = ledger.advance_one(self.source, self.db, self.meta,
                                  ["aoe2war.com"], [], cap=5)
        self.assertEqual(last["step_source_rows"], 0)
        self.assertEqual(self.captured_ids(), [ledger.FROZEN_WATERMARK + 5])

    def test_rowid_seek_plan_uses_primary_key(self):
        self.add_event(ledger.FROZEN_WATERMARK + 1,
                       "2026-10-20T02:00:00+00:00")
        plan = [
            row[3] for row in self.source.execute(
                "EXPLAIN QUERY PLAN " + ledger.live_seek_sql(["aoe2war.com"]),
                (ledger.FROZEN_WATERMARK, ledger.FROZEN_WATERMARK + 10,
                 "aoe2war.com", 2),
            )
        ]
        self.assertTrue(any("INTEGER PRIMARY KEY" in item for item in plan))

    def test_policy_and_epoch_drift_fails_closed(self):
        snapshot = {
            "device": "1", "inode": "2",
            "hosts_sha256": "h", "rules_sha256": "r",
            "canonical_sha256": "c", "source": "/private/traffic.sqlite3",
        }
        ledger.validate_ledger(self.meta, snapshot)
        snapshot["rules_sha256"] = "changed"
        with self.assertRaisesRegex(RuntimeError, "rules_sha256 drift"):
            ledger.validate_ledger(self.meta, snapshot)
        snapshot["rules_sha256"] = "r"
        self.meta["original_watermark"] = "2"
        with self.assertRaisesRegex(RuntimeError, "watermark drift"):
            ledger.validate_ledger(self.meta, snapshot)

    def test_bounds_and_no_unknown_phase(self):
        self.meta["phase"] = "UNKNOWN"
        with self.assertRaisesRegex(RuntimeError, "unknown"):
            ledger.advance_one(self.source, self.db, self.meta,
                               ["aoe2war.com"], [], cap=5)
        with self.assertRaisesRegex(RuntimeError, "row cap"):
            ledger.advance_one(self.source, self.db, self.meta,
                               ["aoe2war.com"], [], cap=10001)


if __name__ == "__main__":
    unittest.main()
