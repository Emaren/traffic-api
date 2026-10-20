from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts import public_audience_v2_state_compare as compare


class PrivateComparisonTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.old = Path(temp.name) / "old.sqlite3"
        self.new = Path(temp.name) / "new.sqlite3"
        for path, segmented in ((self.old, False), (self.new, True)):
            with sqlite3.connect(path) as db:
                db.executescript("""
                    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
                    CREATE TABLE v2_open(
                        host TEXT,ip TEXT,ua TEXT,events_json TEXT,
                        last_time TEXT,version INTEGER,bucket INTEGER
                    );
                    CREATE TABLE v2_closed(bucket INTEGER,session_json TEXT);
                    CREATE TABLE v2_daily(
                        day TEXT,total INTEGER,suspected INTEGER,confirmed INTEGER
                    );
                    CREATE TABLE v2_open_segments(
                        host TEXT,ip TEXT,ua TEXT,seq INTEGER,events_json TEXT,
                        PRIMARY KEY(host,ip,ua,seq)
                    );
                """)
                db.executemany("INSERT INTO metadata VALUES(?,?)", [
                    ("phase", "PASS2_RUNNING"), ("p2_raw", "14"),
                    ("p2_accepted", "14"), ("p2_digest", "a" * 64),
                ])
                db.execute("INSERT INTO v2_daily VALUES('2026-10-16',3,2,1)")
                db.execute("INSERT INTO v2_closed VALUES(?,?)", (17, '{"session":1}'))
                events = '[]' if segmented else '[{"event":1},{"event":2}]'
                db.execute(
                    "INSERT INTO v2_open VALUES(?,?,?,?,?,?,?)",
                    ("host", "private-ip", "ua", events, "2026-10-16", 7, 99),
                )
                if segmented:
                    db.executemany(
                        "INSERT INTO v2_open_segments VALUES(?,?,?,?,?)",
                        [("host", "private-ip", "ua", 0, '[{"event":1}]'),
                         ("host", "private-ip", "ua", 1, '[{"event":2}]')],
                    )
            os.chmod(path, 0o600)

    def test_old_and_segmented_json_have_identical_public_truth(self):
        result = compare.compare_checkpoints(self.old, self.new)
        self.assertEqual(result["status"], "MATCH")
        self.assertEqual(result["p2_raw"], 14)
        self.assertFalse(result["publication_authorized"])

    def test_tampering_with_segment_fails_closed(self):
        with sqlite3.connect(self.new) as db:
            db.execute(
                "UPDATE v2_open_segments SET events_json='[{\"event\":3}]' WHERE seq=1"
            )
        result = compare.compare_checkpoints(self.old, self.new)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("fingerprints.open", result["differences"])

    def test_missing_segment_fails_closed(self):
        with sqlite3.connect(self.new) as db:
            db.execute("DELETE FROM v2_open_segments")
        with self.assertRaisesRegex(RuntimeError, "missing/corrupt"):
            compare.compare_checkpoints(self.old, self.new)

    def test_world_readable_copy_fails_closed(self):
        os.chmod(self.new, 0o644)
        with self.assertRaisesRegex(RuntimeError, "not private"):
            compare.compare_checkpoints(self.old, self.new)


if __name__ == "__main__":
    unittest.main()
