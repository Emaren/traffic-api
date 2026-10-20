from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_preflight as preflight


class ReadOnlyPreflightTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.source=Path(temp.name)/"traffic.sqlite3"
        with sqlite3.connect(self.source) as db:
            db.executescript("""
                CREATE TABLE traffic_entries (
                  timestamp TEXT, host TEXT
                );
                CREATE INDEX idx_traffic_entries_host_timestamp
                  ON traffic_entries(host,timestamp);
                CREATE TABLE traffic_ingest_state(updated_at TEXT);
                CREATE TABLE traffic_public_daily_audience_rollups (
                  project_slug TEXT,bucket_day TEXT,updated_at TEXT
                );
            """)
            db.executemany("INSERT INTO traffic_entries VALUES(?,?)",[
                ("2026-10-20T04:00:00+00:00","aoe2war.com"),
                ("2026-10-20T05:00:00+00:00","aoe2war.com"),
            ])
            db.execute("INSERT INTO traffic_ingest_state VALUES(?)",
                       ("2026-10-20T05:00:00+00:00",))
            db.execute(
                "INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?)",
                ("aoe2hdbets","2026-10-14","2026-10-14T06:15:00+00:00"),
            )

    def test_indexed_source_and_stale_public_truth_are_read_only(self):
        evidence=preflight.read_evidence(self.source,["aoe2war.com"])
        self.assertEqual(evidence["source_rowid_ceiling"],2)
        self.assertEqual(evidence["public_last_day"],"2026-10-14")
        self.assertEqual(evidence["host_latest_utc"]["aoe2war.com"],
                         "2026-10-20T05:00:00+00:00")
        self.assertTrue(self.source.is_file())

    def test_missing_source_fails_without_creating_it(self):
        missing=self.source.parent/"missing.sqlite3"
        with self.assertRaisesRegex(RuntimeError,"does not exist"):
            preflight.read_evidence(missing,["aoe2war.com"])
        self.assertFalse(missing.exists())

    def test_unit_status_is_unknown_not_false_green(self):
        with patch.object(preflight.subprocess,"run",side_effect=OSError("not linux")):
            ok, values=preflight.timer_is_disabled()
        self.assertFalse(ok)
        self.assertIsNone(values["UnitFileState"])

    def test_canary_does_not_succeed_when_timer_not_verified(self):
        with (
            patch.object(preflight.canonical,"project_hosts",return_value=["aoe2war.com"]),
            patch.object(preflight,"timer_is_disabled",return_value=(
                False,{"UnitFileState":"enabled","ActiveState":"active"})),
        ):
            report=preflight.preflight(self.source)
        self.assertFalse(report["canary_ready"])
        self.assertTrue(report["read_only"])
        self.assertTrue(report["no_publication"])


if __name__=="__main__":
    unittest.main()
