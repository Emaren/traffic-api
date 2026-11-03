"""Recent project activity is observable without claiming human-audience finality."""
import json
import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path

from app.services.traffic.observed_daily_series import observed_daily_series


class ObservedDailySeries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "traffic.sqlite3"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
            CREATE TABLE traffic_public_daily_audience_rollups (
              project_slug TEXT, bucket_day TEXT, total_traffic INTEGER,
              suspected_human INTEGER, confirmed_human INTEGER, updated_at TEXT,
              PRIMARY KEY (project_slug,bucket_day));
            CREATE TABLE traffic_project_daily_rollups (
              project_slug TEXT, bucket_day TEXT, visitors INTEGER,
              events INTEGER, updated_at TEXT,
              PRIMARY KEY (project_slug,bucket_day));
            INSERT INTO traffic_public_daily_audience_rollups VALUES
              ('aoe2hdbets','2026-10-19',120,80,60,'2026-10-23T00:00:00Z');
            INSERT INTO traffic_project_daily_rollups VALUES
              ('aoe2hdbets','2026-10-19',100,150,'2026-10-19T22:00:00Z'),
              ('aoe2hdbets','2026-10-20',101,152,'2026-10-20T23:59:59Z'),
              ('aoe2hdbets','2026-11-02',121,200,'2026-11-03T08:00:00Z'),
              ('aoe2hdbets','2026-11-03',122,205,'2026-11-03T19:00:00Z'),
              ('otherproject','2026-11-03',9000,9999,'2026-11-03T19:00:00Z');
            """)

    def tearDown(self):
        self.temp.cleanup()

    def test_recent_provisional_is_separate_from_immutable_certified_archive(self):
        old = self.path.read_bytes()
        data = observed_daily_series(self.path,today_utc=date(2026,11,3))
        self.assertEqual(old,self.path.read_bytes())
        self.assertEqual(data["last_certified_day"],"2026-10-19")
        self.assertEqual([p["date"] for p in data["points"]],
                         ["2026-10-20","2026-11-02","2026-11-03"])
        self.assertTrue(all(p["certified_human"] is False for p in data["points"]))
        self.assertTrue(data["points"][-2]["utc_day_complete"])
        self.assertFalse(data["points"][-1]["utc_day_complete"])
        self.assertEqual(data["points"][0]["observed_qualifying_ips"],101)
        self.assertEqual(data["points"][0]["observed_get_events"],152)
        self.assertNotIn("human",data["points"][0])
        self.assertIn("NOT unique people", data["semantics"]["observed_qualifying_ips"])
        self.assertIn("UNVERIFIED", data["semantics"]["certification"])
        self.assertEqual(data["kind"],"provisional_observed_project_daily")
        self.assertFalse(any("otherproject" in json.dumps(p) for p in data["points"]))

    def test_empty_recent_window_is_truthful_not_fabricated(self):
        result=observed_daily_series(self.path,today_utc=date(2027,3,1))
        self.assertEqual(result["points"],[])
        self.assertEqual(result["last_certified_day"],"2026-10-19")

    def test_invalid_rollup_invariant_fails_closed(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE traffic_project_daily_rollups SET visitors=300 WHERE bucket_day='2026-11-02'")
        with self.assertRaisesRegex(ValueError,"invariant failed"):
            observed_daily_series(self.path,today_utc=date(2026,11,3))

    def test_invalid_archive_future_day_fails_closed(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO traffic_public_daily_audience_rollups VALUES "
                       "('aoe2hdbets','2026-11-03',1,1,1,'2026-11-03T20:00:00Z')")
        with self.assertRaisesRegex(ValueError,"future date"):
            observed_daily_series(self.path,today_utc=date(2026,11,3))

    def test_missing_database_cannot_be_created(self):
        with self.assertRaises(sqlite3.OperationalError):
            observed_daily_series(Path(self.temp.name)/"missing.sqlite3",today_utc=date(2026,11,3))


if __name__=="__main__":unittest.main()
