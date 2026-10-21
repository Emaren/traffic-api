from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.services.traffic.public_browser_insights import (
    MAX_ROWS,
    ObservedInsightsUnavailable,
    build_observed_browser_insights,
    public_path,
)


class ObservedBrowserInsightsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "events.sqlite3"
        with sqlite3.connect(self.db) as conn:
            conn.executescript("""
                CREATE TABLE traffic_browser_events(
                    id INTEGER PRIMARY KEY,
                    project_slug TEXT,
                    received_at TEXT,
                    event_type TEXT,
                    path TEXT,
                    visitor_id TEXT,
                    session_id TEXT,
                    page_view_id TEXT,
                    visible_ms INTEGER,
                    country TEXT,
                    user_agent TEXT
                );
                CREATE INDEX idx_traffic_browser_events_project_received
                ON traffic_browser_events(project_slug, received_at DESC);
                CREATE INDEX idx_traffic_browser_events_project_type_received
                ON traffic_browser_events(project_slug, event_type, received_at DESC);
            """)

    def add(self, visitor="v1", session="s1", view="p1", event="page_view",
            path="/market", visible=0, country="Canada", stamp="2026-10-20T12:00:00+00:00",
            ua="Mozilla/5.0", project="aoe2hdbets"):
        with sqlite3.connect(self.db) as db:
            db.execute(
                """INSERT INTO traffic_browser_events
                   (project_slug,received_at,event_type,path,visitor_id,session_id,
                    page_view_id,visible_ms,country,user_agent)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (project, stamp, event, path, visitor, session, view,
                 visible, country, ua),
            )

    def build(self):
        return build_observed_browser_insights(
            "aoe2hdbets", db_path=self.db,
            now=datetime(2026, 10, 21, 21, tzinfo=timezone.utc)
        )

    def test_counts_page_views_not_heartbeats_and_omits_zero_second_sessions(self):
        for n in range(1, 6):
            visitor = "v" + str(n)
            session = "s" + str(n)
            view = "p" + str(n)
            self.add(visitor, session, view)
            if n <= 4:
                self.add(visitor, session, view, "heartbeat", visible=10_000)
                self.add(visitor, session, view, "heartbeat", visible=14_000)
            self.add(visitor, session, "second"+str(n),
                     path="/academy", visible=0)
            if n == 1:
                self.add(visitor, session, "second"+str(n), "page_hide",
                         path="/academy", visible=6_000)
        payload = self.build()
        self.assertEqual(payload["status"], "OBSERVED_ONLY")
        self.assertEqual(payload["coverage"]["browser_page_views"], 10)
        self.assertEqual(payload["coverage"]["positive_duration_sessions"], 4)
        self.assertEqual(payload["coverage"]["excluded_zero_duration_sessions"], 1)
        self.assertEqual(payload["average_visible_seconds"], 16)
        self.assertEqual(payload["top_pages"][0], {
            "path": "/academy", "page_views": 5
        })
        self.assertEqual(payload["top_countries"], [{
            "name": "Canada", "unique_browser_ids": 5
        }])
        self.assertNotIn("ip", str(payload))
        self.assertNotIn("v1", str(payload))
        self.assertEqual(payload["through_day"], "2026-10-20")

    def test_excludes_private_assets_bots_and_other_project(self):
        self.add(view="internal", path="/admin")
        self.add(view="asset", path="/_next/static/main.js")
        self.add(view="bot", path="/market", ua="HeadlessChrome")
        self.add(view="other", project="other")
        self.add(view="unknown", path="/market", visitor="", session="", visible=100)
        self.assertEqual(self.build()["coverage"]["browser_page_views"], 0)
        self.assertEqual(self.build()["average_visible_seconds"], None)
        self.assertEqual(self.build()["top_countries"], [])

    def test_excludes_current_utc_day_and_out_of_window(self):
        self.add(view="now", stamp="2026-10-21T01:00:00+00:00")
        self.add(view="old", stamp="2026-10-13T23:59:59+00:00")
        self.assertEqual(self.build()["coverage"]["browser_page_views"], 0)

    def test_private_url_filters(self):
        self.assertIsNone(public_path("/api/foo"))
        self.assertIsNone(public_path("/profile/123"))
        self.assertIsNone(public_path("/scripts/data.json"))
        self.assertEqual(public_path("/market?token=secret"), "/market")
        self.assertIsNone(public_path("/market/order/private"))
        self.assertIsNone(public_path("/forum/thread/123"))
        self.assertIsNone(public_path("/reset-password/token"))
        self.assertIsNone(public_path("/lobby"))
        self.assertEqual(public_path("/TRAFFIC?foo=bar"), "/traffic")

    def test_durations_use_max_not_sum_and_do_not_count_phantom_page_views(self):
        self.add(visitor="real", session="session", view="first", visible=0)
        self.add(visitor="real", session="session", view="first",
                 event="heartbeat", visible=10_000)
        self.add(visitor="real", session="session", view="first",
                 event="heartbeat", visible=25_000)
        self.add(visitor="real", session="session", view="first",
                 event="heartbeat", visible=120_000, ua="HeadlessChrome")
        self.add(visitor="real", session="session", view="second",
                 path="/leaderboard", visible=3_000)
        self.add(visitor="real", session="session", view="phantom",
                 event="heartbeat", visible=500_000)
        report = self.build()
        self.assertEqual(report["coverage"]["browser_page_views"], 2)
        self.assertEqual(report["coverage"]["rows_scanned"], 6)
        self.assertEqual(report["coverage"]["positive_duration_sessions"], 1)
        self.assertEqual(report["average_visible_seconds"], 28)
        self.assertEqual(
            {row["path"]: row["page_views"] for row in report["top_pages"]},
            {"/market": 1, "/leaderboard": 1},
        )

    def test_total_cohort_includes_non_page_events_before_limit(self):
        for i in range(4):
            self.add(view="p", event="heartbeat", visible=1_000)
        from unittest.mock import patch
        with patch("app.services.traffic.public_browser_insights.MAX_ROWS", 3):
            with self.assertRaisesRegex(
                ObservedInsightsUnavailable, "bounded scan"
            ):
                self.build()

    def test_missing_database_fails_not_zero(self):
        with self.assertRaises(ObservedInsightsUnavailable):
            build_observed_browser_insights(
                "aoe2hdbets",
                db_path=self.db.with_name("missing.sqlite3"),
                now=datetime(2026, 10, 21, tzinfo=timezone.utc),
            )

    def test_managed_sqlite_symlink_alias_reads_same_existing_database(self):
        self.add(visible=10_000)
        alias = self.db.with_name("configured.sqlite3")
        alias.symlink_to(self.db)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.resolve(strict=True), self.db)
        payload = build_observed_browser_insights(
            "aoe2hdbets",
            db_path=alias,
            now=datetime(2026, 10, 21, 21, tzinfo=timezone.utc),
        )
        self.assertEqual(payload, self.build())
        self.assertEqual(payload["coverage"]["browser_page_views"], 1)
        self.assertEqual(payload["status"], "OBSERVED_ONLY")

    def test_broken_symlink_and_nonfile_target_fail_closed(self):
        missing_alias = self.db.with_name("broken.sqlite3")
        missing_alias.symlink_to(self.db.with_name("missing.sqlite3"))
        directory = Path(self.temp.name) / "not_a_database"
        directory.mkdir()
        directory_alias = self.db.with_name("directory_alias.sqlite3")
        directory_alias.symlink_to(directory, target_is_directory=True)
        for bad_path in (missing_alias, directory_alias):
            with self.subTest(path=bad_path):
                with self.assertRaisesRegex(
                    ObservedInsightsUnavailable,
                    "browser evidence database unavailable",
                ):
                    build_observed_browser_insights(
                        "aoe2hdbets",
                        db_path=bad_path,
                        now=datetime(2026, 10, 21, 21, tzinfo=timezone.utc),
                    )

    def test_fail_closed_at_window_limit(self):
        # Exercise the bounded cohort check without generating 80,001 rows.
        from unittest.mock import patch
        with patch("app.services.traffic.public_browser_insights.MAX_ROWS", 1):
            self.add(view="a")
            self.add(view="b")
            with self.assertRaisesRegex(ObservedInsightsUnavailable, "bounded"):
                self.build()


if __name__ == "__main__":
    unittest.main()
