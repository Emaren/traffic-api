from __future__ import annotations

from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

import app.services.traffic.browser_events as browser_events


class BrowserAudienceHistoryTests(unittest.TestCase):
    def test_all_time_audience_keeps_repeat_visitors_and_returns_bounded_path_trail(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "traffic.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE traffic_entries (host TEXT, timestamp TEXT, normalized_path TEXT, ip TEXT)"
            )
            connection.commit()
            connection.close()

            original_path = browser_events.PERSIST_DB_PATH
            original_enabled = browser_events.PERSIST_ENABLED
            original_ready = browser_events._BROWSER_SCHEMA_READY

            try:
                browser_events.PERSIST_DB_PATH = database
                browser_events.PERSIST_ENABLED = True
                browser_events._BROWSER_SCHEMA_READY = False

                headers = {
                    "origin": "https://aoe2war.com",
                    "user-agent": (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 Chrome/153 Safari/537.36"
                    ),
                    "x-forwarded-for": "203.0.113.145",
                }

                for session_id, path in (
                    ("s_old_one", "/players"),
                    ("s_old_two", "/leaderboard"),
                ):
                    browser_events.record_browser_event(
                        {
                            "host": "aoe2war.com",
                            "path": path,
                            "event_type": "page_view",
                            "visitor_id": "v_repeat_old",
                            "session_id": session_id,
                            "page_view_id": f"pv_{session_id}",
                        },
                        headers=headers,
                    )

                browser_events.record_browser_event(
                    {
                        "host": "aoe2war.com",
                        "path": "/champions",
                        "event_type": "page_view",
                        "visitor_id": "v_repeat_old",
                        "session_id": "s_old_two",
                        "page_view_id": "pv_old_champions",
                    },
                    headers=headers,
                )

                browser_events.record_browser_event(
                    {
                        "host": "aoe2war.com",
                        "path": "/forum",
                        "event_type": "page_view",
                        "visitor_id": "v_recent",
                        "session_id": "s_recent",
                        "page_view_id": "pv_recent",
                    },
                    headers=headers,
                )

                connection = sqlite3.connect(database)
                try:
                    connection.execute(
                        "UPDATE traffic_browser_events SET received_at = '2026-01-01T00:00:00+00:00', occurred_at = '2026-01-01T00:00:00+00:00' WHERE visitor_id = 'v_repeat_old' AND path = '/players'"
                    )
                    connection.execute(
                        "UPDATE traffic_browser_events SET received_at = '2026-01-01T00:01:00+00:00', occurred_at = '2026-01-01T00:01:00+00:00' WHERE visitor_id = 'v_repeat_old' AND path = '/leaderboard'"
                    )
                    connection.execute(
                        "UPDATE traffic_browser_events SET received_at = '2026-01-01T00:02:00+00:00', occurred_at = '2026-01-01T00:02:00+00:00' WHERE visitor_id = 'v_repeat_old' AND path = '/champions'"
                    )
                    connection.commit()
                finally:
                    connection.close()

                recent_only = browser_events.list_browser_visitor_audience(
                    project_slug="aoe2hdbets",
                    since_hours=24,
                    limit=10,
                )
                self.assertEqual(
                    [row["traffic_visitor_id"] for row in recent_only],
                    ["v_recent"],
                )

                all_time = browser_events.list_browser_visitor_audience(
                    project_slug="aoe2hdbets",
                    since_hours=24,
                    limit=10,
                    all_time=True,
                    path_limit=2,
                )
                repeat = next(
                    row
                    for row in all_time
                    if row["traffic_visitor_id"] == "v_repeat_old"
                )

                self.assertEqual(repeat["visit_count"], 2)
                self.assertEqual(repeat["return_count"], 1)
                self.assertFalse(repeat["active_now"])
                self.assertEqual(
                    [step["path"] for step in repeat["path_trail"]],
                    ["/leaderboard", "/champions"],
                )
            finally:
                browser_events.PERSIST_DB_PATH = original_path
                browser_events.PERSIST_ENABLED = original_enabled
                browser_events._BROWSER_SCHEMA_READY = original_ready


if __name__ == "__main__":
    unittest.main()
