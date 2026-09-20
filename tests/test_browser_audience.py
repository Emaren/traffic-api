from __future__ import annotations

from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

import app.services.traffic.browser_events as browser_events


class BrowserAudienceTests(unittest.TestCase):
    def test_repeat_browser_counts_and_synthetic_observers_do_not_persist(self) -> None:
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
                    "x-forwarded-for": "203.0.113.77",
                }
                base = {
                    "host": "aoe2war.com",
                    "path": "/",
                    "event_type": "page_view",
                    "visitor_id": "v_same_browser",
                }

                browser_events.record_browser_event(
                    {
                        **base,
                        "session_id": "s_one",
                        "page_view_id": "pv_one",
                    },
                    headers=headers,
                )
                browser_events.record_browser_event(
                    {
                        **base,
                        "session_id": "s_two",
                        "page_view_id": "pv_two",
                    },
                    headers=headers,
                )

                audience = browser_events.list_browser_visitor_audience(
                    project_slug="aoe2hdbets",
                    since_hours=24,
                    limit=10,
                )

                self.assertEqual(len(audience), 1)
                self.assertEqual(audience[0]["traffic_visitor_id"], "v_same_browser")
                self.assertEqual(audience[0]["visit_count"], 2)
                self.assertEqual(audience[0]["return_count"], 1)
                self.assertFalse(audience[0]["exclude_from_human_analytics"])

                synthetic = browser_events.record_browser_event(
                    {
                        **base,
                        "visitor_id": "v_synthetic",
                        "session_id": "s_synthetic",
                        "page_view_id": "pv_synthetic",
                    },
                    headers={
                        **headers,
                        "x-aoe2war-synthetic": "speedos-test",
                    },
                )

                self.assertFalse(synthetic["stored"])
                self.assertEqual(synthetic["reason"], "synthetic_observer")

                audience = browser_events.list_browser_visitor_audience(
                    project_slug="aoe2hdbets",
                    since_hours=24,
                    limit=10,
                )
                self.assertEqual(
                    [row["traffic_visitor_id"] for row in audience],
                    ["v_same_browser"],
                )

                browser_events.record_authenticated_presence(
                    {
                        "host": "aoe2war.com",
                        "path": "/",
                        "visitor_id": "v_same_browser",
                        "session_id": "s_two",
                        "authenticated_uid": "operator-uid",
                        "authenticated_label": "Operator",
                        "client_ip": "203.0.113.77",
                        "client_user_agent": headers["user-agent"],
                    }
                )

                audience = browser_events.list_browser_visitor_audience(
                    project_slug="aoe2hdbets",
                    since_hours=24,
                    limit=10,
                    exclude_authenticated_uids=["operator-uid"],
                )
                self.assertEqual(audience, [])
            finally:
                browser_events.PERSIST_DB_PATH = original_path
                browser_events.PERSIST_ENABLED = original_enabled
                browser_events._BROWSER_SCHEMA_READY = original_ready

    def test_filtered_newest_observer_does_not_starve_older_human(self) -> None:
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
                    "x-forwarded-for": "203.0.113.91",
                }

                browser_events.record_browser_event(
                    {
                        "host": "aoe2war.com",
                        "path": "/players",
                        "event_type": "page_view",
                        "visitor_id": "v_real_human",
                        "session_id": "s_human",
                        "page_view_id": "pv_human",
                    },
                    headers=headers,
                )

                browser_events.record_browser_event(
                    {
                        "host": "aoe2war.com",
                        "path": "/speed",
                        "event_type": "page_view",
                        "visitor_id": "v_operator",
                        "session_id": "s_operator",
                        "page_view_id": "pv_operator",
                    },
                    headers=headers,
                )
                browser_events.record_authenticated_presence(
                    {
                        "host": "aoe2war.com",
                        "path": "/speed",
                        "visitor_id": "v_operator",
                        "session_id": "s_operator",
                        "authenticated_uid": "operator-uid",
                        "authenticated_label": "Operator",
                        "client_ip": "203.0.113.91",
                        "client_user_agent": headers["user-agent"],
                    }
                )

                audience = browser_events.list_browser_visitor_audience(
                    project_slug="aoe2hdbets",
                    since_hours=24,
                    limit=1,
                    exclude_authenticated_uids=["operator-uid"],
                )

                self.assertEqual(len(audience), 1)
                self.assertEqual(
                    audience[0]["traffic_visitor_id"],
                    "v_real_human",
                )
            finally:
                browser_events.PERSIST_DB_PATH = original_path
                browser_events.PERSIST_ENABLED = original_enabled
                browser_events._BROWSER_SCHEMA_READY = original_ready


if __name__ == "__main__":
    unittest.main()
