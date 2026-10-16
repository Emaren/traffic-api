"""Single-scan graph raw-count regressions: preserve graph semantics."""

import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.services.traffic import overview


class SinglePassGraphRawCountsTests(unittest.TestCase):
    def test_request_and_unique_ip_counts_share_one_scan(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "raw-graph.sqlite3"
            conn = sqlite3.connect(database)
            conn.execute(
                "CREATE TABLE traffic_entries (host TEXT, ip TEXT, timestamp TEXT)"
            )
            conn.executemany(
                "INSERT INTO traffic_entries (host, ip, timestamp) VALUES (?, ?, ?)",
                [
                    ("aoe2war.com", "203.0.113.1", "2026-10-15T12:05:00+00:00"),
                    ("www.aoe2war.com", "203.0.113.1", "2026-10-15T12:06:00+00:00"),
                    ("aoe2war.com", "", "2026-10-15T12:07:00+00:00"),
                    ("aoe2war.com", "203.0.113.2", "2026-10-15T13:00:00+00:00"),
                    ("example.org", "198.51.100.8", "2026-10-15T12:11:00+00:00"),
                    ("aoe2war.com", "203.0.113.9", "2026-10-15T11:59:00+00:00"),
                    ("aoe2war.com", "203.0.113.9", "2026-10-15T14:00:00+00:00"),
                    ("aoe2war.com", "203.0.113.9", "2026-10-15T12:bad+00:00"),
                ],
            )
            conn.commit()
            conn.close()

            connections = []

            def connect():
                connections.append(1)
                connection = sqlite3.connect(database)
                connection.row_factory = sqlite3.Row
                return connection

            projects = [
                {
                    "slug": "aoe2hdbets",
                    "hosts": ["aoe2war.com", "www.aoe2war.com"],
                },
                {
                    "slug": "other",
                    "hosts": ["example.org"],
                },
            ]

            window = {
                "first_bucket": datetime(2026, 10, 15, 12, tzinfo=timezone.utc),
                "last_bucket": datetime(2026, 10, 15, 13, tzinfo=timezone.utc),
                "bucket_minutes": 60,
            }
            b12 = "2026-10-15T12:00:00+00:00"
            b13 = "2026-10-15T13:00:00+00:00"

            with (
                patch.object(overview, "_connect", side_effect=connect),
                patch.object(overview, "_ensure_schema", return_value=None),
                patch.object(overview, "PROJECTS", projects),
            ):
                requests, unique = overview._raw_bucket_counts_by_project(
                    project_slugs=None, **window
                )
                self.assertEqual(len(connections), 1)
                self.assertEqual(dict(requests["aoe2hdbets"]), {b12: 3, b13: 1})
                self.assertEqual(dict(unique["aoe2hdbets"]), {b12: 1, b13: 1})
                self.assertEqual(dict(requests["other"]), {b12: 1})
                self.assertEqual(dict(unique["other"]), {b12: 1})

                scoped_requests, scoped_unique = overview._raw_bucket_counts_by_project(
                    project_slugs={"aoe2hdbets"}, **window
                )
                self.assertEqual(len(connections), 2)
                self.assertEqual(dict(scoped_requests["aoe2hdbets"]), {b12: 3, b13: 1})
                self.assertEqual(dict(scoped_unique["aoe2hdbets"]), {b12: 1, b13: 1})
                self.assertNotIn("other", scoped_requests)
                self.assertNotIn("other", scoped_unique)

    def test_unavailable_raw_store_yields_empty_raw_graph_lines(self):
        with (
            patch.object(overview, "_connect", side_effect=sqlite3.OperationalError("offline")),
            patch.object(overview, "PROJECTS", [
                {"slug": "aoe2hdbets", "hosts": ["aoe2war.com"]}
            ]),
        ):
            requests, unique = overview._raw_bucket_counts_by_project(
                project_slugs=None,
                first_bucket=datetime(2026, 10, 15, 12, tzinfo=timezone.utc),
                last_bucket=datetime(2026, 10, 15, 13, tzinfo=timezone.utc),
                bucket_minutes=60,
            )
            self.assertFalse(requests)
            self.assertFalse(unique)


if __name__ == "__main__":
    unittest.main()
