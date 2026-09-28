from __future__ import annotations

import sqlite3
import unittest
from datetime import date

from scripts import rebuild_project_daily_rollups as rollups


class IncrementalProjectRollupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE traffic_entries (
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                status INTEGER NOT NULL,
                method TEXT NOT NULL,
                ua TEXT NOT NULL,
                normalized_path TEXT NOT NULL,
                ip TEXT NOT NULL
            );

            CREATE TABLE traffic_project_daily_rollups (
                project_slug TEXT NOT NULL,
                bucket_day TEXT NOT NULL,
                visitors INTEGER NOT NULL,
                events INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (project_slug, bucket_day)
            );
            """
        )
        self.hosts = ["aoe2war.test"]
        self.day = date(2026, 9, 28)

    def tearDown(self) -> None:
        self.conn.close()

    def insert(
        self,
        *,
        day: str = "2026-09-28",
        path: str = "/",
        ip: str = "203.0.113.10",
        ua: str = "Mozilla/5.0",
        host: str | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO traffic_entries (
                timestamp,
                host,
                status,
                method,
                ua,
                normalized_path,
                ip
            )
            VALUES (?, ?, 200, 'GET', ?, ?, ?)
            """,
            (
                f"{day}T12:00:00+00:00",
                host or self.hosts[0],
                ua,
                path,
                ip,
            ),
        )
        self.conn.commit()

    def rollup(self, day: str = "2026-09-28") -> tuple[int, int]:
        row = self.conn.execute(
            """
            SELECT visitors, events
            FROM traffic_project_daily_rollups
            WHERE project_slug = 'aoe2hdbets'
              AND bucket_day = ?
            """,
            (day,),
        ).fetchone()
        self.assertIsNotNone(row)
        return int(row["visitors"]), int(row["events"])

    def refresh(self):
        return rollups.refresh_project_incremental(
            self.conn,
            project_slug="aoe2hdbets",
            hosts=self.hosts,
            latest_raw_day=self.day,
        )

    def test_bootstrap_then_noop_without_rescanning_active_day(self) -> None:
        self.insert(path="/")
        self.insert(path="/profile")

        first = self.refresh()
        self.assertEqual(first["mode"], "incremental_bootstrap")
        self.assertEqual(self.rollup(), (1, 2))

        second = self.refresh()
        self.assertEqual(second["mode"], "incremental_noop")
        self.assertEqual(second["days"], 0)
        self.assertEqual(self.rollup(), (1, 2))

    def test_new_rows_merge_into_compact_state(self) -> None:
        self.insert(path="/")
        self.refresh()

        self.insert(path="/profile")
        result = self.refresh()

        self.assertEqual(result["mode"], "incremental")
        self.assertEqual(result["days"], 1)
        self.assertEqual(self.rollup(), (1, 2))

        state_rows = self.conn.execute(
            """
            SELECT normalized_path, hits
            FROM traffic_project_daily_path_state
            WHERE project_slug = 'aoe2hdbets'
              AND bucket_day = '2026-09-28'
            ORDER BY normalized_path
            """
        ).fetchall()
        self.assertEqual(
            [(row["normalized_path"], row["hits"]) for row in state_rows],
            [("/", 1), ("/profile", 1)],
        )

    def test_ineligible_new_rows_only_advance_watermark(self) -> None:
        self.insert(path="/")
        self.refresh()

        self.insert(path="/scanner", ua="curl/8.0")
        result = self.refresh()

        self.assertEqual(result["mode"], "incremental")
        self.assertEqual(result["days"], 0)
        self.assertEqual(self.rollup(), (1, 1))

        noop = self.refresh()
        self.assertEqual(noop["mode"], "incremental_noop")

    def test_host_set_change_rebuilds_complete_project_history_once(self) -> None:
        self.insert(
            day="2026-09-27",
            path="/",
            ip="198.51.100.10",
        )
        self.insert(path="/")

        # Seed the pre-incremental historical day as it would already exist in
        # production, then establish compact state for the active day.
        visitors, events = rollups.compute_project_day(
            self.conn,
            hosts=self.hosts,
            bucket_day=date(2026, 9, 27),
        )
        rollups.upsert_project_day(
            self.conn,
            project_slug="aoe2hdbets",
            bucket_day=date(2026, 9, 27),
            visitors=visitors,
            events=events,
        )
        self.conn.commit()
        self.refresh()
        self.assertEqual(self.rollup("2026-09-27"), (1, 1))

        self.insert(
            day="2026-09-27",
            path="/players",
            ip="198.51.100.11",
            host="legacy.aoe2war.test",
        )
        self.hosts = [
            "aoe2war.test",
            "legacy.aoe2war.test",
        ]

        result = self.refresh()

        self.assertEqual(result["mode"], "incremental_reseed")
        self.assertEqual(result["reason"], "host_set_changed")
        self.assertEqual(result["days"], 2)
        self.assertEqual(self.rollup("2026-09-27"), (2, 2))
        self.assertEqual(self.rollup("2026-09-28"), (1, 1))

        noop = self.refresh()
        self.assertEqual(noop["mode"], "incremental_noop")

    def test_raw_store_rewind_rebuilds_instead_of_reusing_future_state(self) -> None:
        self.insert(path="/")
        self.insert(path="/profile")
        self.refresh()

        highest_rowid = self.conn.execute(
            "SELECT MAX(rowid) FROM traffic_entries"
        ).fetchone()[0]
        self.conn.execute(
            "DELETE FROM traffic_entries WHERE rowid = ?",
            (highest_rowid,),
        )
        self.conn.commit()

        result = self.refresh()

        self.assertEqual(result["mode"], "incremental_reseed")
        self.assertEqual(result["reason"], "raw_store_rewound")
        self.assertEqual(self.rollup(), (1, 1))

        noop = self.refresh()
        self.assertEqual(noop["mode"], "incremental_noop")

    def test_late_historical_row_rebuilds_only_that_day(self) -> None:
        self.insert(path="/")
        self.refresh()

        self.insert(
            day="2026-09-27",
            path="/",
            ip="198.51.100.9",
        )
        result = self.refresh()

        self.assertEqual(result["mode"], "incremental")
        self.assertEqual(result["days"], 1)
        self.assertEqual(self.rollup("2026-09-27"), (1, 1))
        self.assertEqual(self.rollup("2026-09-28"), (1, 1))


if __name__ == "__main__":
    unittest.main()
