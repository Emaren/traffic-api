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

    def test_per_host_day_bounds_equal_original_historical_aggregate(self) -> None:
        self.insert(day="2026-09-25", host="other.example")
        self.insert(day="2026-09-27", host=self.hosts[0])
        self.insert(day="2026-09-28", host=self.hosts[0])
        self.insert(day="2026-10-01", host="other.example")
        self.insert(day="2026-10-03", host="aoe2war-secondary.test")
        hosts = ["missing.example", self.hosts[0], "aoe2war-secondary.test"]
        actual = rollups.raw_day_bounds(self.conn, hosts)
        reference = self.conn.execute(
            "SELECT MIN(timestamp),MAX(timestamp) FROM traffic_entries "
            "WHERE host IN (?,?,?)", hosts,
        ).fetchone()
        self.assertEqual(actual, (
            date.fromisoformat(reference[0][:10]),
            date.fromisoformat(reference[1][:10]),
        ))
        self.assertEqual(rollups.raw_day_bounds(self.conn, ["missing.example"]), (None, None))
        self.assertEqual(rollups.raw_day_bounds(self.conn, []), (None, None))

    def test_unrelated_host_highwater_does_not_miss_later_project_append(self) -> None:
        self.insert(path="/")
        self.insert(host="unrelated.test", path="/")
        self.insert(host="unrelated.test", path="/")
        first = self.refresh()
        self.assertEqual(first["mode"], "incremental_bootstrap")
        self.assertEqual(first["watermark_rowid"], 3)
        self.assertEqual(self.rollup(), (1, 1))
        self.assertEqual(self.refresh()["mode"], "incremental_noop")
        self.insert(host="unrelated.test", path="/")
        unrelated = self.refresh()
        self.assertEqual(unrelated["mode"], "incremental")
        self.assertEqual(unrelated["days"], 0)
        self.assertEqual(unrelated["watermark_rowid"], 4)
        self.insert(path="/profile")
        new = self.refresh()
        self.assertEqual(new["mode"], "incremental")
        self.assertEqual(new["watermark_rowid"], 5)
        self.assertEqual(self.rollup(), (1, 2))
        self.assertEqual(self.refresh()["mode"], "incremental_noop")

    def test_index_probes_and_global_rowid_highwater_do_bounded_work(self) -> None:
        self.conn.execute(
            "CREATE INDEX idx_test_host_timestamp ON traffic_entries(host,timestamp)"
        )
        # Deliberately much more historical data than one new sample:
        # an aggregate MIN/MAX(host IN ...) would read all matching rows.
        self.conn.executemany(
            "INSERT INTO traffic_entries(timestamp,host,status,method,ua,normalized_path,ip)"
            " VALUES(?,?,200,'GET','Mozilla/5.0','/','203.0.113.10')",
            [
                (f"2026-09-{1 + n % 28:02d}T12:00:00+00:00", self.hosts[0])
                for n in range(4000)
            ],
        )
        self.conn.commit()
        calls = [0]
        def instructions() -> int:
            calls[0] += 1
            return 1 if calls[0] > 300 else 0
        self.conn.set_progress_handler(instructions, 100)
        try:
            first, last = rollups.raw_day_bounds(self.conn, self.hosts)
            watermark = rollups._project_max_rowid(self.conn, self.hosts)
        finally:
            self.conn.set_progress_handler(None, 0)
        self.assertEqual(first, date(2026, 9, 1))
        self.assertEqual(last, date(2026, 9, 28))
        self.assertEqual(watermark, 4000)
        self.assertLess(calls[0], 300)

    def test_incremental_range_uses_primary_rowid_not_historical_host_index(self) -> None:
        self.conn.execute(
            "CREATE INDEX idx_test_host_timestamp ON traffic_entries(host,timestamp)"
        )
        self.insert(host="aoe2war.test")
        self.insert(host="unrelated.test")
        plan = self.conn.execute(
            "EXPLAIN QUERY PLAN SELECT rowid FROM traffic_entries NOT INDEXED "
            "WHERE host IN (?) AND rowid>? AND rowid<=?",
            ("aoe2war.test", 0, 2),
        ).fetchall()
        details = " ".join(str(row["detail"]) for row in plan)
        self.assertIn("INTEGER PRIMARY KEY", details)
        self.assertIn("rowid>?", details)
        self.assertNotIn("idx_test_host_timestamp", details)
        fetched = rollups._load_new_eligible_path_rows(
            self.conn, hosts=self.hosts, after_rowid=0, through_rowid=2,
        )
        self.assertEqual(len(fetched), 1)
        self.assertEqual(fetched[0]["hits"], 1)

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
