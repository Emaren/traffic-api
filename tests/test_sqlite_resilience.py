from __future__ import annotations

import asyncio
import inspect
import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import app.main as main
import app.services.traffic.browser_events as browser_events
import app.services.traffic.persistence as persistence
import scripts.rebuild_project_daily_rollups as rollups


class SQLiteResilienceTests(unittest.TestCase):
    def test_closing_connection_context_owns_connection_lifetime(self) -> None:
        from app.services.traffic.sqlite_utils import connect

        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "lifetime.sqlite3"
            with connect(db) as connection:
                connection.execute("CREATE TABLE proof (value INTEGER)")
                connection.execute("INSERT INTO proof(value) VALUES (1)")
            with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed database"):
                connection.execute("SELECT 1")

    def test_health_endpoints_are_async_and_threadpool_independent(self) -> None:
        self.assertTrue(inspect.iscoroutinefunction(main.healthz))
        self.assertTrue(inspect.iscoroutinefunction(main.api_healthz))
        payload = asyncio.run(main.api_healthz())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["service"], "traffic-api")

    def test_browser_schema_reconciliation_runs_once_per_process(self) -> None:
        connection = MagicMock()
        original = browser_events._BROWSER_SCHEMA_READY
        browser_events._BROWSER_SCHEMA_READY = False
        try:
            with patch.object(browser_events, "_ensure_schema_body") as body:
                browser_events._ensure_schema(connection)
                browser_events._ensure_schema(connection)
            body.assert_called_once_with(connection)
            connection.commit.assert_called_once_with()
        finally:
            browser_events._BROWSER_SCHEMA_READY = original

    def test_insert_entry_batches_commits_each_bounded_chunk(self) -> None:
        connection = MagicMock()
        row = tuple(range(16))
        rows = [row for _ in range(5)]
        persistence._insert_entry_batches(connection, rows, batch_rows=2)
        self.assertEqual(connection.executemany.call_count, 3)
        self.assertEqual(connection.commit.call_count, 3)
        sizes = [len(call.args[1]) for call in connection.executemany.call_args_list]
        self.assertEqual(sizes, [2, 2, 1])

    def test_insert_entry_batches_rejects_nonpositive_chunk(self) -> None:
        with self.assertRaisesRegex(ValueError, "batch_rows must be positive"):
            persistence._insert_entry_batches(MagicMock(), [], batch_rows=0)

    def test_retention_prune_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "traffic.sqlite3"
            connection = sqlite3.connect(db)
            connection.execute(
                "CREATE TABLE traffic_entries (timestamp TEXT NOT NULL)"
            )
            connection.executemany(
                "INSERT INTO traffic_entries(timestamp) VALUES (?)",
                [
                    ("2020-01-01T00:00:00+00:00",),
                    ("2020-01-02T00:00:00+00:00",),
                    ("2020-01-03T00:00:00+00:00",),
                    ("2099-01-01T00:00:00+00:00",),
                ],
            )
            connection.commit()
            removed = persistence._prune_old_entries_bounded(connection, limit=2)
            connection.commit()
            remaining = connection.execute(
                "SELECT timestamp FROM traffic_entries ORDER BY timestamp"
            ).fetchall()
            connection.close()
        self.assertEqual(removed, 2)
        self.assertEqual(
            [row[0] for row in remaining],
            ["2020-01-03T00:00:00+00:00", "2099-01-01T00:00:00+00:00"],
        )

    def test_opportunistic_retention_lock_contention_is_clean_skip(self) -> None:
        original = persistence._LAST_RETENTION_PRUNE_MONOTONIC
        persistence._LAST_RETENTION_PRUNE_MONOTONIC = 0.0
        fake_connection = MagicMock()
        fake_connection.execute.side_effect = sqlite3.OperationalError(
            "database is locked"
        )
        try:
            with (
                patch.object(persistence.time, "monotonic", return_value=1000.0),
                patch.object(persistence.sqlite3, "connect", return_value=fake_connection),
            ):
                self.assertEqual(persistence._maybe_prune_old_entries(), 0)
            fake_connection.rollback.assert_called_once_with()
            fake_connection.close.assert_called_once_with()
        finally:
            persistence._LAST_RETENTION_PRUNE_MONOTONIC = original

    def test_rollup_retries_only_database_locked_failures(self) -> None:
        connection = MagicMock()
        with (
            patch.object(
                rollups,
                "upsert_project_day",
                side_effect=[
                    sqlite3.OperationalError("database is locked"),
                    sqlite3.OperationalError("database is locked"),
                    None,
                ],
            ) as upsert,
            patch.object(rollups.time, "sleep") as sleep,
        ):
            rollups.upsert_project_day_with_retry(
                connection,
                project_slug="aoe2hdbets",
                bucket_day=date(2026, 9, 9),
                visitors=67,
                events=176,
                attempts=3,
                retry_delay_seconds=0.25,
            )
        self.assertEqual(upsert.call_count, 3)
        self.assertEqual(connection.rollback.call_count, 2)
        connection.commit.assert_called_once_with()
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.25, 0.5])

    def test_rollup_does_not_retry_non_lock_sqlite_failure(self) -> None:
        connection = MagicMock()
        with (
            patch.object(
                rollups,
                "upsert_project_day",
                side_effect=sqlite3.OperationalError("disk I/O error"),
            ) as upsert,
            patch.object(rollups.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(sqlite3.OperationalError, "disk I/O error"):
                rollups.upsert_project_day_with_retry(
                    connection,
                    project_slug="aoe2hdbets",
                    bucket_day=date(2026, 9, 9),
                    visitors=67,
                    events=176,
                )
        upsert.assert_called_once()
        connection.rollback.assert_called_once_with()
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
