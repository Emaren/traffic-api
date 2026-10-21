from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

from app.services.traffic import persistence


def legacy_entries(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE traffic_entries (
            event_id TEXT PRIMARY KEY, source_path TEXT NOT NULL,
            source_inode INTEGER NOT NULL, line_offset INTEGER NOT NULL,
            timestamp TEXT NOT NULL, ip TEXT NOT NULL,
            request TEXT NOT NULL, method TEXT NOT NULL,
            raw_path TEXT NOT NULL, normalized_path TEXT NOT NULL,
            status INTEGER NOT NULL, referrer TEXT NOT NULL,
            referrer_host TEXT NOT NULL, ua TEXT NOT NULL,
            host TEXT NOT NULL, raw TEXT NOT NULL
        )
    """)


def row(event_id: str = "fixture"):
    return (
        event_id, "/dev/null", 1, 13,
        "2026-10-20T04:11:00+00:00",
        "203.0.113.1", "GET / HTTP/1.1", "GET",
        "/", "/", 200, "", "", "Mozilla",
        "aoe2war.com", "fixture",
    )


class TrafficInsertionClockTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)

    def test_legacy_add_column_idempotent_no_backfill(self):
        legacy_entries(self.conn)
        self.conn.execute("""
            INSERT INTO traffic_entries (
                event_id, source_path, source_inode, line_offset,
                timestamp, ip, request, method, raw_path,
                normalized_path, status, referrer, referrer_host,
                ua, host, raw
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, row("old-event"))
        persistence._ensure_ingestion_clock_column(self.conn)
        persistence._ensure_ingestion_clock_column(self.conn)
        columns = [r[1] for r in self.conn.execute(
            "PRAGMA table_info(traffic_entries)"
        )]
        self.assertEqual(columns.count("ingested_at_utc"), 1)
        self.assertIsNone(self.conn.execute(
            "SELECT ingested_at_utc FROM traffic_entries "
            "WHERE event_id='old-event'"
        ).fetchone()[0])

    def test_new_insert_has_sqlite_clock_not_log_event_clock(self):
        legacy_entries(self.conn)
        persistence._ensure_ingestion_clock_column(self.conn)
        persistence._insert_entry_batches(self.conn, [row()])
        value = self.conn.execute(
            "SELECT ingested_at_utc FROM traffic_entries "
            "WHERE event_id='fixture'"
        ).fetchone()[0]
        self.assertIsNotNone(value)
        self.assertTrue(value.endswith("+00:00"))
        inserted = datetime.fromisoformat(value)
        self.assertLess(abs(
            (datetime.now(timezone.utc) - inserted).total_seconds()
        ), 10.0)
        self.assertNotEqual(value, row()[4])

    def test_duplicate_event_cannot_rewrite_original_receipt(self):
        legacy_entries(self.conn)
        persistence._ensure_ingestion_clock_column(self.conn)
        persistence._insert_entry_batches(self.conn, [row("duplicate")])
        original = self.conn.execute(
            "SELECT ingested_at_utc FROM traffic_entries "
            "WHERE event_id='duplicate'"
        ).fetchone()[0]
        persistence._insert_entry_batches(self.conn, [row("duplicate")])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM traffic_entries "
            "WHERE event_id='duplicate'"
        ).fetchone()[0], 1)
        self.assertEqual(self.conn.execute(
            "SELECT ingested_at_utc FROM traffic_entries "
            "WHERE event_id='duplicate'"
        ).fetchone()[0], original)

    def test_real_schema_upgrade_keeps_legacy_rows_null(self):
        legacy_entries(self.conn)
        self.conn.execute("""
            INSERT INTO traffic_entries (
                event_id, source_path, source_inode, line_offset,
                timestamp, ip, request, method, raw_path,
                normalized_path, status, referrer, referrer_host,
                ua, host, raw
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, row("legacy-untouched"))
        # _ensure_schema must be tested via its actual implementation,
        # not only the isolated ALTER helper.
        with patch.object(persistence, "_SCHEMA_READY", False):
            persistence._ensure_schema(self.conn)
        cols = {r[1] for r in self.conn.execute(
            "PRAGMA table_info(traffic_entries)"
        )}
        self.assertIn("ingested_at_utc", cols)
        self.assertIsNone(self.conn.execute(
            "SELECT ingested_at_utc FROM traffic_entries "
            "WHERE event_id='legacy-untouched'"
        ).fetchone()[0])
        persistence._insert_entry_batches(self.conn, [row("new-after-upgrade")])
        self.assertIsNotNone(self.conn.execute(
            "SELECT ingested_at_utc FROM traffic_entries "
            "WHERE event_id='new-after-upgrade'"
        ).fetchone()[0])

    def test_empty_table_migration_works(self):
        legacy_entries(self.conn)
        persistence._ensure_ingestion_clock_column(self.conn)
        self.assertIn("ingested_at_utc", {
            r[1] for r in self.conn.execute(
                "PRAGMA table_info(traffic_entries)"
            )
        })


if __name__ == "__main__":
    unittest.main()
