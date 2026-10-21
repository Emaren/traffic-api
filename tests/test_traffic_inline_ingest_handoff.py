"""Stage-2 opt-in inline-ingest handoff; worker path stays independent.

These are focused behavioral tests, not only static source assertions.
"""
from __future__ import annotations

import os
import sqlite3
import unittest
from unittest.mock import patch

from app.services.traffic import notifications, persistence
from scripts import sync_traffic_logs


class InlineIngestHandoffTests(unittest.TestCase):
    def test_absent_or_malformed_flag_preserves_inline_ingest(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(persistence.inline_log_sync_disabled())
        for value in ("", "0", "false", "off", "no", "maybe", "unsupported"):
            with self.subTest(value=value), patch.dict(
                os.environ, {"TRAFFIC_DISABLE_INLINE_INGEST": value},
            ):
                self.assertFalse(persistence.inline_log_sync_disabled())

    def test_explicit_flag_disables_only_inline_ingest(self):
        for value in ("1", "TRUE", " yes ", "ON"):
            with self.subTest(value=value), patch.dict(
                os.environ, {"TRAFFIC_DISABLE_INLINE_INGEST": value},
            ):
                self.assertTrue(persistence.inline_log_sync_disabled())

    def snapshot(self, value: str):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("""
            CREATE TABLE traffic_entries(
                timestamp TEXT, line_offset INTEGER, ip TEXT,
                raw_path TEXT, normalized_path TEXT, referrer_host TEXT,
                ua TEXT, host TEXT)
        """)
        with (
            patch.dict(os.environ, {"TRAFFIC_DISABLE_INLINE_INGEST": value}),
            patch.object(persistence, "persistence_enabled", return_value=True),
            patch.object(persistence, "sync_configured_logs_to_persistence") as sync,
            patch.object(persistence, "_connect", return_value=db),
            patch.object(persistence, "_ensure_schema"),
        ):
            rows = persistence.load_recent_entries(
                window_hours=24, log_paths=(), include_raw_fields=False,
            )
        self.assertEqual(rows, [])
        return sync

    def test_recent_snapshots_still_sync_by_default(self):
        self.snapshot("0").assert_called_once_with(())

    def test_recent_snapshots_skip_sync_only_after_explicit_optin(self):
        self.snapshot("1").assert_not_called()

    def notifications_case(self, value: str):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        no_browser = {"checked": 0, "delivered": 0, "suppressed": 0, "errors": 0}
        with (
            patch.dict(os.environ, {"TRAFFIC_DISABLE_INLINE_INGEST": value}),
            patch.object(notifications, "persistence_enabled", return_value=True),
            patch.object(notifications, "get_notification_settings",
                         return_value={"enabled": True, "provider": "fixture"}),
            patch.object(notifications, "_provider_ready", return_value=True),
            patch.object(notifications, "sync_configured_logs_to_persistence") as sync,
            patch.object(notifications, "_connect", return_value=db),
            patch.object(notifications, "_ensure_schema"),
            patch.object(notifications, "list_operator_identities", return_value=[]),
            patch.object(notifications, "list_notification_mutes", return_value=[]),
            patch.object(notifications, "_load_unprocessed_candidates",
                         return_value=[]),
            patch.object(notifications, "_process_browser_notification_candidates",
                         return_value=no_browser),
        ):
            result = notifications.process_notification_batch(limit=5)
        self.assertEqual(result["mode"], "running")
        return sync

    def test_notification_path_still_syncs_by_default(self):
        self.notifications_case("0").assert_called_once_with()

    def test_notification_path_skips_sync_when_timer_owns_ingestion(self):
        self.notifications_case("1").assert_not_called()

    def test_standalone_worker_still_ingests_when_inline_is_off(self):
        with (
            patch.dict(os.environ, {"TRAFFIC_DISABLE_INLINE_INGEST": "1"}),
            patch.object(sync_traffic_logs, "persistence_enabled", return_value=True),
            patch.object(sync_traffic_logs, "sync_configured_logs_to_persistence",
                         return_value=[{"mode": "persisted", "inserted": 1}]) as sync,
        ):
            self.assertEqual(sync_traffic_logs.main(), 0)
        sync.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
