from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

import app.services.traffic.browser_events as be


class AtomicPresenceBindingTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Path(directory.name) / "fixture.sqlite3"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE traffic_entries (host TEXT, timestamp TEXT, normalized_path TEXT, ip TEXT)")
        for name, value in (
            ("PERSIST_DB_PATH", self.db),
            ("PERSIST_ENABLED", True),
            ("_BROWSER_SCHEMA_READY", False),
            ("get_geo_details", lambda _ip: {}),
        ):
            override = patch.object(be, name, value)
            override.start()
            self.addCleanup(override.stop)
        with be._connect() as conn:
            be._ensure_schema(conn)
        self.payload = dict(
            host="aoe2war.com", path="/", visitor_id="fixture-visitor",
            session_id="fixture-session", authenticated_uid="fixture-account",
            authenticated_label="Fixture account", client_ip="192.0.2.1",
        )

    def store(self, **overrides):
        return be.record_authenticated_presence(dict(self.payload, **overrides))

    def snapshot(self):
        with sqlite3.connect(self.db) as conn:
            return tuple(
                tuple(conn.execute("SELECT * FROM " + table + " ORDER BY 1,2,3"))
                for table in ("traffic_browser_events", "traffic_browser_sessions")
            )

    def test_same_binding_refresh_commits_and_keeps_event_id(self):
        first = self.store()
        second = self.store(authenticated_label="Updated label")
        self.assertTrue(first["stored"] and second["stored"])
        self.assertEqual(first["event_id"], second["event_id"])
        events, sessions = self.snapshot()
        self.assertEqual((len(events), len(sessions)), (1, 1))
        self.assertIn("Updated label", str(events[0]))

    def test_cross_visitor_denied_without_mutation(self):
        self.store()
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            self.store(visitor_id="other-visitor")
        self.assertEqual(self.snapshot(), before)

    def test_account_change_requires_new_session(self):
        self.store()
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            self.store(authenticated_uid="other-account")
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.store(session_id="rotated-session",
                                   authenticated_uid="other-account")["stored"])
        self.assertEqual(len(self.snapshot()[0]), 2)

    def test_disabled_persistence_is_not_stored(self):
        before = self.snapshot()
        with patch.object(be, "PERSIST_ENABLED", False):
            self.assertIs(self.store()["stored"], False)
        self.assertEqual(self.snapshot(), before)

    def test_ambiguous_legacy_rows_fail_closed(self):
        self.store()
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO traffic_browser_events (received_at,occurred_at,host,project_slug,project_name,path,visitor_id,session_id,event_type,payload_json) "
                         "SELECT received_at,occurred_at,host,project_slug,project_name,path,visitor_id,session_id,event_type,payload_json FROM traffic_browser_events")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.store()
        self.assertEqual(self.snapshot(), before)

    def test_concurrent_conflicting_first_writes(self):
        barrier = threading.Barrier(2)
        def worker(visitor):
            barrier.wait(timeout=5)
            try:
                return ("stored", self.store(visitor_id=visitor)["event_id"])
            except ValueError:
                return ("rejected", None)
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(worker, v) for v in ("visitor-a", "visitor-b")]
            results = [job.result(timeout=10) for job in jobs]
        self.assertCountEqual([r[0] for r in results], ["stored", "rejected"])
        events, sessions = self.snapshot()
        self.assertEqual((len(events), len(sessions)), (1, 1))

    def test_concurrent_same_binding_reuses_one_row(self):
        barrier = threading.Barrier(2)
        def worker():
            barrier.wait(timeout=5)
            return self.store()["event_id"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(worker) for _ in range(2)]
            results = [job.result(timeout=10) for job in jobs]
        self.assertEqual(results[0], results[1])
        self.assertEqual(tuple(map(len, self.snapshot())), (1, 1))

    def test_propagation_isolated_by_project_visitor_and_session(self):
        base = dict(project_slug="aoe2hdbets", visitor_id="visitor-a", session_id="session-a")
        proof = dict(base, id=1, event_type="auth_presence",
                     received_at="2026-11-24T20:00:00Z", authenticated=True,
                     authenticated_uid="fixture-account")
        event = dict(base, event_type="click", received_at="2026-11-24T20:01:00Z",
                     authenticated=False)
        rows = [
            proof, dict(event, id=2), dict(event, id=3, visitor_id="visitor-b"),
            dict(event, id=4, project_slug="other-project"),
            dict(event, id=5, session_id="session-b"),
            dict(event, id=6, visitor_id=""),
        ]
        result = be._propagate_authenticated_identity(rows)
        self.assertTrue(result[1]["authenticated"])
        self.assertEqual(result[1]["authenticated_uid"], "fixture-account")
        for row in result[2:]:
            self.assertFalse(row["authenticated"])
            self.assertNotIn("authenticated_uid", row)


if __name__ == "__main__":
    unittest.main()
