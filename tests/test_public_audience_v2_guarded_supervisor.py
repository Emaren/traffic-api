from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_guarded_supervisor as supervisor


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.state = self.dir / "checkpoint.sqlite3"
        self.source = self.dir / "raw.sqlite3"
        self.source.write_bytes(b"read-only source placeholder")
        with sqlite3.connect(self.state) as db:
            db.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
            db.executemany("INSERT INTO metadata VALUES(?,?)", [
                ("phase", "PASS2_RUNNING"),
                ("p2_raw", "4471344"),
                ("p2_accepted", "4471344"),
            ])
        os.chmod(self.state, 0o600)
        self.args = argparse.Namespace(
            source=self.source, state=self.state, require_sha="pinned",
            total_seconds=300, window_seconds=60, max_windows=1,
            worker_poll_seconds=5, worker_wait_seconds=60,
        )

    def create_receipt(self, *, reason="max_steps", count=4491344,
                       phase="PASS2_RUNNING", steps=1):
        path = self.dir / "v2-pass2-guarded-test.jsonl"
        data = [
            {"event": "START", "source_sha": "pinned",
             "publication_authorized": False},
            *([{"event": "STEP", "total_raw": count, "peak_rss_kib": 90000,
               "performance": {"max_closed_session_events": 120}}] * steps),
            {"event": "STOP", "reason": reason, "steps": steps,
             "p2_raw": count, "phase": phase,
             "publication_authorized": False},
        ]
        path.write_text("".join(json.dumps(x) + "\n" for x in data))
        os.chmod(path, 0o600)
        return path

    @staticmethod
    def fake_git(*args, cwd=None):
        return "pinned" if "rev-parse" in args else ""

    def protections(self):
        return (
            patch.object(supervisor.replay, "cmd_output", side_effect=self.fake_git),
            patch.object(supervisor.replay, "verify_frozen"),
            patch.object(supervisor.replay, "require_worker_priority"),
            patch.object(supervisor.replay, "resource_headroom"),
            patch.object(supervisor, "require_memory"),
            patch.object(supervisor, "wait_for_worker", return_value=True),
        )

    def test_receipt_accepts_only_expected_private_window(self):
        path = self.create_receipt()
        report = supervisor.read_window_receipt(path, source_sha="pinned")
        self.assertEqual(report["steps"], 1)
        self.assertEqual(report["p2_raw"], 4491344)
        self.assertEqual(report["peak_rss_kib"], 90000)
        self.assertEqual(report["max_closed_session_events"], 120)
        self.assertNotIn("private-ip", json.dumps(report))
        with self.assertRaisesRegex(RuntimeError, "source drift"):
            supervisor.read_window_receipt(path, source_sha="another")
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(RuntimeError, "private"):
            supervisor.read_window_receipt(path, source_sha="pinned")

    def test_missing_stop_or_failure_is_denied(self):
        path = self.create_receipt()
        items = [json.loads(s) for s in path.read_text().splitlines()]
        items[-1]["event"] = "FAIL"
        path.write_text("".join(json.dumps(x)+"\n" for x in items))
        with self.assertRaisesRegex(RuntimeError, "without STOP"):
            supervisor.read_window_receipt(path, source_sha="pinned")

    def test_supervisor_advances_exactly_one_verified_window(self):
        class FakeProcess:
            returncode = 0
            pid = 123456

            def communicate(self, timeout=None):
                with sqlite3.connect(self_state) as db:
                    db.execute(
                        "UPDATE metadata SET value='4491344' WHERE key='p2_raw'"
                    )
                test.create_receipt()
                return ("", "")

        self_state = self.state
        test = self
        with ExitStack() as stack:
            for p in self.protections():
                stack.enter_context(p)
            stack.enter_context(
                patch.object(supervisor.subprocess, "Popen", return_value=FakeProcess())
            )
            self.assertEqual(supervisor.run(self.args), 0)
        self.assertEqual(
            supervisor.replay.checkpoint_info(self.state)["p2_raw"], "4491344"
        )

    def test_supervisor_stops_if_priority_worker_does_not_yield(self):
        with ExitStack() as stack:
            for p in self.protections():
                stack.enter_context(p)
            stack.enter_context(
                patch.object(supervisor, "wait_for_worker", return_value=False)
            )
            child = stack.enter_context(
                patch.object(supervisor.subprocess, "Popen")
            )
            self.assertEqual(supervisor.run(self.args), 3)
            child.assert_not_called()
        self.assertEqual(
            supervisor.replay.checkpoint_info(self.state)["p2_raw"], "4471344"
        )

    def test_supervisor_stops_on_soft_memory_hit_without_repeating(self):
        class FakeProcess:
            returncode = 0
            pid = 123456

            def communicate(self, timeout=None):
                with sqlite3.connect(self_state) as db:
                    db.execute("UPDATE metadata SET value='4491344' WHERE key='p2_raw'")
                test.create_receipt(reason="performance_soft_stop")
                return ("", "")

        self_state = self.state
        test = self
        self.args.max_windows = 3
        with ExitStack() as stack:
            for p in self.protections():
                stack.enter_context(p)
            child = stack.enter_context(
                patch.object(supervisor.subprocess, "Popen", return_value=FakeProcess())
            )
            self.assertEqual(supervisor.run(self.args), 3)
            child.assert_called_once()
        self.assertEqual(
            supervisor.replay.checkpoint_info(self.state)["p2_raw"], "4491344"
        )

    def test_operator_interrupt_kills_child_process_group(self):
        class FakeProcess:
            pid = 88319
            def poll(self):
                return None
            def wait(self, timeout=None):
                return 0

        original = supervisor._ACTIVE_CHILD
        try:
            supervisor._ACTIVE_CHILD = FakeProcess()
            with patch.object(supervisor.os, "killpg") as kill:
                with self.assertRaisesRegex(RuntimeError, "interrupted"):
                    supervisor._handle_operator_interrupt(signal.SIGHUP, None)
                kill.assert_called_once_with(88319, signal.SIGKILL)
        finally:
            supervisor._ACTIVE_CHILD = original

    def test_state_mode_and_unknown_cursor_refused_before_subprocess(self):
        os.chmod(self.state, 0o644)
        with self.assertRaisesRegex(RuntimeError, "mode 0600"):
            supervisor.run(self.args)


if __name__ == "__main__":
    unittest.main()
