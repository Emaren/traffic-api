from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_guarded_resume as runner


class RecoveryGuardsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.raw = self.dir / "raw.sqlite3"
        self.raw.write_bytes(b"not actually used by mocked source verification")
        self.state = self.dir / "checkpoint.sqlite3"
        self.start_info = {
            "phase": "PASS2_RUNNING",
            "raw_scanned": str(runner.FROZEN_ROWS),
            "accepted": str(runner.FROZEN_ACCEPTED),
            "p1_digest": runner.FROZEN_DIGEST,
            "watermark": "44247247",
            "start": "2026-05-22T00:00:00+00:00",
            "end": "2026-10-20T00:00:00+00:00",
            "p2_raw": "51344",
            "p2_accepted": "51344",
            "p2_digest": "a"*64,
        }
        with sqlite3.connect(self.state) as db:
            db.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
            db.executemany("INSERT INTO metadata VALUES(?,?)",
                           self.start_info.items())
        os.chmod(self.state, 0o600)
        self.args = argparse.Namespace(
            source=self.raw, state=self.state, require_sha="pinned",
            max_steps=1, wall_seconds=120, rows_per_step=20000,
            budget_seconds=25, hard_seconds=35, max_elapsed_seconds=18.,
            max_rss_kib=196608, min_data_gib=12, min_root_gib=6,
        )

    def fake_git(self, *args, cwd=None):
        return "pinned" if "rev-parse" in args else ""

    def advance(self, *args, **kwargs):
        with sqlite3.connect(self.state) as db:
            db.execute(
                "UPDATE metadata SET value=? WHERE key='p2_raw'", ("71344",)
            )
            db.execute(
                "UPDATE metadata SET value=? WHERE key='p2_accepted'", ("71344",)
            )
        return ({"total_raw": 71344}, 2.5, 80368)

    def protections(self):
        return (
            patch.object(runner, "cmd_output", side_effect=self.fake_git),
            patch.object(runner, "require_worker_priority"),
            patch.object(runner, "resource_headroom"),
            patch.object(runner, "worker_idle", return_value=True),
            patch.object(runner.sessions, "verified_state",
                         return_value=(["aoe2war.com"], [])),
        )

    def test_frozen_checkpoint_counts_digest_and_policy(self):
        with patch.object(runner.sessions, "verified_state",
                          return_value=(["aoe2war.com"], [])):
            runner.verify_frozen(self.raw, self.state, self.start_info)
            broken = {**self.start_info, "p1_digest": "0"*64}
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                runner.verify_frozen(self.raw, self.state, broken)
            completed = {**self.start_info, "phase": "PASS2_COMPLETE"}
            with self.assertRaisesRegex(RuntimeError, "final raw parity"):
                runner.verify_frozen(self.raw, self.state, completed)

    def test_positive_run_emits_private_start_step_stop_receipts(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for protection in self.protections():
                stack.enter_context(protection)
            stack.enter_context(
                patch.object(runner, "run_one", side_effect=self.advance)
            )
            self.assertEqual(runner.run(self.args), 0)
        receipts = list(self.dir.glob("v2-pass2-guarded-*.jsonl"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0].stat().st_mode & 0o777, 0o600)
        events = [json.loads(line) for line in receipts[0].read_text().splitlines()]
        self.assertEqual([r["event"] for r in events], ["START", "STEP", "STOP"])
        self.assertEqual(events[1]["total_raw"], 71344)
        self.assertEqual(events[2]["reason"], "max_steps")
        self.assertFalse(any(r["publication_authorized"] for r in events))
        self.assertEqual(runner.checkpoint_info(self.state)["p2_raw"], "71344")

    def test_child_failure_receipted_and_checkpoint_not_advanced(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for protection in self.protections():
                stack.enter_context(protection)
            stack.enter_context(patch.object(
                runner, "run_one", side_effect=RuntimeError("simulated failure")
            ))
            with self.assertRaisesRegex(RuntimeError, "simulated failure"):
                runner.run(self.args)
        receipts = list(self.dir.glob("v2-pass2-guarded-*.jsonl"))
        self.assertEqual(len(receipts), 1)
        events = [json.loads(line) for line in receipts[0].read_text().splitlines()]
        self.assertEqual([r["event"] for r in events], ["START", "FAIL"])
        self.assertEqual(runner.checkpoint_info(self.state)["p2_raw"], "51344")

    def test_busy_worker_yields_without_replaying(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for protection in self.protections():
                stack.enter_context(protection)
            stack.enter_context(patch.object(runner, "worker_idle", return_value=False))
            call = stack.enter_context(patch.object(runner, "run_one"))
            self.assertEqual(runner.run(self.args), 0)
            call.assert_not_called()
        receipts = list(self.dir.glob("v2-pass2-guarded-*.jsonl"))
        events = [json.loads(line) for line in receipts[0].read_text().splitlines()]
        self.assertEqual(events[-1]["reason"], "project_worker_priority")
        self.assertEqual(runner.checkpoint_info(self.state)["p2_raw"], "51344")

    def test_world_readable_checkpoint_denied(self):
        os.chmod(self.state, 0o644)
        with self.assertRaisesRegex(RuntimeError, "mode 0600"):
            runner.run(self.args)


if __name__ == "__main__":
    unittest.main()
