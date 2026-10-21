from __future__ import annotations

import argparse
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_forward_ip_supervisor as sup

SHA = "9c0457fea7b2d31456091a57b29c03e78437002a"


def starting(n=3000):
    return {
        "result": "READY_PRIVATE_PASS1",
        "forward_phase": "LIVE",
        "shadow_processed_events": n,
        "remaining_retained_events": 108764 - n,
        "publication_authorized": False,
        "daily_classification_ready": False,
        "private_ip_shadow_writes_only": True,
    }


def step(n, total, cursor, remaining):
    return {
        "result": "PRIVATE_PASS1_STEP",
        "step_input_events": n,
        "total_input_events_processed": total,
        "last_source_rowid": cursor,
        "remaining_retained_events": remaining,
        "publication_authorized": False,
        "daily_classification_ready": False,
        "private_ip_shadow_writes_only": True,
    }


class PrivateShadowSupervisorTests(unittest.TestCase):
    def args(self, **overrides):
        base = dict(
            source=Path("/tmp/source.db"), checkpoint=Path("/tmp/checkpoint.db"),
            ledger=Path("/tmp/future-ledger.db"),
            shadow=Path("/tmp/future-ip-shadow.db"),
            require_sha=SHA, max_steps=2, max_rows=3000,
            wall_seconds=120, step_timeout=25,
            min_data_gib=8, min_root_gib=4,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def guard_env(self):
        stack = __import__("contextlib").ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(sup, "check_timer_state"))
        stack.enter_context(patch.object(sup.guard, "resource_headroom"))
        stack.enter_context(patch.object(sup.guard, "worker_idle", return_value=True))
        stack.enter_context(patch.object(
            sup.guard, "cmd_output",
            side_effect=lambda *argv, **kw:
                SHA if argv[1:3] == ("rev-parse", "HEAD") else "",
        ))
        return stack

    def test_exactly_two_bounded_steps_and_no_public_write(self):
        self.guard_env()
        receipts = iter([
            starting(),
            step(3000, 6000, 10000, 102764),
            step(3000, 9000, 15000, 99764),
        ])
        calls = []
        def child(argv, **kw):
            calls.append(argv)
            return next(receipts)
        done = sup.supervise(self.args(), child=child)
        self.assertEqual(done["steps"], 2)
        self.assertEqual(done["events_added"], 6000)
        self.assertEqual(done["reason"], "max_steps")
        self.assertFalse(done["publication_authorized"])
        self.assertTrue(done["no_publication"])
        self.assertEqual(len(calls), 3)
        self.assertNotIn("--advance", calls[0])
        self.assertIn("--advance", calls[1])

    def test_stop_if_caught_up_early(self):
        self.guard_env()
        receipts = iter([starting(), step(0, 3000, 9999, 0)])
        done = sup.supervise(self.args(max_steps=6),
                             child=lambda *_args, **_kw: next(receipts))
        self.assertEqual(done["reason"], "source_caught_up")
        self.assertEqual(done["steps"], 1)
        self.assertEqual(done["events_added"], 0)

    def test_refuse_bootstrap_before_any_write(self):
        self.guard_env()
        before = {**starting(), "result": "BLOCKED_BOOTSTRAP",
                  "forward_phase": "BOOTSTRAP"}
        calls = []
        def child(cmd, **kw):
            calls.append(cmd)
            return before
        with self.assertRaisesRegex(RuntimeError, "not LIVE"):
            sup.supervise(self.args(), child=child)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--advance", calls[0])

    def test_reject_wrong_commit(self):
        self.guard_env()
        with self.assertRaisesRegex(RuntimeError, "release moved"):
            sup.supervise(self.args(require_sha="a"*40),
                          child=lambda *a, **kw: starting())

    def test_reject_dangerous_batch_size(self):
        self.guard_env()
        with self.assertRaisesRegex(RuntimeError, "max_rows"):
            sup.supervise(self.args(max_rows=3001),
                          child=lambda *a, **kw: starting())

    def test_caught_up_step_cannot_move_cursor(self):
        with self.assertRaisesRegex(RuntimeError, "cursor"):
            sup.check_receipt(
                starting(3000), step(0, 3000, 1001, 0),
                max_rows=3000, previous_cursor=1000,
            )

    def test_cursor_must_advance_on_nonempty_step(self):
        with self.assertRaisesRegex(RuntimeError, "cursor"):
            sup.check_receipt(
                starting(3000), step(3, 3003, 1000, 1),
                max_rows=3000, previous_cursor=1000,
            )

    def test_reject_wrong_total_progress(self):
        with self.assertRaisesRegex(RuntimeError, "processed cursor"):
            sup.check_receipt(
                starting(3000), step(3, 5000, 1000, 1),
                max_rows=3000, previous_cursor=None,
            )

    def test_reject_publication_authorized(self):
        with self.assertRaisesRegex(RuntimeError, "public publication"):
            sup.check_receipt(
                starting(3000),
                {**step(3, 3003, 1000, 1), "publication_authorized": True},
                max_rows=3000, previous_cursor=None,
            )

    def test_reject_batch_cap_overrun(self):
        with self.assertRaisesRegex(RuntimeError, "out-of-bounds"):
            sup.check_receipt(
                starting(3000), step(3001, 6001, 1000, 1),
                max_rows=3000, previous_cursor=None,
            )

    def test_readonly_preflight_child_timeout_fails_closed(self):
        with patch.object(sup.subprocess, "run", side_effect=subprocess.TimeoutExpired(
            cmd=["python"], timeout=1,
        )):
            with self.assertRaisesRegex(RuntimeError, "time bound"):
                sup.run_child(["python"], workdir=Path("/tmp"),
                              timeout_seconds=1)

    def test_child_safe_stop_fails_closed(self):
        fake = subprocess.CompletedProcess(
            args=["python"], returncode=2, stdout="",
            stderr="SAFE STOP: project rollup worker active",
        )
        with patch.object(sup.subprocess, "run", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "project rollup worker active"):
                sup.run_child(["python"], workdir=Path("/tmp"),
                              timeout_seconds=1)

    def test_child_success_parses_safe_json(self):
        fake = subprocess.CompletedProcess(
            args=["python"], returncode=0,
            stdout=json.dumps(starting())+"\n", stderr="",
        )
        with patch.object(sup.subprocess, "run", return_value=fake):
            outcome = sup.run_child(["python"], workdir=Path("/tmp"),
                                    timeout_seconds=1)
        self.assertEqual(outcome["result"], "READY_PRIVATE_PASS1")


if __name__ == "__main__":
    unittest.main()
