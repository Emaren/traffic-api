"""Only legitimate in-flight rollups yield an auditable successful no-op.

The scheduled private capture must never leave systemd failed purely because
its higher-priority production rollup is executing. Bad priority state, real
rollup failure, disabled timers, or malformed input all remain hard failure.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from scripts import public_audience_v2_forward_ledger as capture


class PriorityDeferTests(TestCase):
    def make_args(self, root: Path):
        private = root / "private"
        private.mkdir(mode=0o700)
        state = private / "checkpoint.sqlite3"
        state.write_bytes(b"test-protected-checkpoint")
        state.chmod(0o600)
        source = root / "traffic.sqlite3"
        source.write_bytes(b"read-only-source")
        return argparse.Namespace(
            checkpoint=state, source=source,
            ledger=private / "future-ledger.sqlite3",
            max_rows=3000, budget_seconds=12,
            advance=True, approve_private_write=True,
        )

    def check_state(self, state, result, expected_defer):
        with TemporaryDirectory() as tmp:
            args = self.make_args(Path(tmp))
            ledger_preexists = args.ledger.exists()
            def unit(prop):
                assert prop in ("ActiveState", "Result", "Type", "NeedDaemonReload")
                return {"ActiveState": state, "Result": result,
                        "Type": "oneshot", "NeedDaemonReload": "no"}[prop]
            with mock.patch.object(capture.guard, "require_worker_priority") as priority, \
                 mock.patch.object(capture.guard, "unit_state", side_effect=lambda u, p: unit(p)) as query, \
                 mock.patch.object(capture.guard, "checkpoint_info", side_effect=AssertionError("must not read checkpoint")):
                if expected_defer:
                    data = capture.execute(args)
                    self.assertEqual(data["status"], "DEFERRED_VERIFIED_ROLLUP_IN_PROGRESS")
                    self.assertEqual(data["mode"], "PRIVATE_LEDGER_NOOP")
                    self.assertFalse(data["private_ledger_advanced"])
                    self.assertFalse(data["public_audience_writes"])
                    self.assertFalse(data["publish_authorized"])
                    self.assertEqual(query.call_count, 4)
                else:
                    with self.assertRaisesRegex(RuntimeError, "STOP: (project rollup worker failed or unreviewed state|rollup worker in-flight but unsuccessful)"):
                        capture.execute(args)
                priority.assert_called_once()
            self.assertEqual(args.ledger.exists(), ledger_preexists)
            self.assertEqual(args.checkpoint.read_bytes(), b"test-protected-checkpoint")
            self.assertEqual(args.source.read_bytes(), b"read-only-source")

    def test_activating_rollup_defers_without_writes(self):
        self.check_state("activating", "success", True)

    def test_active_rollup_defers_without_writes(self):
        self.check_state("active", "success", True)

    def test_deactivating_rollup_defers_without_writes(self):
        self.check_state("deactivating", "success", True)

    def test_failed_rollup_is_not_silently_treated_as_busy(self):
        self.check_state("failed", "exit-code", False)

    def test_unknown_idle_rollup_is_not_treated_as_healthy(self):
        self.check_state("inactive", "exit-code", False)

    def test_unknown_rollup_state_is_denied(self):
        self.check_state("reloading", "success", False)

    def test_active_with_failed_result_is_denied(self):
        self.check_state("active", "exit-code", False)

    def test_wrong_service_type_or_pending_reload_denied(self):
        for field, value in (("Type", "simple"), ("NeedDaemonReload", "yes")):
            with self.subTest(field=field), TemporaryDirectory() as tmp:
                args = self.make_args(Path(tmp))
                props = {"ActiveState": "active", "Result": "success",
                         "Type": "oneshot", "NeedDaemonReload": "no"}
                props[field] = value
                with mock.patch.object(capture.guard, "require_worker_priority"), \
                     mock.patch.object(capture.guard, "unit_state",
                                       side_effect=lambda unit, name: props[name]), \
                     mock.patch.object(capture.guard, "checkpoint_info",
                                       side_effect=AssertionError("unsafe source")):
                    with self.assertRaisesRegex(RuntimeError, "service type or loaded source changed"):
                        capture.execute(args)
                self.assertFalse(args.ledger.exists())

    def test_disabled_priority_timer_denied_even_when_worker_active(self):
        with TemporaryDirectory() as tmp:
            args = self.make_args(Path(tmp))
            with mock.patch.object(capture.guard, "require_worker_priority", side_effect=RuntimeError("STOP: priority timer disabled")), \
                 mock.patch.object(capture.guard, "unit_state") as query:
                with self.assertRaisesRegex(RuntimeError, "priority timer disabled"):
                    capture.execute(args)
                query.assert_not_called()

    def test_missing_checkpoint_denied_before_priority_check(self):
        with TemporaryDirectory() as tmp:
            args = self.make_args(Path(tmp))
            args.checkpoint.unlink()
            with mock.patch.object(capture.guard, "require_worker_priority") as priority:
                with self.assertRaisesRegex(RuntimeError, "verified historical checkpoint missing"):
                    capture.execute(args)
                priority.assert_not_called()

if __name__ == "__main__":
    import unittest
    unittest.main()
