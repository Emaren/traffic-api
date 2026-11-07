from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "ops/systemd/traffic-v2-forward-ledger-aoe2hdbets.service"
TIMER = ROOT / "ops/systemd/traffic-v2-forward-ledger-aoe2hdbets.timer"


class PrivateForwardLedgerUnitTests(unittest.TestCase):
    def test_private_worker_can_only_write_private_canary_artifacts(self):
        content = SERVICE.read_text()
        self.assertIn("ProtectSystem=strict", content)
        self.assertIn("NoNewPrivileges=yes", content)
        self.assertIn("PrivateTmp=yes", content)
        self.assertIn("UMask=0077", content)
        self.assertIn("MemoryMax=512M", content)
        self.assertIn("TimeoutStartSec=50s", content)
        self.assertIn(
            "ReadWritePaths=/mnt/HC_Volume_105319120/traffic-v2-shadow/"
            "canary-oocB0WuA /mnt/HC_Volume_105319120/traffic-db",
            content,
        )
        self.assertIn(
            "ReadOnlyPaths=/mnt/HC_Volume_105319120/traffic-db/"
            "traffic_history.sqlite3 -/mnt/HC_Volume_105319120/traffic-db/"
            "traffic_history.sqlite3-wal",
            content,
        )
        self.assertNotIn("ReadWritePaths=/mnt/HC_Volume_105319120/traffic-db\\n", content)
        self.assertIn("ProtectSystem=strict", content)
        self.assertIn("NoNewPrivileges=yes", content)
        self.assertIn("--checkpoint ", content)
        self.assertIn("--ledger ", content)
        self.assertIn("--max-rows 3000", content)
        self.assertIn("--budget-seconds 12", content)
        self.assertIn("--advance --approve-private-write", content)
        self.assertNotIn("rebuild_public_audience_archive", content)
        self.assertNotIn("public_audience_v2_atomic_publish", content)
        self.assertNotIn("--apply", content)

    def test_timer_only_targets_private_evidence_job(self):
        timer = TIMER.read_text()
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertNotIn("OnUnitInactiveSec=", timer)
        self.assertIn("OnBootSec=5min", timer)
        self.assertIn("AccuracySec=15s", timer)
        self.assertIn("RandomizedDelaySec=30s", timer)
        self.assertIn("Unit=traffic-v2-forward-ledger-aoe2hdbets.service", timer)
        self.assertNotIn("traffic-public-audience-aoe2hdbets.service", timer)
        self.assertNotIn("ExecStart", timer)

    def test_verified_in_progress_collision_defers_but_real_failures_still_stop(self):
        code = (ROOT / "scripts/public_audience_v2_forward_ledger.py").read_text()
        guard = (ROOT / "scripts/public_audience_v2_guarded_resume.py").read_text()
        service = SERVICE.read_text()
        timer = TIMER.read_text()
        self.assertIn('require(guard.worker_idle(), "project rollup worker active")', code)
        self.assertIn('"DEFERRED_VERIFIED_ROLLUP_IN_PROGRESS"', code)
        self.assertIn('"PRIVATE_LEDGER_NOOP"', code)
        self.assertIn('"private_ledger_advanced": False', code)
        self.assertIn('worker_result == "success"', code)
        self.assertIn('project rollup worker failed or unreviewed state', code)
        self.assertIn('print("SAFE STOP:", type(exc).__name__, str(exc)', code)
        self.assertIn("return 2", code)
        self.assertIn('unit_state(WORKER + ".service", "ActiveState") == "inactive"',guard)
        self.assertIn('unit_state(WORKER + ".service", "Result") == "success"',guard)
        self.assertIn("OnUnitActiveSec=5min",timer)
        self.assertNotIn("OnUnitInactiveSec=",timer)
        self.assertNotIn("Restart=always",service)
        for critical in ("PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX",
                         "NoNewPrivileges=yes","ProtectSystem=strict",
                         "CapabilityBoundingSet=",
                         "--advance --approve-private-write"):
            self.assertIn(critical,service)
        self.assertNotIn("OnFailure=",timer)
        self.assertNotIn("OnFailure=",service)


if __name__ == "__main__":
    unittest.main()
