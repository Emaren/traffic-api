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
        self.assertIn("ReadWritePaths=/mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA", content)
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
        self.assertIn("OnUnitInactiveSec=5min", timer)
        self.assertIn("Unit=traffic-v2-forward-ledger-aoe2hdbets.service", timer)
        self.assertNotIn("traffic-public-audience-aoe2hdbets.service", timer)
        self.assertNotIn("ExecStart", timer)


if __name__ == "__main__":
    unittest.main()
