from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DAILY = ROOT / "ops/systemd/traffic-project-daily-rollups-aoe2hdbets.service"
PUBLIC_ARCHIVE = ROOT / "ops/systemd/traffic-public-audience-aoe2hdbets.service"
LOCK = "/run/traffic-rollups/aoe2hdbets.lock"


class SystemdContractTests(unittest.TestCase):
    def test_daily_rollup_treats_only_lock_contention_as_successful_skip(self) -> None:
        unit = DAILY.read_text(encoding="utf-8")
        self.assertIn(
            f"ExecStart=/usr/bin/flock -n -E 0 {LOCK} ",
            unit,
        )
        self.assertIn(
            "scripts/rebuild_project_daily_rollups.py --incremental --project aoe2hdbets",
            unit,
        )
        self.assertNotIn("SuccessExitStatus=1", unit)

    def test_shared_rollup_runtime_directory_is_preserved_across_oneshot_exit(self) -> None:
        for unit_path in (DAILY, PUBLIC_ARCHIVE):
            with self.subTest(unit=unit_path.name):
                unit = unit_path.read_text(encoding="utf-8")
                self.assertIn("RuntimeDirectory=traffic-rollups", unit)
                self.assertIn("RuntimeDirectoryMode=0755", unit)
                self.assertIn("RuntimeDirectoryPreserve=yes", unit)

    def test_public_archive_and_daily_rollup_share_one_serialization_lock(self) -> None:
        daily = DAILY.read_text(encoding="utf-8")
        archive = PUBLIC_ARCHIVE.read_text(encoding="utf-8")
        self.assertIn(LOCK, daily)
        self.assertIn(LOCK, archive)
        self.assertIn(f"ExecStart=/usr/bin/flock {LOCK} ", archive)
        self.assertNotIn(f"ExecStart=/usr/bin/flock -n {LOCK} ", archive)


if __name__ == "__main__":
    unittest.main()
