"""Static acceptance for the existing nonroot V2 publisher systemd path.

These tests never talk to systemd, use a real source database or sign a day.
Root/owner approval, real source certificates and a natural timer trigger are
separate physical deployment proofs.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "ops/systemd/traffic-v2-publisher.service"
TIMER = ROOT / "ops/systemd/traffic-v2-publisher.timer"
SOURCE = ROOT / "scripts/public_audience_v2_runner.py"
RECONCILE = ROOT / "scripts/public_audience_v2_production_reconciliation.py"


class ProductionV2PublisherUnits(unittest.TestCase):
    def test_names_exactly_match_existing_production_reconciliation(self):
        code = RECONCILE.read_text()
        self.assertIn('PUBLISHER_TIMER = "traffic-v2-publisher.timer"', code)
        self.assertIn('PUBLISHER_SERVICE = "traffic-v2-publisher.service"', code)
        self.assertEqual(SERVICE.name, "traffic-v2-publisher.service")
        self.assertEqual(TIMER.name, "traffic-v2-publisher.timer")

    def test_runs_only_nonroot_qualified_existing_publisher(self):
        s = SERVICE.read_text()
        self.assertRegex(s, r"(?m)^User=tony$")
        self.assertRegex(s, r"(?m)^Group=tony$")
        self.assertNotRegex(s, r"(?m)^User=root$")
        self.assertIn("python3 -B -m scripts.public_audience_v2_runner --once", s)
        self.assertNotIn("public_audience_v2_forward_ledger --", s)
        self.assertNotIn("rebuild_public_audience_archive", s)
        self.assertNotIn("public_audience_v2_atomic_publish --", s)
        self.assertIn('CONFIG = Path("/etc/aoe2war/traffic-v2/runner.json")',
                      SOURCE.read_text())

    def test_fail_closed_runner_is_real_not_a_stub(self):
        s = SOURCE.read_text()
        self.assertIn("HOLD_ROOT_OWNED_RUNNER_NOT_INSTALLED", s)
        self.assertIn("INDEPENDENT_OPERATOR_PERMIT_VERIFIED", (
            ROOT / "scripts/public_audience_v2_operator_permit.py").read_text())
        self.assertIn("current_external_state", s)
        self.assertIn("verify_and_append(", s)

    def test_production_process_cannot_gain_root_privileges(self):
        s = SERVICE.read_text()
        for item in ("NoNewPrivileges=yes", "CapabilityBoundingSet=",
                     "AmbientCapabilities=", "ProtectSystem=strict",
                     "ProtectHome=yes", "UMask=0077", "RestrictNamespaces=yes",
                     "InaccessiblePaths=-/run/postgresql -/var/run/postgresql"):
            self.assertIn(item, s)
        self.assertNotIn("ExecStartPre=/bin/bash", s)
        self.assertNotIn("sudo ", s)
        self.assertNotIn("systemctl enable", s)
        self.assertNotIn("PrivateNetwork=yes", s)  # GitHub revocation GET

    def test_writable_paths_are_only_source_and_fenced_publisher_state(self):
        text = SERVICE.read_text()
        candidates = re.findall(r"(?m)^ReadWritePaths=(.+)$", text)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].split(),
            ["/mnt/HC_Volume_105319120/traffic-db",
             "-/mnt/HC_Volume_105319120/traffic-v2-publisher"])
        self.assertNotIn("/var/www/Traffic/traffic-api ", candidates[0])
        self.assertIn("ReadOnlyPaths=-/etc/aoe2war/traffic-v2", text)

    def test_timer_is_hourly_utc_with_minimum_finality_grace(self):
        t = TIMER.read_text()
        self.assertIn("OnCalendar=*-*-* *:37:00 UTC", t)
        self.assertIn("Persistent=true", t)
        self.assertIn("Unit=traffic-v2-publisher.service", t)
        self.assertNotIn("traffic-public-audience-aoe2hdbets.service", t)
        self.assertNotIn("OnBootSec=", t)

    def test_publisher_unit_cannot_enable_itself_or_legacy_timer(self):
        s = SERVICE.read_text()
        self.assertNotIn("[Install]", s)
        self.assertNotIn("WantedBy=multi-user.target", s)
        self.assertIn("[Install]", TIMER.read_text())
        self.assertNotIn("traffic-public-audience-aoe2hdbets.timer", TIMER.read_text())


if __name__ == "__main__":
    unittest.main()
