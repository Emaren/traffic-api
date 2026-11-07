"""C03 source-only financial network/capability firewall for Traffic forward ledger.

The worker currently needs root for 0600 root-owned SQLite canary evidence.
This proves a *configured deny* baseline, not live C03 quiescence and not an
isolated kernel result. The corresponding physical admission uses a transient
HEL1 systemd sandbox; no production unit is changed by these tests.
"""
from __future__ import annotations

import configparser
from pathlib import Path
import unittest

UNIT = Path(__file__).resolve().parents[1] / "ops/systemd/traffic-v2-forward-ledger-aoe2hdbets.service"
PRIVATE = "/mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA"
SOURCE = "/mnt/HC_Volume_105319120/traffic-db"
HISTORY = SOURCE + "/traffic_history.sqlite3"


def qualified_config(raw: str) -> dict:
    """Raise on broadened or missing sandbox controls. Never run this unit."""
    import io
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_file(io.StringIO(raw))
    assert set(parser.sections()) == {"Unit", "Service"}
    service = parser["Service"]
    expected = {
        "Type": "oneshot",
        "User": "root",  # Explicit temporary root-owned 0600 ledger limitation.
        "Group": "root",
        "NoNewPrivileges": "yes",
        "PrivateNetwork": "yes",
        "RestrictAddressFamilies": "AF_UNIX",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "RestrictNamespaces": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectControlGroups": "yes",
        "LockPersonality": "yes",
        "RestrictSUIDSGID": "yes",
        "InaccessiblePaths": "-/run/postgresql -/var/run/postgresql",
        "PrivateTmp": "yes",
        "ProtectHome": "yes",
        "ProtectSystem": "strict",
        "UMask": "0077",
        "ReadWritePaths": PRIVATE + " " + SOURCE,
        "ReadOnlyPaths": HISTORY + " -" + HISTORY + "-wal",
        "MemoryMax": "512M",
        "TimeoutStartSec": "50s",
    }
    for key, value in expected.items():
        if key not in service or service[key] != value:
            raise AssertionError(f"C03_CONFIG_DRIFT:{key}")
    # A second ExecStart/ExecStartPre, override or environment injection must
    # never be mistaken for a copy of the reviewed read-only-input script.
    cmd = service.get("ExecStart", "")
    expected_exec = (
        "/var/www/Traffic/traffic-api/.venv/bin/python3 "
        "-m scripts.public_audience_v2_forward_ledger "
        f"--source {HISTORY} --checkpoint {PRIVATE}/checkpoint.sqlite3 "
        f"--ledger {PRIVATE}/future-ledger.sqlite3 "
        "--max-rows 3000 --budget-seconds 12 --advance --approve-private-write"
    )
    if cmd != expected_exec:
        raise AssertionError("C03_COMMAND_OR_DESTINATION_CHANGED")
    if any(key in service for key in (
        "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStopPost",
        "BindPaths", "BindReadOnlyPaths", "SupplementaryGroups",
        "RootDirectory", "RootImage", "EnvironmentFile",
    )):
        raise AssertionError("C03_EXTRA_EXEC_OR_NAMESPACE_BYPASS")
    return {"command_confined": True, "no_ip_network": True,
            "no_capabilities": True, "temporary_root_uid": True,
            "finance_authorized": False}


class C03ForwardLedgerUnitSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = UNIT.read_text()

    def test_exact_reviewed_baseline(self):
        result = qualified_config(self.raw)
        self.assertTrue(result["command_confined"])
        self.assertFalse(result["finance_authorized"])

    def test_current_user_is_explicitly_root_not_a_nohuman_claim(self):
        self.assertTrue(qualified_config(self.raw)["temporary_root_uid"])

    def test_no_extra_command_or_timer_privilege(self):
        self.assertEqual(self.raw.count("ExecStart="), 1)
        self.assertNotIn("ExecStartPre=", self.raw)

    def test_no_network_capability_bypasses(self):
        self.assertTrue(qualified_config(self.raw)["no_ip_network"])
        self.assertTrue(qualified_config(self.raw)["no_capabilities"])

    def test_adversarial_broadened_profiles_reject(self):
        mutations = [
            ("PrivateNetwork=yes", "PrivateNetwork=no"),
            ("PrivateNetwork=yes", ""),
            ("RestrictAddressFamilies=AF_UNIX", "RestrictAddressFamilies=AF_UNIX AF_INET"),
            ("RestrictAddressFamilies=AF_UNIX", ""),
            ("CapabilityBoundingSet=\n", "CapabilityBoundingSet=CAP_NET_ADMIN\n"),
            ("CapabilityBoundingSet=\n", ""),
            ("AmbientCapabilities=\n", "AmbientCapabilities=CAP_NET_ADMIN\n"),
            ("NoNewPrivileges=yes", "NoNewPrivileges=no"),
            ("ProtectSystem=strict", "ProtectSystem=full"),
            ("ProtectHome=yes", "ProtectHome=no"),
            ("RestrictNamespaces=yes", "RestrictNamespaces=no"),
            ("ProtectKernelTunables=yes", "ProtectKernelTunables=no"),
            ("ProtectKernelModules=yes", "ProtectKernelModules=no"),
            ("ProtectControlGroups=yes", "ProtectControlGroups=no"),
            ("LockPersonality=yes", "LockPersonality=no"),
            ("RestrictSUIDSGID=yes", "RestrictSUIDSGID=no"),
            ("InaccessiblePaths=-/run/postgresql -/var/run/postgresql", ""),
            ("ReadWritePaths=" + PRIVATE + " " + SOURCE,
             "ReadWritePaths=" + PRIVATE + " " + SOURCE + " /var/run/postgresql"),
            ("ReadOnlyPaths=" + HISTORY, "ReadOnlyPaths=/var/run/postgresql " + HISTORY),
            ("--max-rows 3000", "--max-rows 300000"),
            ("--advance --approve-private-write", "--apply --approve-private-write"),
            ("User=root", "User=tony"),
            ("Group=root", "Group=tony"),
            ("MemoryMax=512M", "MemoryMax=infinity"),
        ]
        for before, after in mutations:
            with self.subTest(before=before, after=after):
                self.assertIn(before, self.raw)
                with self.assertRaises((AssertionError, configparser.Error)):
                    qualified_config(self.raw.replace(before, after, 1))

    def test_unknown_extra_command_rejected(self):
        with self.assertRaises(AssertionError):
            qualified_config(self.raw + "\nExecStartPre=/usr/bin/true\n")

    def test_unknown_environment_file_rejected(self):
        with self.assertRaises(AssertionError):
            qualified_config(self.raw + "\nEnvironmentFile=/etc/finance.env\n")

    def test_duplicate_sandbox_key_rejected(self):
        with self.assertRaises(configparser.Error):
            qualified_config(self.raw + "\nPrivateNetwork=no\n")

    def test_unexpected_extra_write_path_rejected(self):
        with self.assertRaises(AssertionError):
            qualified_config(self.raw.replace(
                f"ReadWritePaths={PRIVATE} {SOURCE}",
                f"ReadWritePaths={PRIVATE} {SOURCE} /var/lib/postgresql"
            ))

if __name__ == "__main__":
    unittest.main()
