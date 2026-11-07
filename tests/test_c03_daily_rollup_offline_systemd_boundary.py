"""C03 fail-closed tests for the Traffic-only daily-rollup systemd sandbox.

Source/unit admission only. No real financial database or service is touched.
"""
from __future__ import annotations

import configparser
import io
from pathlib import Path
import unittest

UNIT = Path(__file__).resolve().parents[1] / "ops/systemd/traffic-project-daily-rollups-aoe2hdbets.service"
DB_DIR = "/mnt/HC_Volume_105319120/traffic-db"
LOCK = "/run/traffic-rollups/aoe2hdbets.lock"
EXPECTED = {
    "Type": "oneshot",
    "User": "tony",
    "Group": "tony",
    "PrivateNetwork": "yes",
    "RestrictAddressFamilies": "AF_UNIX",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "NoNewPrivileges": "yes",
    "RestrictNamespaces": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes",
    "LockPersonality": "yes",
    "RestrictSUIDSGID": "yes",
    "PrivateTmp": "yes",
    "ProtectHome": "yes",
    "ProtectSystem": "strict",
    "InaccessiblePaths": "-/run/postgresql -/var/run/postgresql",
    "ReadWritePaths": DB_DIR + " /run/traffic-rollups",
    "RuntimeDirectory": "traffic-rollups",
    "RuntimeDirectoryPreserve": "yes",
    "RuntimeDirectoryMode": "0755",
    "UMask": "0027",
    "EnvironmentFile": "/etc/traffic-api.env",
    "WorkingDirectory": "/var/www/Traffic/traffic-api",
    "TimeoutStartSec": "3600",
}
EXEC = (
    "ExecStart=/usr/bin/flock -n -E 0 " + LOCK + " "
    "/var/www/Traffic/traffic-api/.venv/bin/python3 "
    "scripts/rebuild_project_daily_rollups.py --incremental --project aoe2hdbets"
)
UNSAFE = (
    "ExecStartPre", "ExecStartPost", "ExecStopPost", "ExecReload",
    "BindPaths", "BindReadOnlyPaths", "SupplementaryGroups",
    "RootDirectory", "RootImage",
)

def evaluate(raw: str) -> dict:
    cfg=configparser.ConfigParser(interpolation=None,strict=True)
    cfg.read_file(io.StringIO(raw))
    assert set(cfg.sections())=={"Unit","Service"}, "UNKNOWN_SECTION"
    svc=cfg["Service"]
    for key,val in EXPECTED.items():
        assert svc.get(key,None)==val, f"C03_DRIFT_{key}"
    assert raw.count("ExecStart=")==1 and EXEC in raw.splitlines(), "COMMAND_DRIFT"
    assert not any(k in svc for k in UNSAFE), "EXTRA_SERVICE_EXEC"
    assert not any(k.startswith("ExecStartPre") for k in svc), "START_BYPASS"
    return {"network_denied":True, "capabilities_empty":True,
            "finance_release_authorized":False}

class TrafficDailyRollupSandboxTests(unittest.TestCase):
    def test_reviewed_source(self):
        self.assertFalse(evaluate(UNIT.read_text())["finance_release_authorized"])

    def test_negative_mutations(self):
        raw=UNIT.read_text()
        mutations=[
            ("PrivateNetwork=yes","PrivateNetwork=no"),
            ("RestrictAddressFamilies=AF_UNIX","RestrictAddressFamilies=AF_UNIX AF_INET"),
            ("CapabilityBoundingSet=\n","CapabilityBoundingSet=CAP_NET_ADMIN\n"),
            ("AmbientCapabilities=\n","AmbientCapabilities=CAP_NET_RAW\n"),
            ("NoNewPrivileges=yes","NoNewPrivileges=no"),
            ("RestrictNamespaces=yes","RestrictNamespaces=no"),
            ("ProtectSystem=strict","ProtectSystem=full"),
            ("ProtectHome=yes","ProtectHome=no"),
            ("InaccessiblePaths=-/run/postgresql -/var/run/postgresql",
             "InaccessiblePaths=-/run/postgresql"),
            ("ReadWritePaths="+DB_DIR+" /run/traffic-rollups",
             "ReadWritePaths="+DB_DIR+" /run/traffic-rollups /var/lib/postgresql"),
            ("User=tony","User=root"),
            ("RuntimeDirectoryPreserve=yes","RuntimeDirectoryPreserve=no"),
            ("UMask=0027","UMask=0000"),
            ("-E 0 "+LOCK,"-E 1 "+LOCK),
            ("--project aoe2hdbets","--project all"),
        ]
        for src,dst in mutations:
            with self.subTest(src=src):
                self.assertIn(src,raw)
                with self.assertRaises((AssertionError,configparser.Error)):
                    evaluate(raw.replace(src,dst,1))

    def test_additional_exec_and_network_namespace_bypass(self):
        raw=UNIT.read_text()
        for extra in ("ExecStartPre=/usr/bin/true", "BindPaths=/var/run/postgresql",
                      "RootDirectory=/", "SupplementaryGroups=postgres"):
            with self.subTest(extra=extra):
                with self.assertRaises((AssertionError,configparser.Error)):
                    evaluate(raw+"\n"+extra+"\n")

    def test_duplicate_effective_keys_rejected(self):
        raw=UNIT.read_text()
        with self.assertRaises(configparser.Error):
            evaluate(raw+"\nPrivateNetwork=no\n")

if __name__=="__main__":
    unittest.main()
