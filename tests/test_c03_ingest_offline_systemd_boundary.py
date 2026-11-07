"""C03 Traffic ingestion source-only systemd sandbox denial proof."""
from __future__ import annotations
import configparser
import io
from pathlib import Path
import unittest

UNIT=Path(__file__).resolve().parents[1]/"ops/systemd/traffic-ingest.service"
DB_DIR="/mnt/HC_Volume_105319120/traffic-db"
LOCK="/run/traffic-ingest/sync.lock"
EXEC=("ExecStart=/usr/bin/flock -n -E 75 "+LOCK+" "
      "/var/www/Traffic/traffic-api/.venv/bin/python3 scripts/sync_traffic_logs.py")
FIELDS={
    "Type":"oneshot","User":"tony","Group":"tony",
    "PrivateNetwork":"yes","RestrictAddressFamilies":"AF_UNIX",
    "CapabilityBoundingSet":"","AmbientCapabilities":"",
    "NoNewPrivileges":"yes","RestrictNamespaces":"yes",
    "ProtectKernelTunables":"yes","ProtectKernelModules":"yes",
    "ProtectControlGroups":"yes","LockPersonality":"yes",
    "RestrictSUIDSGID":"yes","PrivateTmp":"yes","ProtectHome":"yes",
    "ProtectSystem":"strict",
    "InaccessiblePaths":"-/run/postgresql -/var/run/postgresql",
    "ReadWritePaths":DB_DIR+" /run/traffic-ingest",
    "RuntimeDirectory":"traffic-ingest",
    "RuntimeDirectoryPreserve":"yes","RuntimeDirectoryMode":"0755",
    "UMask":"0027","WorkingDirectory":"/var/www/Traffic/traffic-api",
    "EnvironmentFile":"/etc/traffic-api.env","TimeoutStartSec":"600",
}
UNSAFE=("ExecStartPre","ExecStartPost","ExecStopPost","ExecReload",
        "BindPaths","BindReadOnlyPaths","SupplementaryGroups",
        "RootDirectory","RootImage")

def evaluate(raw):
    cfg=configparser.ConfigParser(interpolation=None,strict=True)
    cfg.read_file(io.StringIO(raw))
    assert set(cfg.sections())=={"Unit","Service"},"UNKNOWN_SECTION"
    s=cfg["Service"]
    for key,value in FIELDS.items():
        assert s.get(key,None)==value,"DRIFT_"+key
    assert raw.count("ExecStart=")==1 and EXEC in raw.splitlines(),"COMMAND_DRIFT"
    assert not any(key in s for key in UNSAFE),"EXEC_OR_MOUNT_BYPASS"
    return {"sqlite_write_preserved":True,"financial_release_authorized":False}

class IngestSandbox(unittest.TestCase):
    def test_expected_policy(self):
        self.assertFalse(evaluate(UNIT.read_text())["financial_release_authorized"])

    def test_adversarial_drift(self):
        raw=UNIT.read_text()
        for before,after in [
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
            ("ReadWritePaths="+DB_DIR+" /run/traffic-ingest",
             "ReadWritePaths="+DB_DIR+" /run/traffic-ingest /var/lib/postgresql"),
            ("User=tony","User=root"),
            ("UMask=0027","UMask=0000"),
            ("-E 75 "+LOCK,"-E 0 "+LOCK),
        ]:
            with self.subTest(before=before):
                self.assertIn(before,raw)
                with self.assertRaises((AssertionError,configparser.Error)):
                    evaluate(raw.replace(before,after,1))

    def test_extra_exec_or_namespace_bypass(self):
        raw=UNIT.read_text()
        for suffix in ("ExecStartPre=/usr/bin/true","RootDirectory=/",
                       "BindPaths=/var/run/postgresql","SupplementaryGroups=postgres"):
            with self.subTest(suffix=suffix):
                with self.assertRaises((AssertionError,configparser.Error)):
                    evaluate(raw+"\n"+suffix+"\n")

    def test_duplicate_options(self):
        with self.assertRaises(configparser.Error):
            evaluate(UNIT.read_text()+"\nPrivateNetwork=no\n")

if __name__=="__main__":
    unittest.main()
