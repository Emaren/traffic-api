"""No live root/SQLite/systemd mutation: exact Traffic PR74 permit and inverse tests."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import traffic_pr74_onefile_executor as t

NOW=1800000000

def permit(phase="install", **changes):
    p={"schema":"aoe2war.traffic.pr74.one-use-maintenance.v1",
       "purpose":t.PURPOSE,"action":phase,"target":str(t.DROPIN_PATH),
       "source_sha":t.SOURCE_SHA,"executor_sha256":"a"*64,
       "dropin_sha256":t.DROPIN_SHA,
       "original_unit_sha256":t.ORIGINAL_CAT_SHA,
       "postimage_sha256":t.EXPECTED_CAT_SHA,
       "witness_sha256":"b"*64,"nonce":"c"*64,
       "issued_at_unix":NOW-30,"expires_at_unix":NOW+600,
       "financial_authorized":False}
    p.update(changes)
    return p

class OneFileExecutor(unittest.TestCase):
    def test_only_original_reviewed_setting(self):
        self.assertEqual(t.DROPIN_BYTES,
                         b"[Service]\nEnvironment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1\n")
        self.assertEqual(t.sha(t.DROPIN_BYTES),t.DROPIN_SHA)
        self.assertNotIn(b"ExecStart",t.DROPIN_BYTES)
        self.assertNotIn(b"Restart",t.DROPIN_BYTES)

    def test_exact_permit_install_and_inverse(self):
        t.required_permit(permit(),"install",NOW,"a"*64)
        t.required_permit(permit("inverse"),"inverse",NOW,"a"*64)

    def test_denies_unreviewed_scope_and_financial_actions(self):
        for p in (permit("inverse"),permit(extra="unreviewed"),
                  permit(purpose="PRODUCT_WEBSITE_RELEASE"),
                  permit(target="/etc/systemd/system/other.service"),
                  permit(financial_authorized=True),
                  permit(source_sha="0"*40),
                  permit(executor_sha256="1"*64),
                  permit(postimage_sha256="0"*64),
                  permit(dropin_sha256="0"*64)):
            with self.subTest(p=p),self.assertRaises(t.Hold):
                t.required_permit(p,"install",NOW,"a"*64)

    def test_rejects_expired_oversized_and_future_permits(self):
        for p in (permit(nonce="short"),
                  permit(issued_at_unix=NOW-901),
                  permit(expires_at_unix=NOW-1),
                  permit(issued_at_unix=NOW+61),
                  permit(issued_at_unix=NOW-5,expires_at_unix=NOW+896),
                  permit(expires_at_unix="tomorrow")):
            with self.subTest(p=p),self.assertRaises(t.Hold):
                t.required_permit(p,"install",NOW,"a"*64)

    def test_we4_fresh_sqlite_and_nginx_witness_only(self):
        actual={"db_dev":2064,"db_inode":131074,"max_rowid":51356048,
                "old_1000_stamped":0,"nginx_dev":2064,"nginx_inode":390667,
                "nginx_cursor_inode":390667,"nginx_cursor_offset":65238274}
        witness={**actual,
                 "schema":"aoe2war.traffic.pr74.preinstall-witness.v1",
                 "observed_at_unix":NOW-20}
        t.compare_witness(witness,actual,NOW)
        for bad in ({**witness,"max_rowid":12},
                    {**witness,"observed_at_unix":NOW-91},
                    {**witness,"nginx_cursor_offset":1},
                    {**witness,"private_ips":[]},
                    {**witness,"observed_at_unix":NOW+1}):
            with self.subTest(bad=bad),self.assertRaises(t.Hold):
                t.compare_witness(bad,actual,NOW)

    def test_source_only_does_not_grant_root(self):
        with patch.object(t.os,"geteuid",return_value=1000):
            self.assertEqual(t.main(["--phase","install"]),2)
        with patch.object(t.os,"geteuid",return_value=0),\
             patch.object(t,"trusted_dir",side_effect=t.Hold("NO_TRUST")):
            self.assertEqual(t.main(["--phase","install"]),2)

    def test_nonce_used_only_once_across_both_actions(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(t,"STATE",Path(folder)):
            nonce="d"*64
            t.consume_nonce("install",nonce)
            with self.assertRaises(FileExistsError):
                t.consume_nonce("inverse",nonce)
            self.assertTrue((Path(folder)/(nonce+".consumed")).exists())

    def test_exact_atomic_install_and_inverse_disposable_only(self):
        with tempfile.TemporaryDirectory() as folder,\
             patch.object(t,"DROPIN_PATH",Path(folder)/"one.conf"),\
             patch.object(t,"systemctl",return_value=b""):
            t.exact_install()
            self.assertEqual(t.DROPIN_PATH.read_bytes(),t.DROPIN_BYTES)
            self.assertEqual(t.DROPIN_PATH.stat().st_mode&0o777,0o644)
            with self.assertRaises(FileExistsError):
                t.exact_install()
            t.exact_inverse()
            self.assertFalse(t.DROPIN_PATH.exists())

    def test_inverse_refuses_drift_without_removal(self):
        with tempfile.TemporaryDirectory() as folder,\
             patch.object(t,"DROPIN_PATH",Path(folder)/"one.conf"):
            t.DROPIN_PATH.write_bytes(t.DROPIN_BYTES+b"tamper")
            with self.assertRaises(t.Hold):
                t.exact_inverse()
            self.assertTrue(t.DROPIN_PATH.exists())

if __name__=="__main__":
    unittest.main()
