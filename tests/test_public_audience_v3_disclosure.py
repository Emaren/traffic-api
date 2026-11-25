"""V3 API disclosure and protected renderer gate, isolated SQLite only."""
from datetime import date, timedelta
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from app import main
from app.services.traffic import config
from scripts import public_audience_v2_day_admission as witness
from scripts import public_audience_v2_daily_append as append
from scripts import public_audience_v2_runner as runner
from tests import test_public_audience_v2_runner as existing


class VersionDisclosureTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.dbpath=Path(self.folder.name)/"fixture.sqlite"
        self.db=sqlite3.connect(self.dbpath)
        self.addCleanup(self.db.close)
        self.db.executescript("""
          CREATE TABLE traffic_public_daily_audience_rollups(
            project_slug TEXT,bucket_day TEXT,total_traffic INTEGER,
            suspected_human INTEGER,confirmed_human INTEGER,updated_at TEXT,
            PRIMARY KEY(project_slug,bucket_day));
        """+append.DAY_CERT_TABLE_SCHEMA)
        rows=[("aoe2hdbets",(date(2026,6,11)+timedelta(days=i)).isoformat(),100+i,20,4,"2026-10-20T00:00:00+00:00") for i in range(131)]
        self.db.executemany("INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?,?)",rows)
        self.db.commit()

    def call(self):
        with patch.object(config,"PERSIST_DB_PATH",self.dbpath):
            return main.api_project_public_audience_series("aoe2hdbets")

    def add_v3(self,day):
        self.db.execute("INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?,?)",
                        ("aoe2hdbets",day,250,45,10,"2026-11-25T01:00:00+00:00"))
        self.db.execute("INSERT INTO traffic_public_audience_day_certificates_v2 VALUES(?,?,?,?,?,?)",
                        ("aoe2hdbets",day,"a"*64,"b"*64,witness.V3_SCHEMA,"2026-11-25T01:00:00+00:00"))
        self.db.commit()

    def test_actual_transition_only_with_versioned_ledger_rows(self):
        before=self.call()
        self.assertEqual(len(before["points"]),131)
        self.assertNotIn("metric_transition",before)
        self.add_v3("2026-11-24")
        after=self.call()
        self.assertEqual(after["points"][:131],before["points"])
        self.assertEqual(after["metric_transition"]["first_date"],"2026-11-24")
        self.assertEqual(after["points"][-1]["metricVersion"],"v3-utc-day-slice")
        self.assertNotIn("2026-11-23",[p["date"] for p in after["points"]])

    def test_orphan_and_unversioned_later_rows_fail_closed(self):
        self.add_v3("2026-11-23")
        self.db.execute("INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?,?)",
                        ("aoe2hdbets","2026-11-24",250,45,10,"2026-11-25T01:00:00+00:00"))
        self.db.commit()
        with self.assertRaises(HTTPException) as error:
            self.call()
        self.assertEqual(error.exception.status_code,503)
        self.db.execute("DELETE FROM traffic_public_daily_audience_rollups WHERE bucket_day>='2026-11-23'")
        self.db.commit()
        with self.assertRaises(HTTPException):
            self.call()


class VersionedRendererGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        existing.BoundedRunnerTests.setUpClass()
    @classmethod
    def tearDownClass(cls):
        existing.BoundedRunnerTests.tearDownClass()

    def setUp(self):
        self.f=existing.BoundedRunnerTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_v3_requires_new_physical_disclosure_receipt(self):
        f=self.f
        cfg=dict(f.cfg,schema=runner.V3_RUNNER_SCHEMA)
        f._write(f.config,cfg)
        cfg=runner.config_read(f.config,uid=f.uid)
        with self.assertRaisesRegex(ValueError,"GAP_RENDERER_ACTIVATION"):
            runner.public_source_state(cfg,trust_uid=f.uid)
        receipt={"schema":"aoe2war.traffic-v3.gap-renderer-readback.v1",
                 "status":"WE2_ACTIVATED_GAP_RENDERER_READBACK",
                 "renderer_sha256":f.websha,"approved_source_commit":existing.SOURCE,
                 "metric_version_disclosure":False}
        f._write(f.render,receipt)
        with self.assertRaisesRegex(ValueError,"GAP_RENDERER_ACTIVATION"):
            runner.public_source_state(cfg,trust_uid=f.uid)
        receipt["metric_version_disclosure"]=True
        f._write(f.render,receipt)
        self.assertEqual(runner.public_source_state(cfg,trust_uid=f.uid),
                         (cfg["source_dev"],cfg["source_inode"]))

    def test_v3_does_not_consider_pre_migration_days(self):
        f=self.f
        f.set_day("2026-11-17")
        cfg=dict(f.cfg,schema=runner.V3_RUNNER_SCHEMA)
        self.assertEqual(runner._candidate_dirs(cfg,existing.NOW,uid=f.uid),[])


if __name__=="__main__":
    unittest.main()
