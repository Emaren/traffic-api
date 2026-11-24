"""Keep private forward capture alive after a truly certified V2 daily append.

Fixture-only SQLite: no public writes, real signer, or root traffic source.
"""
from __future__ import annotations

from datetime import date, timedelta
import sqlite3
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_release_manifest as manifest

START=date(2026,6,11)
END=date(2026,10,20)
HIST={str(START+timedelta(days=i)): [3,2,1]
      for i in range((END-START).days)}
CERT_SCHEMA="""CREATE TABLE traffic_public_audience_day_certificates_v2(
 project_slug TEXT NOT NULL,bucket_day TEXT NOT NULL,
 certificate_sha256 TEXT NOT NULL,source_page_sha256 TEXT NOT NULL,
 signed_finality_schema TEXT NOT NULL,certified_at_utc TEXT NOT NULL,
 PRIMARY KEY(project_slug,bucket_day))"""


class ForwardCertifiedAppendObserverTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript(
            """CREATE TABLE traffic_public_daily_audience_rollups(
              project_slug TEXT,bucket_day TEXT,
              total_traffic INT,suspected_human INT,confirmed_human INT,
              PRIMARY KEY(project_slug,bucket_day))""")
        self.db.executemany(
            "INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?)",
            [("aoe2hdbets",d,*metrics) for d,metrics in HIST.items()])
        self.db.commit()
        self.original_sha=manifest.sha
        self.patcher=patch.object(
            manifest,"sha",side_effect=lambda matrix: forward.RELEASE_SHA
            if matrix == HIST else "0"*64)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def assert_complete(self):
        forward.assert_published_history(self.db)

    def next(self, day="2026-11-23"):
        self.db.execute(
            "INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?)",
            ("aoe2hdbets",day,4,2,1))
        self.db.commit()

    def ledger(self):
        self.db.executescript(CERT_SCHEMA)

    def receipt(self, day="2026-11-23", *, digest="a"*64,
                schema="traffic.public-audience.v2.dual-witness-day.v1",
                clock="2026-11-24T01:00:00+00:00"):
        self.db.execute(
            "INSERT INTO traffic_public_audience_day_certificates_v2 VALUES(?,?,?,?,?,?)",
            ("aoe2hdbets",day,digest,"b"*64,schema,clock))
        self.db.commit()

    def test_original_historical_131_can_run_without_new_ledger(self):
        self.assert_complete()

    def test_valid_new_day_requires_exact_certificate_ledger(self):
        self.next()
        with self.assertRaisesRegex(RuntimeError,"certificate ledger"):
            self.assert_complete()
        self.ledger()
        with self.assertRaisesRegex(RuntimeError,"certificate gap"):
            self.assert_complete()
        self.receipt()
        self.assert_complete()

    def test_unknown_gap_stays_unknown_with_valid_certified_later_day(self):
        self.next("2026-11-23")
        self.ledger()
        self.receipt("2026-11-23")
        self.assert_complete()
        rows=self.db.execute(
            "SELECT bucket_day FROM traffic_public_daily_audience_rollups WHERE bucket_day>'2026-10-19'"
        ).fetchall()
        self.assertEqual(rows,[("2026-11-23",)])

    def test_rejects_forged_digests_schema_and_utc_clocks(self):
        for typ in ("digest","schema","nonutc"):
            with self.subTest(typ=typ):
                self.db.execute("DELETE FROM traffic_public_daily_audience_rollups WHERE bucket_day>'2026-10-19'")
                self.db.execute("DROP TABLE IF EXISTS traffic_public_audience_day_certificates_v2")
                self.next()
                self.ledger()
                self.receipt(digest="q"*64 if typ=="digest" else "a"*64,
                             schema="unapproved" if typ=="schema" else
                             "traffic.public-audience.v2.dual-witness-day.v1",
                             clock="2026-11-24T01:00:00+02:00" if typ=="nonutc"
                             else "2026-11-24T01:00:00+00:00")
                with self.assertRaisesRegex(RuntimeError,
                                            "digest|schema|not UTC"):
                    self.assert_complete()

    def test_rejects_orphan_certificate(self):
        self.next()
        self.ledger()
        self.receipt(day="2026-11-22")
        with self.assertRaisesRegex(RuntimeError,"orphan"):
            self.assert_complete()

    def test_tampered_frozen_history_still_holds_after_append(self):
        self.next()
        self.ledger()
        self.receipt()
        self.db.execute(
            """UPDATE traffic_public_daily_audience_rollups
               SET total_traffic=9 WHERE bucket_day='2026-07-12'""")
        with self.assertRaisesRegex(RuntimeError,"original 131-day"):
            self.assert_complete()

    def test_nonhierarchical_future_values_hold_even_if_cert_present(self):
        self.next()
        self.ledger()
        self.receipt()
        self.db.execute(
            "UPDATE traffic_public_daily_audience_rollups SET confirmed_human=99 WHERE bucket_day='2026-11-23'")
        with self.assertRaisesRegex(RuntimeError,"audience hierarchy"):
            self.assert_complete()


if __name__=="__main__":
    unittest.main()
