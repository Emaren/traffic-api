"""WE4 source-only real SQLite transactional append, simulated signed days."""
from __future__ import annotations
from datetime import date, datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_daily_append as daily
from scripts import public_audience_v2_day_admission as admission
from scripts import public_audience_v2_release_manifest as manifest
from tests.test_public_audience_v2_day_admission import TwoWitnessDayTests

DDL = """
CREATE TABLE traffic_public_daily_audience_rollups(
 project_slug TEXT NOT NULL,bucket_day TEXT NOT NULL,
 total_traffic INTEGER NOT NULL,suspected_human INTEGER NOT NULL,
 confirmed_human INTEGER NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(project_slug,bucket_day)
);
"""
NOW = datetime(2026, 11, 18, 15, tzinfo=timezone.utc)


class AtomicDailyAppendFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TwoWitnessDayTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        TwoWitnessDayTests.tearDownClass()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="traffic-daily-append-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(os.path.realpath(self.temp.name))
        self.database_file = self.folder / "fictional-traffic.sqlite"
        self.conn = sqlite3.connect(self.database_file)
        self.addCleanup(self.conn.close)
        self.conn.executescript(DDL + daily.DAY_CERT_TABLE_SCHEMA)
        self.history = {}
        for i, day in enumerate(
            manifest.days_between(date(2026, 6, 11), date(2026, 10, 20))
        ):
            vals = [3000 + i, 1000 + i, 500 + i]
            self.history[day] = vals
            self.conn.execute(
                "INSERT INTO traffic_public_daily_audience_rollups "
                "VALUES(?,?,?,?,?,?)",
                ("aoe2hdbets", day, *vals, NOW.isoformat()),
            )
        self.conn.commit()
        self.history_sha = manifest.sha(self.history)
        self.fixture = TwoWitnessDayTests()
        self.fake_keys = self.fixture.keys

    def candidate(self, day="2026-11-17"):
        p = self.fixture.page(day)
        c = self.fixture.certificate(p, day)
        c["historical_release_sha256"] = self.history_sha
        env = self.fixture.envelope(c)
        return env, p

    def permit(self, cert, **changes):
        return {
            "status": "INDEPENDENT_OPERATOR_PERMIT_VERIFIED",
            "project": "aoe2hdbets", "day": cert["day"],
            "certificate_sha256": admission.digest(admission.canonical(cert)),
            "source_commit_sha": "a" * 40,
            "permit_signature_verified": True,
            "gap_aware_api_and_chart": True,
            **changes,
        }

    def durable(self, rows):
        payload = admission.canonical(rows)
        file = self.folder / "original-preimage.json"
        with file.open("xb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        file.chmod(0o600)
        return hashlib.sha256(file.read_bytes()).hexdigest()

    def call(self, env=None, page=None, *, permit=None, expected=None,
             durable=None, lock=True, day="2026-11-17"):
        if env is None or page is None:
            env, page = self.candidate(day)
        if expected is None:
            rows = daily.public_rows(self.conn)
            expected = manifest.sha({
                r["day"]: [r["total"], r["potential"], r["confirmed"]]
                for r in rows
            })
        if permit is None:
            permit = self.permit(env["certificate"],
                                 permitted_public_preimage_sha256=expected)
        with patch.object(daily, "RELEASE_SHA", self.history_sha), \
             patch.object(admission, "RELEASE_SHA", self.history_sha):
            return daily.append_verified_day(
                self.conn, certificate_envelope=env,
                page_state=page, now=NOW,
                upstream_key=self.fake_keys[0][1],
                classifier_key=self.fake_keys[1][1],
                upstream_key_sha256=hashlib.sha256(
                    self.fake_keys[0][1]).hexdigest(),
                classifier_key_sha256=hashlib.sha256(
                    self.fake_keys[1][1]).hexdigest(),
                independently_admitted_operator_permit=permit,
                durable_preimage=durable or self.durable,
                expected_public_sha256=expected, lock_proven=lock,
            )

    def rows(self):
        return self.conn.execute(
            "SELECT bucket_day,total_traffic,suspected_human,confirmed_human "
            "FROM traffic_public_daily_audience_rollups "
            "ORDER BY bucket_day"
        ).fetchall()

    def test_one_day_commits_with_atomic_signed_provenance_and_preserves_131(self):
        old = self.rows()
        result = self.call()
        self.assertEqual(result["status"], "COMMITTED_ONE_SIGNED_COMPLETED_DAY")
        self.assertEqual(result["day"], "2026-11-17")
        self.assertEqual(result["public_write_count"], 1)
        self.assertEqual(len(self.rows()), 132)
        self.assertEqual(self.rows()[:131], old)
        self.assertEqual(self.rows()[-1][1:], (150, 40, 19))
        proof = self.conn.execute(
            "SELECT certificate_sha256,source_page_sha256 "
            "FROM traffic_public_audience_day_certificates_v2"
        ).fetchone()
        self.assertEqual(proof[0], result["source_certificate_sha256"])
        self.assertEqual((self.folder / "original-preimage.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse(result["missing_days_are_unknown"] is False)
        self.assertFalse("2026-10-20" in (x[0] for x in self.rows()))

    def test_repeated_signed_day_no_duplicate_and_no_backup(self):
        env,p = self.candidate()
        self.call(env,p)
        result=self.call(env,p,durable=lambda rows: self.fail("idempotent backup"))
        self.assertEqual(result["status"],"IDEMPOTENT_ALREADY_CERTIFIED")
        self.assertEqual(result["public_write_count"],0)
        self.assertEqual(len(self.rows()),132)

    def test_out_of_order_historical_backfill_refused(self):
        self.call()
        env,p=self.candidate("2026-11-16")
        with self.assertRaisesRegex(ValueError, "OUT_OF_ORDER_OR_RETROACTIVE_DAY"):
            self.call(env,p)
        self.assertEqual(len(self.rows()),132)

    def test_missing_operator_permit_or_shared_lock_refused(self):
        old=self.rows()
        env,p=self.candidate()
        with self.assertRaisesRegex(ValueError, "PROJECT_WORKER_LOCK_MISSING"):
            self.call(env,p,lock=False)
        with self.assertRaisesRegex(ValueError, "INDEPENDENT_OPERATOR"):
            self.call(env,p,permit=self.permit(env["certificate"],
                                                gap_aware_api_and_chart=False))
        with self.assertRaisesRegex(ValueError, "INDEPENDENT_OPERATOR"):
            self.call(env,p,permit=self.permit(env["certificate"],
                                                permit_signature_verified=False))
        self.assertEqual(self.rows(),old)

    def test_failed_audit_insert_rolls_back_public_day_and_retains_131(self):
        old=self.rows()
        self.conn.executescript("""
        CREATE TRIGGER deny_day_certificate BEFORE INSERT
        ON traffic_public_audience_day_certificates_v2
        BEGIN SELECT RAISE(ABORT,'FIXTURE_AUDIT_FAIL'); END;
        """)
        with self.assertRaisesRegex(sqlite3.IntegrityError,"FIXTURE_AUDIT_FAIL"):
            self.call()
        self.assertEqual(self.rows(),old)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM traffic_public_audience_day_certificates_v2"
        ).fetchone()[0],0)

    def test_preimage_drift_cas_hold_and_failed_backup_rolls_back(self):
        old=self.rows()
        with self.assertRaisesRegex(ValueError, "PUBLIC_DAY_PREIMAGE_MOVED"):
            self.call(expected="f"*64)
        with self.assertRaisesRegex(ValueError, "DURABLE_PREIMAGE_NOT_VERIFIED"):
            self.call(durable=lambda rows: "0"*64)
        self.assertEqual(self.rows(),old)

    def test_wrong_source_signature_and_missing_receipts_never_write(self):
        old=self.rows()
        env,p=self.candidate()
        env["certificate"]["total"]+=1
        with self.assertRaisesRegex(ValueError, "INDEPENDENT_SIGNATURE_REFUSED"):
            self.call(env,p)
        env,p=self.candidate()
        p["missing_receipts"]=3
        env["certificate"]["missing_insertion_receipts"]=3
        env["certificate"]["page_state_sha256"]=admission.digest(
            admission.canonical(p))
        env=self.fixture.envelope(env["certificate"])
        with self.assertRaisesRegex(ValueError, "INSERT_RECEIPTS_INCOMPLETE"):
            self.call(env,p)
        self.assertEqual(self.rows(),old)

    def test_unauthorized_ledger_absence_refuses_before_write(self):
        self.conn.execute("DROP TABLE traffic_public_audience_day_certificates_v2")
        with self.assertRaisesRegex(ValueError, "REVIEWED_DAY_CERTIFICATE_LEDGER_NOT_INSTALLED"):
            self.call()
        self.assertEqual(len(self.rows()),131)

    def test_conflicting_replay_refused_without_mutating_committed_day(self):
        env,p=self.candidate()
        self.call(env,p)
        new_env,new_p=self.candidate()
        new_env["certificate"]["total"]=151
        new_env=self.fixture.envelope(new_env["certificate"])
        with self.assertRaisesRegex(ValueError,"CONFLICTING_REPLAY"):
            self.call(new_env,new_p)
        self.assertEqual(self.rows()[-1][1:],(150,40,19))


    def test_two_sequential_signed_days_survive_real_sqlite_connection_restart(self):
        private = self.folder / "preimages"
        private.mkdir(mode=0o700)
        private.chmod(0o700)
        prior = self.rows()
        first = self.call(
            day="2026-11-16",
            durable=lambda rows: daily.durable_public_preimage(
                private,rows,day="2026-11-16")
        )
        self.assertEqual(first["public_write_count"],1)
        self.conn.close()
        self.conn = sqlite3.connect(self.database_file)
        self.addCleanup(self.conn.close)
        second = self.call(
            day="2026-11-17",
            durable=lambda rows: daily.durable_public_preimage(
                private,rows,day="2026-11-17")
        )
        self.assertEqual(second["status"],"COMMITTED_ONE_SIGNED_COMPLETED_DAY")
        self.assertEqual(second["public_write_count"],1)
        self.assertEqual(self.rows()[:131],prior)
        self.assertEqual(len(self.rows()),133)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM traffic_public_audience_day_certificates_v2"
            ).fetchone()[0],2)
        self.assertEqual(len(list(private.glob("traffic-v2-prior-*.json"))),2)
        self.assertEqual([r[0] for r in self.rows()[-2:]],
                         ["2026-11-16","2026-11-17"])

    def test_builtin_durable_0600_preimage_fsync_and_no_overwrite(self):
        folder = self.folder / "private"
        folder.mkdir(mode=0o700)
        folder.chmod(0o700)
        before = daily.public_rows(self.conn)
        sha = daily.durable_public_preimage(
            folder, before, day="2026-11-17"
        )
        saved = list(folder.glob("traffic-v2-prior-*.json"))
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(saved[0].read_bytes()).hexdigest(),sha)
        with self.assertRaises(FileExistsError):
            daily.durable_public_preimage(
                folder, before, day="2026-11-17"
            )
        self.assertEqual(len(list(folder.iterdir())),1)

    def test_builtin_private_preimage_refuses_weak_directory_symlink(self):
        private = self.folder / "private"
        private.mkdir(mode=0o700)
        private.chmod(0o755)
        with self.assertRaisesRegex(ValueError,"PREIMAGE_DIRECTORY_NOT_OWNER_PRIVATE"):
            daily.durable_public_preimage(
                private, daily.public_rows(self.conn),day="2026-11-17")
        private.chmod(0o700)
        alias = self.folder / "alias"
        alias.symlink_to(private, target_is_directory=True)
        with self.assertRaisesRegex(ValueError,"PREIMAGE_DIRECTORY_NOT_OWNER_PRIVATE"):
            daily.durable_public_preimage(
                alias,daily.public_rows(self.conn),day="2026-11-17")


if __name__=="__main__":
    unittest.main()
