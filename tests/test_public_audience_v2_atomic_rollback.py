from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_atomic_publish as publication
from scripts import public_audience_v2_atomic_rollback as rollback
from scripts import public_audience_v2_release_manifest as manifest


class HistoricalRollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("""
            CREATE TABLE traffic_public_daily_audience_rollups (
              project_slug TEXT NOT NULL, bucket_day TEXT NOT NULL,
              total_traffic INTEGER NOT NULL, suspected_human INTEGER NOT NULL,
              confirmed_human INTEGER NOT NULL, updated_at TEXT NOT NULL,
              PRIMARY KEY(project_slug,bucket_day)
            )
        """)
        dates = manifest.days_between(manifest.START, manifest.END_EXCLUSIVE)
        self.candidate = {
            day: [j + 500, j + 70, j + 20]
            for j, day in enumerate(dates)
        }
        self.old = [
            {
                "day": d, "total": v[0], "potential": v[1],
                "confirmed": v[2], "updated_at": "2026-10-14T08:16:41+00:00"
            }
            for d, v in sorted({
                "2026-06-09": [90, 3, 1],
                "2026-06-10": [2939, 21, 9],
                **{day: vals for day, vals in self.candidate.items()
                   if day <= "2026-10-14"}
            }.items())
        ]
        self.candidate_sha = manifest.sha(self.candidate)
        self.old_sha = manifest.sha(publication.audience_matrix(self.old))
        for day, vals in self.candidate.items():
            self.db.execute(
                "INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?,?)",
                (publication.PROJECT, day, *vals, "2026-10-20T20:00:00+00:00")
            )
        self.db.execute(
            "INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?,?)",
            ("other-project", "2026-10-17", 9, 8, 7, "2026-10-17T00:00:00+00:00")
        )
        self.db.commit()

    def build_preimage(self):
        with patch.object(publication, "EXPECTED_LEGACY_SHA", self.old_sha):
            return publication.preimage_backup(self.dir, self.old)

    def test_preimage_verification_and_atomic_restore_preserve_unrelated_projects(self):
        preimage = self.build_preimage()
        with patch.object(publication, "EXPECTED_LEGACY_SHA", self.old_sha):
            approved = rollback.verified_preimage(preimage, self.dir)
            self.assertEqual(approved, self.old)
            with patch.object(publication, "EXPECTED_CANDIDATE_SHA", self.candidate_sha):
                outcome = rollback.transactional_restore(self.db, approved)
                self.assertEqual(outcome["result"], "RESTORED_OLD_PUBLIC_AUDIENCE")
                self.assertEqual(publication.public_rows(self.db), self.old)
                repeat = rollback.transactional_restore(self.db, approved)
                self.assertEqual(repeat["result"], "ALREADY_RESTORED")
        other = self.db.execute(
            "SELECT total_traffic FROM traffic_public_daily_audience_rollups "
            "WHERE project_slug='other-project'"
        ).fetchone()
        self.assertEqual(other, (9,))

    def test_changed_new_archive_refuses_rollback(self):
        self.db.execute(
            "UPDATE traffic_public_daily_audience_rollups SET total_traffic=5555 "
            "WHERE project_slug=? AND bucket_day='2026-09-13'",
            (publication.PROJECT,),
        )
        self.db.commit()
        previous = publication.public_rows(self.db)
        with patch.object(publication, "EXPECTED_LEGACY_SHA", self.old_sha):
            with patch.object(publication, "EXPECTED_CANDIDATE_SHA", self.candidate_sha):
                with self.assertRaisesRegex(RuntimeError, "changed public archive"):
                    rollback.transactional_restore(self.db, self.old)
        self.assertEqual(publication.public_rows(self.db), previous)

    def test_sql_insert_failure_rolls_back_deletion(self):
        self.db.execute("""
            CREATE TRIGGER deny_recover BEFORE INSERT
            ON traffic_public_daily_audience_rollups
            WHEN NEW.project_slug='aoe2hdbets' AND NEW.bucket_day='2026-07-10'
            BEGIN SELECT RAISE(ABORT, 'recover simulation'); END;
        """)
        before = publication.public_rows(self.db)
        with patch.object(publication, "EXPECTED_LEGACY_SHA", self.old_sha):
            with patch.object(publication, "EXPECTED_CANDIDATE_SHA", self.candidate_sha):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "recover simulation"):
                    rollback.transactional_restore(self.db, self.old)
        self.assertEqual(publication.public_rows(self.db), before)

    def test_preimage_tamper_denied(self):
        preimage = self.build_preimage()
        record = json.loads(preimage.read_text())
        record["rows"][0]["total"] += 1
        preimage.write_text(json.dumps(record))
        with patch.object(publication, "EXPECTED_LEGACY_SHA", self.old_sha):
            with self.assertRaisesRegex(RuntimeError, "content proof"):
                rollback.verified_preimage(preimage, self.dir)

    def test_untrusted_preimage_permission_denied(self):
        preimage = self.build_preimage()
        os.chmod(preimage, 0o644)
        with self.assertRaisesRegex(RuntimeError, "mode 0600"):
            rollback.verified_preimage(preimage, self.dir)


if __name__ == "__main__":
    unittest.main()
