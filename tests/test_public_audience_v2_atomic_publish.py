from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_atomic_publish as publish
from scripts import public_audience_v2_release_manifest as manifest


DDL = """
CREATE TABLE traffic_public_daily_audience_rollups (
 project_slug TEXT NOT NULL,
 bucket_day TEXT NOT NULL,
 total_traffic INTEGER NOT NULL,
 suspected_human INTEGER NOT NULL,
 confirmed_human INTEGER NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(project_slug,bucket_day)
);
"""


class AtomicPublicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.private = Path(temp.name)
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.execute(DDL)
        self.candidate = {
            day: [300 + i, 40 + i, 10 + i]
            for i, day in enumerate(
                manifest.days_between(manifest.START, manifest.END_EXCLUSIVE)
            )
        }
        self.legacy = {
            "2026-06-09": [90, 3, 1],
            "2026-06-10": [2939, 21, 9],
        }
        for day in sorted(self.candidate):
            if day <= "2026-10-14":
                self.legacy[day] = self.candidate[day]
        self.assertEqual(len(self.legacy), 128)
        for day, numbers in self.legacy.items():
            self.conn.execute(
                "INSERT INTO traffic_public_daily_audience_rollups "
                "VALUES(?,?,?,?,?,?)",
                (publish.PROJECT, day, *numbers, "2026-10-14T08:16:41+00:00"),
            )
        self.conn.execute(
            "INSERT INTO traffic_public_daily_audience_rollups "
            "VALUES(?,?,?,?,?,?)",
            ("other-project", "2026-10-14", 8, 7, 6,
             "2026-10-14T08:16:41+00:00"),
        )
        self.conn.commit()
        self.candidate_hash = manifest.sha(self.candidate)
        self.before_hash = manifest.sha(
            publish.audience_matrix(publish.public_rows(self.conn))
        )

    def publisher(self, callback=None):
        with patch.object(publish, "EXPECTED_CANDIDATE_SHA",
                          self.candidate_hash):
            return publish.transactional_replace(
                self.conn, self.candidate,
                expected_previous_sha=self.before_hash,
                backup_old=callback or (
                    lambda rows: publish.preimage_backup(self.private, rows)
                ),
            )

    def snapshot(self):
        return publish.public_rows(self.conn)

    def test_atomic_131_day_release_preserves_other_projects_and_preimage(self):
        previous = self.snapshot()
        result = self.publisher()
        self.assertEqual(result["result"], "COMMITTED")
        self.assertEqual(result["written_days"], 131)
        self.assertEqual(
            manifest.sha(publish.audience_matrix(self.snapshot())),
            self.candidate_hash,
        )
        self.assertNotIn("2026-06-09",
                         publish.audience_matrix(self.snapshot()))
        self.assertNotIn("2026-06-10",
                         publish.audience_matrix(self.snapshot()))
        backup = Path(result["backup_file"])
        self.assertTrue(backup.exists())
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        saved = json.loads(backup.read_text())
        self.assertEqual(saved["rows"], previous)
        self.assertEqual(saved["matrix_sha256"], self.before_hash)
        other = self.conn.execute(
            "SELECT total_traffic,suspected_human,confirmed_human "
            "FROM traffic_public_daily_audience_rollups "
            "WHERE project_slug='other-project'"
        ).fetchone()
        self.assertEqual(other, (8, 7, 6))

    def test_identical_repeat_is_noop_without_backup_or_timestamp_change(self):
        self.publisher()
        first_rows = self.snapshot()
        result = self.publisher(callback=lambda _: self.fail(
            "Must never create another preimage on exact no-op"
        ))
        self.assertEqual(result["result"], "ALREADY_PUBLISHED")
        self.assertEqual(result["written_days"], 0)
        self.assertEqual(self.snapshot(), first_rows)

    def test_backup_failure_rolls_back_original_legacy(self):
        old = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "simulated"):
            self.publisher(callback=lambda _: (_ for _ in ()).throw(
                RuntimeError("simulated backup failure")
            ))
        self.assertEqual(self.snapshot(), old)

    def test_sql_trigger_failure_rolls_back_deletion_and_insertion(self):
        old = self.snapshot()
        self.conn.execute("""
        CREATE TRIGGER abort_new_day
        BEFORE INSERT ON traffic_public_daily_audience_rollups
        WHEN NEW.project_slug='aoe2hdbets' AND NEW.bucket_day='2026-08-01'
        BEGIN
          SELECT RAISE(ABORT, 'simulated transaction failure');
        END;
        """)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "simulated"):
            self.publisher()
        self.assertEqual(self.snapshot(), old)
        self.assertTrue(list(self.private.glob("v2-public-audience-preimage-*.json")))

    def test_public_archive_cas_change_is_refused(self):
        self.conn.execute(
            "UPDATE traffic_public_daily_audience_rollups "
            "SET total_traffic=total_traffic+1 "
            "WHERE project_slug=? AND bucket_day='2026-06-12'",
            (publish.PROJECT,),
        )
        self.conn.commit()
        old = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "compare-and-swap"):
            self.publisher()
        self.assertEqual(self.snapshot(), old)
        self.assertFalse(list(self.private.glob("v2-public-audience-preimage-*.json")))

    def test_invalid_candidate_does_not_start_transaction(self):
        invalid = dict(self.candidate)
        invalid.pop("2026-06-12")
        with patch.object(publish, "EXPECTED_CANDIDATE_SHA",
                          manifest.sha(invalid)):
            with self.assertRaisesRegex(RuntimeError, "unexpected days"):
                publish.transactional_replace(
                    self.conn, invalid, expected_previous_sha=self.before_hash,
                    backup_old=lambda _: self.fail("must not save"),
                )
        self.assertEqual(len(self.snapshot()), 128)

    def test_preimage_durability_requires_private_directory(self):
        os.chmod(self.private, 0o755)
        with self.assertRaisesRegex(RuntimeError, "private backup directory"):
            publish.preimage_backup(self.private, self.snapshot())
        os.chmod(self.private, 0o700)


if __name__ == "__main__":
    unittest.main()
