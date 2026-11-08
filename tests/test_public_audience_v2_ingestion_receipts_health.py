"""Protect observable ingestion timestamps from being mistaken for day finality."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import subprocess
import sys
import json
import tempfile
import unittest

from scripts import public_audience_v2_ingestion_receipts_health as audit


NOW = datetime(2026, 11, 3, 23, 50, tzinfo=timezone.utc)
def row(i: int, day: str = "2026-11-03",
        inserted: str | None = "2026-11-03T23:10:00.000+00:00"):
    return (i, day + "T23:00:00+00:00", inserted)


class SampleReadiness(unittest.TestCase):
    def test_no_schema_is_explanatory_hold_not_publication(self):
        receipt=audit.sample_health([row(9,inserted=None)],
                                    now_utc=NOW,receipts_column=False)
        self.assertEqual(receipt["status"],"HOLD_SOURCE_COLUMN_ABSENT")
        self.assertEqual(receipt["legacy_or_uninstrumented_rows"],1)
        self.assertFalse(receipt["publication_authorized"])
        self.assertFalse(receipt["canonical_archive_integrity_verified_by_this_audit"])
        self.assertEqual(receipt["baseline_only_last_published_utc_day"],"2026-10-19")
        self.assertEqual(receipt["ready_to_publish_days"],[])
        self.assertFalse(receipt["remote_log_delivery_complete"])
        self.assertFalse(receipt["global_ip_classification_stable"])
        self.assertFalse(receipt["two_complete_days_certified"])

    def test_real_insert_clock_is_observation_not_certification(self):
        # Newer rowid 30 must have insertion clock >= older rowid 29.
        rows=[row(30,inserted="2026-11-03T23:11:00.000+00:00"),
              row(29),row(28,inserted=None)]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"OBSERVED_RECEIPT_SAMPLE_ONLY")
        self.assertEqual(receipt["sampled_insert_clock_receipts"],2)
        self.assertEqual(receipt["legacy_or_uninstrumented_rows"],1)
        self.assertEqual(receipt["observed_ingestion_delay_max_milliseconds"],660000)
        self.assertEqual(receipt["observed_delays_over_30_minutes"],0)
        self.assertFalse(receipt["publication_authorized"])
        self.assertNotIn("ip",receipt)
        self.assertNotIn("ua",receipt)
        self.assertNotIn("actor",receipt)

    def test_mixed_recent_writer_is_hold(self):
        rows=[row(31,inserted=None),row(30),
              row(29,inserted=None)]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"HOLD_RECENT_WRITER_MISSING_RECEIPTS")
        self.assertEqual(receipt["missing_receipts_newer_than_most_recent_receipt"],1)

    def test_interior_receipt_hole_fails_closed_not_legacy_boundary(self):
        rows=[row(34),row(33,inserted=None),row(32)]
        result=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(result["status"],"HOLD_INTERLEAVED_INGESTION_RECEIPT_GAPS")
        self.assertEqual(result["missing_receipts_between_instrumented_rows"],1)
        self.assertEqual(result["older_null_rows_with_unproven_boundary"],0)
        self.assertEqual(result["sampled_insert_clock_receipts"],2)
        self.assertFalse(result["publication_authorized"])

    def test_multiple_interleaved_holes_counted_without_private_data(self):
        rows=[row(39),row(38,inserted=None),row(37,inserted=None),
              row(36),row(35,inserted=None),row(34)]
        result=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(result["status"],"HOLD_INTERLEAVED_INGESTION_RECEIPT_GAPS")
        self.assertEqual(result["missing_receipts_between_instrumented_rows"],3)
        self.assertNotIn("source_path",result)
        self.assertNotIn("ip",result)

    def test_older_contiguous_null_tail_remains_legitimate_legacy(self):
        rows=[row(37),row(36),row(35,inserted=None),row(34,inserted=None)]
        result=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(result["status"],"OBSERVED_RECEIPT_SAMPLE_ONLY")
        self.assertEqual(result["missing_receipts_between_instrumented_rows"],0)
        self.assertEqual(result["older_null_rows_with_unproven_boundary"],2)
        self.assertFalse(result["publication_authorized"])

    def test_insertion_clock_reversal_fails_closed_even_with_positive_event_delay(self):
        # The highest ROWID is newest; its ingestion clock cannot legitimately
        # precede an older row's SQLite insertion clock.
        rows=[
            row(40, inserted="2026-11-03T23:10:00+00:00"),
            row(39, inserted="2026-11-03T23:12:00+00:00"),
            row(38, inserted="2026-11-03T23:09:00+00:00"),
        ]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"HOLD_INGESTION_CLOCK_ROWID_REVERSAL")
        self.assertEqual(receipt["ingestion_clock_rowid_reversals"],1)
        self.assertEqual(receipt["nonnegative_ingest_delay_rows"],3)
        self.assertEqual(receipt["event_time_after_insert"],0)
        self.assertFalse(receipt["publication_authorized"])

    def test_equal_sqlite_batch_insertion_clocks_are_legitimate(self):
        rows=[
            row(40, inserted="2026-11-03T23:10:00.123+00:00"),
            row(39, inserted="2026-11-03T23:10:00.123+00:00"),
            row(38, inserted="2026-11-03T23:10:00.123+00:00"),
        ]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"OBSERVED_RECEIPT_SAMPLE_ONLY")
        self.assertEqual(receipt["ingestion_clock_rowid_reversals"],0)
        self.assertFalse(receipt["publication_authorized"])

    def test_reversal_behind_historical_null_and_newer_gap_remains_hold(self):
        rows=[
            row(43, inserted="2026-11-03T23:10:00+00:00"),
            row(42, inserted=None),
            row(41, inserted="2026-11-03T23:12:00+00:00"),
        ]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"HOLD_INTERLEAVED_INGESTION_RECEIPT_GAPS")
        self.assertEqual(receipt["missing_receipts_between_instrumented_rows"],1)
        self.assertEqual(receipt["ingestion_clock_rowid_reversals"],1)
        self.assertFalse(receipt["publication_authorized"])

    def test_clock_in_future_is_hold(self):
        rows=[row(30,inserted="2026-11-04T23:10:00+00:00")]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"HOLD_CLOCK_CONSISTENCY")
        self.assertEqual(receipt["future_insert_clock_rows"],1)

    def test_negative_lag_is_hold(self):
        rows=[row(30,inserted="2026-11-03T22:10:00+00:00")]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"HOLD_NO_VALID_INGESTION_RECEIPTS")
        self.assertEqual(receipt["event_time_after_insert"],1)

    def test_two_valid_and_one_negative_is_hold(self):
        rows=[row(30),row(29,inserted="2026-11-03T22:10:00+00:00")]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"HOLD_CLOCK_CONSISTENCY")
        self.assertEqual(receipt["event_time_after_insert"],1)

    def test_historical_null_before_first_new_receipt_is_allowed(self):
        rows=[row(31),row(30,day="2026-10-21",inserted=None)]
        receipt=audit.sample_health(rows,now_utc=NOW,receipts_column=True)
        self.assertEqual(receipt["status"],"OBSERVED_RECEIPT_SAMPLE_ONLY")
        self.assertTrue(receipt["historic_null_timestamps_not_backfilled"])

    def test_utc_clock_rejects_nonzero_timezone(self):
        with self.assertRaisesRegex(ValueError,"non-UTC ingestion clock"):
            audit.sample_health(
                [row(31,inserted="2026-11-03T16:10:00-07:00")],
                now_utc=NOW,receipts_column=True,
            )

    def test_no_event_time_zone_fails(self):
        with self.assertRaisesRegex(ValueError,"lacks UTC offset"):
            audit.sample_health(
                [(31,"2026-11-03T23:00:00","2026-11-03T23:10:00+00:00")],
                now_utc=NOW,receipts_column=True,
            )

    def test_duplicate_rowid_or_unbounded_sample_fails(self):
        with self.assertRaisesRegex(ValueError,"rowids not strictly"):
            audit.sample_health([row(31),row(31)],now_utc=NOW,receipts_column=True)
        with self.assertRaisesRegex(ValueError,"exceeds bounded"):
            audit.sample_health([row(1)] * (audit.MAX_SAMPLE+1),
                                now_utc=NOW,receipts_column=True)

    def test_future_source_time_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"future-dated"):
            audit.sample_health([(33,"2026-11-05T11:00:00+00:00",None)],
                                now_utc=NOW,receipts_column=True)

    def test_release_cutoff_cannot_be_silently_rebased(self):
        with self.assertRaisesRegex(ValueError,"published audience boundary"):
            audit.sample_health([],now_utc=NOW,receipts_column=True,
                                last_certified_day="2026-11-03")


class RealSQLiteReadOnly(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/"traffic.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def create(self,clock:bool):
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE traffic_entries (event_id TEXT, timestamp TEXT" +
                       (", ingested_at_utc TEXT)" if clock else ")"))
            for i in range(1,5):
                if clock:
                    db.execute("INSERT INTO traffic_entries VALUES (?,?,?)",
                               (str(i),"2026-11-03T23:00:00+00:00",
                                "2026-11-03T23:10:00+00:00"))
                else:
                    db.execute("INSERT INTO traffic_entries VALUES (?,?)",
                               (str(i),"2026-11-03T23:00:00+00:00"))

    def test_read_only_observation_no_database_edits(self):
        self.create(clock=True)
        before=self.path.read_bytes()
        receipt=audit.audit(self.path,sample=3)
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(receipt["sampled_recent_source_rows"],3)
        self.assertEqual(receipt["sampled_insert_clock_receipts"],3)
        self.assertTrue(receipt["read_only_sqlite_connection"])
        self.assertFalse(receipt["publication_authorized"])
        self.assertFalse((self.path.parent/"traffic.sqlite3-wal").exists())

    def test_real_sqlite_insert_clock_reversal_is_readonly_hold(self):
        self.create(clock=True)
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE traffic_entries SET ingested_at_utc = "
                "'2026-11-03T23:12:00+00:00' WHERE rowid=3"
            )
        before=self.path.read_bytes()
        result=audit.audit(self.path,sample=4)
        self.assertEqual(result["status"],"HOLD_INGESTION_CLOCK_ROWID_REVERSAL")
        self.assertEqual(result["ingestion_clock_rowid_reversals"],1)
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(before,self.path.read_bytes())

    def test_cli_reversal_requires_nonzero_and_does_not_mutate_sqlite(self):
        self.create(clock=True)
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE traffic_entries SET ingested_at_utc = "
                "'2026-11-03T23:12:00+00:00' WHERE rowid=3"
            )
        before=self.path.read_bytes()
        result=subprocess.run(
            [sys.executable, "-m", "scripts.public_audience_v2_ingestion_receipts_health",
             "--source", str(self.path), "--sample", "4", "--require-receipts"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,text=True,timeout=10,
        )
        self.assertEqual(result.returncode,2)
        output=json.loads(result.stdout)
        self.assertEqual(output["status"],"HOLD_INGESTION_CLOCK_ROWID_REVERSAL")
        self.assertFalse(output["publication_authorized"])
        self.assertEqual(self.path.read_bytes(),before)

    def test_real_sqlite_interleaved_receipts_fail_closed_without_writes(self):
        self.create(clock=True)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE traffic_entries SET ingested_at_utc = NULL WHERE event_id='3'")
        original=self.path.read_bytes()
        result=audit.audit(self.path,sample=4)
        self.assertEqual(result["status"],"HOLD_INTERLEAVED_INGESTION_RECEIPT_GAPS")
        self.assertEqual(result["missing_receipts_between_instrumented_rows"],1)
        self.assertEqual(original,self.path.read_bytes())
        self.assertFalse(result["publication_authorized"])

    def test_cli_interleaved_receipt_hole_requires_failure(self):
        self.create(clock=True)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE traffic_entries SET ingested_at_utc=NULL WHERE event_id='3'")
        before=self.path.read_bytes()
        result=subprocess.run(
            [sys.executable, "-m", "scripts.public_audience_v2_ingestion_receipts_health",
             "--source", str(self.path), "--sample", "4", "--require-receipts"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,text=True,timeout=10,
        )
        self.assertEqual(result.returncode,2)
        response=json.loads(result.stdout)
        self.assertEqual(response["status"],"HOLD_INTERLEAVED_INGESTION_RECEIPT_GAPS")
        self.assertFalse(response["publication_authorized"])
        self.assertEqual(self.path.read_bytes(),before)

    def test_missing_column_stays_missing(self):
        self.create(clock=False)
        before=self.path.read_bytes()
        receipt=audit.audit(self.path,sample=3)
        self.assertEqual(receipt["status"],"HOLD_SOURCE_COLUMN_ABSENT")
        self.assertEqual(before,self.path.read_bytes())
        with sqlite3.connect(self.path) as db:
            self.assertNotIn("ingested_at_utc",
                             {r[1] for r in db.execute("PRAGMA table_info(traffic_entries)")})

    def test_cli_require_receipts_exits_nonzero_on_missing_clock(self):
        self.create(clock=False)
        result = subprocess.run(
            [sys.executable, "-m",
             "scripts.public_audience_v2_ingestion_receipts_health",
             "--source", str(self.path), "--sample", "3",
             "--require-receipts"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"],
                         "HOLD_SOURCE_COLUMN_ABSENT")
        self.assertFalse(result.stderr)

    def test_cli_informational_hold_does_not_look_like_publication(self):
        self.create(clock=False)
        result = subprocess.run(
            [sys.executable, "-m",
             "scripts.public_audience_v2_ingestion_receipts_health",
             "--source", str(self.path), "--sample", "3"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        body = json.loads(result.stdout)
        self.assertFalse(body["publication_authorized"])
        self.assertEqual(body["status"], "HOLD_SOURCE_COLUMN_ABSENT")

    def test_missing_source_does_not_create_one(self):
        with self.assertRaisesRegex(ValueError,"source database missing"):
            audit.audit(self.path,sample=3)
        self.assertFalse(self.path.exists())

    def test_too_large_and_zero_samples_refused(self):
        self.create(clock=True)
        for count in (0,10001):
            with self.subTest(count=count),self.assertRaisesRegex(ValueError,"invalid bounded"):
                audit.audit(self.path,sample=count)


if __name__=="__main__": unittest.main()
