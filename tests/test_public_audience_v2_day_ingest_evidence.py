"""Source-only day ingestion evidence contract; no live SQLite or publisher."""
from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from scripts import public_audience_v2_day_ingest_evidence as evidence
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v2_guarded_resume as guard
from scripts import public_audience_v2_sessions as sessions

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
D = "2026-11-14"


def row(rowid=forward.FROZEN_WATERMARK + 1,
        event="2026-11-14T10:00:00+00:00",
        inserted="2026-11-14T10:01:00+00:00"):
    return (rowid, event, inserted)


class DayEvidencePureTests(unittest.TestCase):
    def report(self, rows, *, day=D, cursor=None, **kwargs):
        return evidence.evaluate_rows(
            rows, day=day, now=NOW,
            cursor=cursor if cursor is not None else forward.FROZEN_WATERMARK + 4,
            max_rowid=forward.FROZEN_WATERMARK + 5,
            retroactive_frozen_history=kwargs.pop("retroactive", False),
            **kwargs,
        )

    def test_past_good_receipts_still_cannot_certify_delivery_or_classify(self):
        r = self.report([row()])
        self.assertEqual(r["status"], "HOLD_INDEPENDENT_DELIVERY_AND_CLASSIFIER_FINALITY_ABSENT")
        self.assertFalse(r["publication_authorized"])
        self.assertEqual(r["ready_to_publish_days"], [])
        self.assertFalse(r["upstream_log_delivery_complete"])
        self.assertFalse(r["source_equivalent_sessions_certified"])
        self.assertFalse(r["cross_midnight_carry_certified"])

    def test_missing_historical_insert_stamp_is_unknown_not_zero(self):
        r = self.report([row(inserted=None)],day="2026-11-14")
        self.assertEqual(r["status"], "HOLD_INSERTION_CLOCK_UNKNOWN")
        self.assertEqual(r["rows_with_missing_insertion_receipt"], 1)
        self.assertTrue(r["unknown_days_not_filled_with_zero"])

    def test_lagging_forward_cursor_is_hold(self):
        r = self.report([row(rowid=forward.FROZEN_WATERMARK + 5)])
        self.assertEqual(r["status"], "HOLD_DAY_SOURCE_PREFIX_NOT_CAPTURED")
        self.assertEqual(r["rows_not_captured_at_prefix"], 1)

    def test_backdated_input_undoes_frozen_october_history(self):
        r = self.report([row()],retroactive=True)
        self.assertEqual(r["status"], "HOLD_FROZEN_HISTORY_RETROACTIVE_INPUT")
        self.assertTrue(r["late_input_targets_frozen_history"])

    def test_zero_observed_rows_is_not_certified_zero_visitors(self):
        r=self.report([])
        self.assertEqual(r["status"], "HOLD_DAY_SOURCE_EVIDENCE_ABSENT")
        self.assertEqual(r["source_rows_examined"],0)

    def test_ingest_clock_before_event_is_invalid(self):
        r=self.report([row(inserted="2026-11-14T09:59:00+00:00")])
        self.assertEqual(r["status"], "HOLD_INSERTION_CLOCK_INCONSISTENT")

    def test_utc_clock_rowid_reversal_is_invalid(self):
        r=self.report([
            row(rowid=forward.FROZEN_WATERMARK + 1,
                inserted="2026-11-14T12:00:00+00:00"),
            row(rowid=forward.FROZEN_WATERMARK + 2,
                inserted="2026-11-14T11:00:00+00:00"),
        ])
        self.assertEqual(r["insertion_clock_rowid_reversals"],1)
        self.assertEqual(r["status"], "HOLD_INSERTION_CLOCK_INCONSISTENT")

    def test_utc_clock_far_in_future_rejected(self):
        r=self.report([row(inserted="2026-11-16T10:01:00+00:00")])
        self.assertEqual(r["status"], "HOLD_INSERTION_CLOCK_INCONSISTENT")

    def test_naive_insertion_clock_refused(self):
        with self.assertRaisesRegex(ValueError,"UTC offset"):
            self.report([row(inserted="2026-11-14T10:01:00")])

    def test_non_utc_zone_insertion_clock_refused(self):
        with self.assertRaisesRegex(ValueError,"UTC offset"):
            self.report([row(inserted="2026-11-14T11:01:00+01:00")])

    def test_malformed_event_outside_day_refused(self):
        with self.assertRaisesRegex(ValueError,"outside requested"):
            self.report([row(event="2026-11-15T00:00:00+00:00")])

    def test_repeated_source_rowids_refused(self):
        with self.assertRaisesRegex(ValueError,"duplicate"):
            self.report([row(),row()])

    def test_invalid_cursor_or_rewind_refused(self):
        with self.assertRaisesRegex(ValueError,"cursor invalid"):
            self.report([row()],cursor=forward.FROZEN_WATERMARK-1)
        with self.assertRaisesRegex(ValueError,"rewind"):
            evidence.evaluate_rows([row()],day=D,now=NOW,
                cursor=forward.FROZEN_WATERMARK+5,
                max_rowid=forward.FROZEN_WATERMARK+4,
                retroactive_frozen_history=False)

    def test_max_day_rows_refused(self):
        with self.assertRaisesRegex(ValueError,"bounded row ceiling"):
            self.report([row()]*(evidence.MAX_DAY_ROWS+1))

    def test_incomplete_today_future_and_original_boundary_stop(self):
        for day in ("2026-11-15", "2026-11-16", "2026-10-19"):
            with self.subTest(day=day), self.assertRaisesRegex(ValueError,"completed future-epoch"):
                evidence.completed_day(day,now=NOW)

    def test_utc_date_not_local_offset(self):
        start,end=evidence.completed_day(D,now=NOW)
        self.assertEqual(start.isoformat(),"2026-11-14T00:00:00+00:00")
        self.assertEqual((end-start).total_seconds(),86400)

    def test_invalid_day_and_naive_now(self):
        for day in ("2026-11-1", "2026-11-99", "11/14/2026"):
            with self.subTest(day=day),self.assertRaises(ValueError):
                evidence.completed_day(day,now=NOW)
        with self.assertRaisesRegex(ValueError,"lacks UTC"):
            evidence.completed_day(D,now=datetime(2026,11,15))


class DayEvidenceSqliteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir=Path(self.tmp.name)
        self.source=self.dir/"raw.sqlite3"
        self.proofdir=self.dir/"private"
        self.proofdir.mkdir(mode=0o700)
        self.ledger=self.proofdir/"ledger.sqlite3"
        self.lock=self.proofdir/".canary.lock"
        self.lock.touch(mode=0o600)
        self.checkpoint=self.proofdir/"checkpoint.sqlite3"
        self.checkpoint.touch(mode=0o600)
        with sqlite3.connect(self.source) as db:
            db.executescript("""
                CREATE TABLE traffic_entries(event_id TEXT,timestamp TEXT,
                    line_offset INTEGER, ingested_at_utc TEXT,
                    host TEXT NOT NULL, normalized_path TEXT NOT NULL,
                    ua TEXT NOT NULL);
                CREATE INDEX idx_traffic_entries_timestamp_line_offset
                    ON traffic_entries(timestamp,line_offset);
            """)
            db.execute("INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc,host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)",
                (forward.FROZEN_WATERMARK+1,"fixture",D+"T10:00:00+00:00",1,D+"T10:01:00+00:00","aoe2war.com","/","Mozilla"))
        os.chmod(self.source,0o600)
        with sqlite3.connect(self.ledger) as db:
            db.execute("CREATE TABLE ledger_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            self.historical = {
                "phase":"PASS2_COMPLETE",
                "device":str(self.source.stat().st_dev),
                "inode":str(self.source.stat().st_ino),
                "hosts_sha256":"fixture-hosts",
                "rules_sha256":"fixture-rules",
                "canonical_sha256":"fixture-canonical",
                "source":str(self.source.resolve()),
            }
            info={
                "original_pass_digest":guard.FROZEN_DIGEST,
                "start":forward.START,
                **{k:v for k,v in self.historical.items() if k!="phase"},
                "phase":"LIVE",
                "original_watermark":str(forward.FROZEN_WATERMARK),
                "historical_public_digest":forward.RELEASE_SHA,
                "device":str(self.source.stat().st_dev),
                "inode":str(self.source.stat().st_ino),
                "live_rowid":str(forward.FROZEN_WATERMARK+1),
            }
            db.executemany("INSERT INTO ledger_metadata VALUES(?,?)",info.items())
        os.chmod(self.ledger,0o600)
        # An isolated synthetic fixture cannot possess the real 131-day
        # historical checkpoint/rollups; only these external roots are mocked.
        # The REAL forward epoch validation still runs unmocked.
        for module, name, return_value in (
            (guard, "checkpoint_info", self.historical),
            (guard, "verify_frozen", None),
            (guard, "require_worker_priority", None),
            (guard, "worker_idle", True),
            (sessions, "verified_state", (["aoe2war.com"], [])),
            (forward, "assert_published_history", None),
        ):
            p=patch.object(module,name,return_value=return_value)
            p.start()
            self.addCleanup(p.stop)

    def audit(self,**kw):
        return evidence.audit(self.source,self.checkpoint,self.ledger,self.lock,
                              day=D,now=NOW,**kw)

    def test_good_read_only_evidence_cannot_be_publication(self):
        before=self.source.read_bytes()
        result=self.audit()
        self.assertEqual(result["source_rows_examined"],1)
        self.assertEqual(result["status"],"HOLD_INDEPENDENT_DELIVERY_AND_CLASSIFIER_FINALITY_ABSENT")
        self.assertTrue(result["shared_canary_lock_acquired"])
        self.assertTrue(result["source_inode_matches_forward_prefix"])
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(self.source.read_bytes(),before)

    def test_previous_day_becomes_uncertain_if_stamp_null(self):
        with sqlite3.connect(self.source) as db:
            db.execute("UPDATE traffic_entries SET ingested_at_utc=NULL")
        self.assertEqual(self.audit()["status"],"HOLD_INSERTION_CLOCK_UNKNOWN")

    def test_raw_source_cursor_behind_is_hold(self):
        with sqlite3.connect(self.source) as db:
            db.execute("INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc,host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)",
                (forward.FROZEN_WATERMARK+2,"future",D+"T10:02:00+00:00",2,D+"T10:03:00+00:00","aoe2war.com","/","Mozilla"))
        self.assertEqual(self.audit()["status"],"HOLD_DAY_SOURCE_PREFIX_NOT_CAPTURED")

    def test_new_frozen_oct19_input_held(self):
        with sqlite3.connect(self.source) as db:
            db.execute("INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc,host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)",
                (forward.FROZEN_WATERMARK+2,"old","2026-10-19T23:59:59+00:00",2,"2026-11-14T11:00:00+00:00","aoe2war.com","/","Mozilla"))
        self.assertEqual(self.audit()["status"],"HOLD_FROZEN_HISTORY_RETROACTIVE_INPUT")

    def test_cli_emits_no_authorization_and_returns_nonzero_hold(self):
        argv=["day-audit","--source",str(self.source),
              "--checkpoint",str(self.checkpoint),"--ledger",str(self.ledger),
              "--lock",str(self.lock),"--day",D]
        with patch("sys.argv",argv), patch.object(
            evidence,"datetime",wraps=datetime
        ) as clock:
            clock.now.return_value=NOW
            out=StringIO()
            with redirect_stdout(out):
                exitcode=evidence.main()
        import json
        report=json.loads(out.getvalue())
        self.assertEqual(exitcode,2)
        self.assertFalse(report["publication_authorized"])
        self.assertFalse(report["public_audience_writes"])
        self.assertEqual(report["certified_days"],[])

    def test_unrelated_hosts_do_not_inflate_canonical_source_inputs(self):
        with sqlite3.connect(self.source) as db:
            db.execute("INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc,host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)",
                (forward.FROZEN_WATERMARK+2,"unrelated",D+"T12:00:00+00:00",3,None,"unrelated.invalid","/","Mozilla"))
        result=self.audit()
        self.assertEqual(result["source_rows_examined"],1)
        self.assertEqual(result["status"],"HOLD_INDEPENDENT_DELIVERY_AND_CLASSIFIER_FINALITY_ABSENT")
        self.assertTrue(result["canonical_host_and_non_browser_filter_checked"])

    def test_missing_index_is_hard_stop(self):
        with sqlite3.connect(self.source) as db:
            db.execute("DROP INDEX idx_traffic_entries_timestamp_line_offset")
        with self.assertRaisesRegex(ValueError,"day index absent"):
            self.audit()

    def test_invalid_source_epoch_rejected(self):
        with sqlite3.connect(self.ledger) as db:
            db.execute("UPDATE ledger_metadata SET value='bad' WHERE key='historical_public_digest'")
        with self.assertRaisesRegex(RuntimeError,"release digest drift"):
            self.audit()

    def test_source_inode_mismatch_rejected(self):
        with sqlite3.connect(self.ledger) as db:
            db.execute("UPDATE ledger_metadata SET value='3' WHERE key='inode'")
        with self.assertRaisesRegex(RuntimeError,"inode drift"):
            self.audit()

    def test_symlink_and_nonprivate_ledger_rejected(self):
        fake=self.dir/"shortcut"
        fake.symlink_to(self.source)
        with self.assertRaisesRegex(ValueError,"regular file"):
            evidence.audit(fake,self.checkpoint,self.ledger,self.lock,day=D,now=NOW)
        os.chmod(self.ledger,0o644)
        with self.assertRaisesRegex(ValueError,"0600"):
            self.audit()

    def test_active_canary_lock_rejected_nonblocking(self):
        fd=os.open(self.lock,os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.audit()
        finally:os.close(fd)

    def test_busy_project_worker_refuses_evidence_before_file_access(self):
        with patch.object(guard,"worker_idle",return_value=False), self.assertRaisesRegex(ValueError,"worker has priority"):
            self.audit()

    def test_bad_historical_checkpoint_refuses_ledger(self):
        self.historical["phase"]="PASS2_RUNNING"
        with self.assertRaisesRegex(ValueError,"checkpoint not complete"):
            self.audit()

    def test_immutable_131_day_histogram_mismatch_holds(self):
        with patch.object(forward,"assert_published_history",side_effect=RuntimeError("131-day changed")):
            with self.assertRaisesRegex(RuntimeError,"131-day changed"):
                self.audit()

    def test_bounded_max_scan_refused(self):
        with sqlite3.connect(self.source) as db:
            db.execute("INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc,host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)",
                (forward.FROZEN_WATERMARK+2,"two",D+"T11:00:00+00:00",2,D+"T11:01:00+00:00","aoe2war.com","/","Mozilla"))
        with self.assertRaisesRegex(ValueError,"more events"):
            self.audit(max_rows=1)

    def test_today_fails_before_touching_files(self):
        with patch.object(Path,"lstat",side_effect=AssertionError("file access")):
            with self.assertRaisesRegex(ValueError,"completed future-epoch"):
                evidence.audit(self.source,self.checkpoint,self.ledger,self.lock,day="2026-11-15",now=NOW)


if __name__=="__main__":
    unittest.main()
