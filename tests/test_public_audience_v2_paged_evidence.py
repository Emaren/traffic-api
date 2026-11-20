"""Bounded source-only Traffic V2 paging, UTC boundary and restart evidence."""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_paged_evidence as pages
from scripts.public_audience_v2_forward_ledger import FROZEN_WATERMARK as BASE

NOW = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)
DAY = "2026-11-16"
EPOCH = "a" * 64
POLICY = "b" * 64


class PagingEvidenceFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "traffic.sqlite3"
        self.private = Path(self.tmp.name) / "private"
        self.private.mkdir(mode=0o700)
        self.state_file = self.private / "day-state.json"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE traffic_entries(
                    event_id TEXT,timestamp TEXT,line_offset INTEGER,
                    ingested_at_utc TEXT,host TEXT NOT NULL,
                    normalized_path TEXT NOT NULL,ua TEXT NOT NULL);
                CREATE INDEX idx_traffic_entries_timestamp_line_offset
                  ON traffic_entries(timestamp,line_offset);
            """)
            for index in range(1, 13):
                stamp = "2026-11-16T12:00:%02d+00:00" % index
                received = None if index in (2, 6, 8) else stamp
                db.execute("""
                    INSERT INTO traffic_entries
                    (rowid,event_id,timestamp,line_offset,ingested_at_utc,
                     host,normalized_path,ua)
                    VALUES(?,?,?,?,?,?,?,?)
                """,(BASE+index,str(index),stamp,index,received,
                     "aoe2war.com","/","Mozilla/5.0"))
            # Two excluded rows: out-of-epoch canonical source and foreign host.
            db.execute("""INSERT INTO traffic_entries
                (rowid,event_id,timestamp,line_offset,ingested_at_utc,
                 host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)""",
                (BASE+13,"not-snapshot","2026-11-16T12:00:30+00:00",
                 13,None,"aoe2war.com","/","Mozilla/5.0"))
            db.execute("""INSERT INTO traffic_entries
                (rowid,event_id,timestamp,line_offset,ingested_at_utc,
                 host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)""",
                (BASE+14,"foreign","2026-11-16T12:00:31+00:00",
                 14,None,"other.invalid","/","Mozilla/5.0"))
        self.db=sqlite3.connect("file:%s?mode=ro" % self.path,uri=True)
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA query_only=ON")
        self.args=dict(day=DAY,now=NOW,hosts=["aoe2war.com"],
                       source_epoch_sha256=EPOCH,host_rules_sha256=POLICY,
                       snapshot_rowid=BASE+12,forward_prefix_rowid=BASE+12,
                       page_rows=5)

    def page(self, state=None, **kwargs):
        return pages.inspect_page(self.db, continuation=state,
                                  **{**self.args,**kwargs})

    def test_three_pages_replay_exact_prefix_and_preserve_source(self):
        original=self.path.read_bytes()
        first=self.page()
        self.assertTrue(first["has_more"])
        self.assertEqual(first["page_rows_examined"],5)
        state=first["continuation"]
        second=self.page(state)
        self.assertTrue(second["has_more"])
        self.assertEqual(second["page_rows_examined"],5)
        last=self.page(second["continuation"])
        self.assertFalse(last["has_more"])
        self.assertEqual(last["page_rows_examined"],2)
        self.assertEqual(last["source_prefix_rows_examined"],12)
        self.assertEqual(last["source_prefix_missing_insertion_receipts"],3)
        with self.assertRaisesRegex(ValueError,"already scanned"):
            self.page(last["continuation"])
        self.assertFalse(last["publication_authorized"])
        self.assertFalse(last["canonical_sessions_certified"])
        self.assertFalse(last["upstream_log_delivery_complete"])
        self.assertEqual(last["certified_days"],[])
        self.assertEqual(self.path.read_bytes(),original)

    def test_atomic_checkpoint_restore_next_page_after_process_restart(self):
        first=self.page()
        first_hash=pages.save_private_continuation(self.state_file,
                                                    first["continuation"])
        state, read_hash=pages.read_private_continuation(self.state_file)
        self.assertEqual(first_hash,read_hash)
        self.assertEqual(self.page(state)["source_prefix_rows_examined"],10)
        with self.assertRaisesRegex(ValueError,"preimage drift"):
            pages.save_private_continuation(
                self.state_file,state,expected_prior_sha256="f"*64)
        second=self.page(state)
        second_hash=pages.save_private_continuation(
            self.state_file,second["continuation"],
            expected_prior_sha256=read_hash)
        self.assertNotEqual(second_hash,read_hash)
        reloaded,_=pages.read_private_continuation(self.state_file)
        self.assertEqual(self.page(reloaded)["source_prefix_rows_examined"],12)

    def test_repeat_page_from_same_state_is_deterministic_not_a_double_count(self):
        first=self.page()
        second_a=self.page(first["continuation"])
        second_b=self.page(json.loads(json.dumps(first["continuation"])))
        self.assertEqual(second_a["continuation"],second_b["continuation"])
        self.assertEqual(second_a["source_prefix_rows_examined"],10)

    def test_more_than_20000_source_events_are_processed_across_pages(self):
        # This is the exact case the previous per-DAY 20k diagnostic cannot
        # inspect. We use 20k per PAGE with no full-history source scan.
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM traffic_entries WHERE rowid=?",(BASE+13,))
            db.executemany("""INSERT INTO traffic_entries
                (rowid,event_id,timestamp,line_offset,ingested_at_utc,
                 host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)""",
                ((BASE+20+i,str(i),"2026-11-16T19:00:00+00:00",i,
                  "2026-11-16T19:00:00+00:00","aoe2war.com","/",
                  "Mozilla/5.0") for i in range(1,20002)))
        pinned=dict(snapshot_rowid=BASE+20021,forward_prefix_rowid=BASE+20021,
                    page_rows=20000,budget_seconds=45)
        first=self.page(**pinned)
        self.assertEqual(first["page_rows_examined"],20000)
        self.assertTrue(first["has_more"])
        second=self.page(first["continuation"],**pinned)
        self.assertEqual(second["page_rows_examined"],13)
        self.assertFalse(second["has_more"])
        self.assertEqual(second["source_prefix_rows_examined"],20013)
        self.assertFalse(second["publication_authorized"])

    def test_changed_epoch_policy_day_prefix_cannot_resume(self):
        first=self.page()
        for override in [
            {"source_epoch_sha256":"c"*64},
            {"host_rules_sha256":"d"*64},
            {"snapshot_rowid":BASE+11},
            {"forward_prefix_rowid":BASE+13},
            {"day":"2026-11-17"},
        ]:
            with self.subTest(override=override),self.assertRaises(ValueError):
                self.page(first["continuation"],**override)

    def test_invalid_resume_key_and_counts_rejected(self):
        state=self.page()["continuation"]
        for new in (["2026-11-17T00:00:00+00:00",1,BASE+5],
                    ["2026-11-16T12:00:05+00:00",-1,BASE+5],
                    ["2026-11-16T12:00:05+00:00",5,BASE+13]):
            altered={**state,"last_key":new}
            with self.subTest(new=new),self.assertRaises(ValueError):
                self.page(altered)
        altered={**state,"missing_receipts":999}
        with self.assertRaises(ValueError):
            self.page(altered)

    def test_bound_and_utc_day_stay_fail_closed(self):
        with self.assertRaisesRegex(ValueError,"per-page scan bound"):
            self.page(page_rows=pages.PAGE_CEILING+1)
        with self.assertRaisesRegex(ValueError,"completed future-epoch"):
            self.page(day="2026-11-18")
        with self.assertRaisesRegex(ValueError,"UTC"):
            self.page(day="2026-11-16", now=datetime(2026,11,18))

    def test_no_query_only_or_missing_index_stops(self):
        self.db.execute("PRAGMA query_only=OFF")
        with self.assertRaisesRegex(ValueError,"query_only"):
            self.page()
        self.db.execute("PRAGMA query_only=ON")
        with sqlite3.connect(self.path) as mut:
            mut.execute("DROP INDEX idx_traffic_entries_timestamp_line_offset")
        with self.assertRaisesRegex(ValueError,"ordering index"):
            self.page()

    def test_private_checkpoint_security_and_preimage(self):
        state=self.page()["continuation"]
        with self.assertRaisesRegex(ValueError,"private"):
            other_dir=Path(self.tmp.name) / "unprotected"
            other_dir.mkdir(mode=0o755)
            other=other_dir / "unprotected.json"
            pages.save_private_continuation(other,state)
        pages.save_private_continuation(self.state_file,state)
        os.chmod(self.state_file,0o644)
        with self.assertRaisesRegex(ValueError,"0600"):
            pages.read_private_continuation(self.state_file)
        os.chmod(self.state_file,0o600)
        self.state_file.unlink()
        self.state_file.symlink_to(self.path)
        with self.assertRaises(OSError):
            pages.save_private_continuation(self.state_file,state)

    def test_second_private_writer_cannot_take_active_lock(self):
        state=self.page()["continuation"]
        h=pages.save_private_continuation(self.state_file,state)
        lockpath=self.private / (self.state_file.name + ".lock")
        fd=os.open(lockpath,os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                pages.save_private_continuation(
                    self.state_file,state,expected_prior_sha256=h)
        finally:
            os.close(fd)
        loaded,after=pages.read_private_continuation(self.state_file)
        self.assertEqual(h,after)
        self.assertEqual(loaded,state)

    def test_interrupted_atomic_save_keeps_prior_committed_state(self):
        first=self.page()
        h=pages.save_private_continuation(self.state_file,
                                          first["continuation"])
        second=self.page(first["continuation"])
        with patch.object(pages.os,"replace",side_effect=OSError("crash")):
            with self.assertRaisesRegex(OSError,"crash"):
                pages.save_private_continuation(
                    self.state_file,second["continuation"],
                    expected_prior_sha256=h)
        loaded,still=pages.read_private_continuation(self.state_file)
        self.assertEqual(still,h)
        self.assertEqual(loaded,first["continuation"])


if __name__=="__main__":
    unittest.main()
