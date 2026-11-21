"""Bounded keyset UTC source evidence; never a publication certificate."""
import sqlite3
import unittest
from unittest.mock import patch
from scripts import public_audience_v2_day_ingest_evidence as paged
from scripts import public_audience_v2_forward_ledger as forward
from tests import test_public_audience_v2_day_ingest_evidence as fixture
D=fixture.D
NOW=fixture.NOW

class PagedReadOnlyWitness(unittest.TestCase):
 def setUp(self):
  # Reuse exact original preflight fixture, including its real nonmocked
  # forward epoch validation and original read-only canonical filter.
  fixture.DayEvidenceSqliteTests.setUp(self)
 def populate(self,n=106,tied=False,missing=False):
  with sqlite3.connect(self.source) as db:
   for i in range(2,n+1):
    db.execute("INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc,host,normalized_path,ua) VALUES(?,?,?,?,?,?,?,?)",
      (forward.FROZEN_WATERMARK+i,"synthetic",D+"T10:00:00+00:00",
       1 if tied else i,None if missing and i==n else D+"T10:01:00+00:00",
       "aoe2war.com","/","Mozilla"))
  with sqlite3.connect(self.ledger) as db:
   db.execute("UPDATE ledger_metadata SET value=? WHERE key='live_rowid'",
      (str(forward.FROZEN_WATERMARK+n),))
 def witness(self,**kw):
  options={"day":D,"now":NOW,"paged":True,"max_rows":50,
           "max_pages":5,"budget_seconds":30}
  options.update(kw)
  return paged.audit(self.source,self.checkpoint,self.ledger,self.lock,**options)
 def test_keyset_pages_106_rows_same_source_snapshot_no_certificate(self):
  self.populate()
  before=self.source.read_bytes()
  r=self.witness()
  self.assertEqual(r["source_rows_examined"],106)
  self.assertEqual([p["rows"] for p in r["source_keyset_pages"]],[50,50,6])
  self.assertEqual(r["source_keyset_page_count"],3)
  self.assertTrue(r["full_day_eof_page_observed"])
  self.assertFalse(r["publication_authorized"])
  self.assertFalse(r["full_day_independent_signatures_verified"])
  self.assertEqual(r["ready_to_publish_days"],[])
  self.assertEqual(r["status"],"HOLD_INDEPENDENT_DELIVERY_AND_CLASSIFIER_FINALITY_ABSENT")
  self.assertEqual(before,self.source.read_bytes())
 def test_real_20k_page_boundary_with_20015_rows(self):
  self.populate(n=20015)
  r=paged.audit(self.source,self.checkpoint,self.ledger,self.lock,
   day=D,now=NOW,paged=True,max_rows=20000,max_pages=3,budget_seconds=30)
  self.assertEqual(r["source_rows_examined"],20015)
  self.assertEqual([p["rows"] for p in r["source_keyset_pages"]],[20000,15])
  self.assertTrue(r["full_day_eof_page_observed"])
  self.assertFalse(r["publication_authorized"])
  self.assertEqual(r["status"],"HOLD_INDEPENDENT_DELIVERY_AND_CLASSIFIER_FINALITY_ABSENT")
 def test_identical_event_clock_and_offset_uses_rowid_tiebreaker(self):
  self.populate(n=106,tied=True)
  r=self.witness()
  self.assertEqual(r["source_rows_examined"],106)
  self.assertEqual(r["source_keyset_page_count"],3)
 def test_paged_total_rows_does_not_silently_truncate(self):
  self.populate()
  with self.assertRaisesRegex(ValueError,"page ceiling reached before EOF"):
   self.witness(max_pages=2)
 def test_legacy_single_page_remains_fail_closed(self):
  self.populate()
  with self.assertRaisesRegex(ValueError,"more events than bounded source scan"):
   paged.audit(self.source,self.checkpoint,self.ledger,self.lock,
     day=D,now=NOW,paged=False,max_rows=50,budget_seconds=30)
 def test_missing_receipt_across_page_boundary_is_hold(self):
  self.populate(n=106,missing=True)
  r=self.witness()
  self.assertEqual(r["rows_with_missing_insertion_receipt"],1)
  self.assertEqual(r["status"],"HOLD_INSERTION_CLOCK_UNKNOWN")
 def test_max_pages_and_budget_enforced(self):
  with self.assertRaisesRegex(ValueError,"budget outside"):
   paged.audit(self.source,self.checkpoint,self.ledger,self.lock,
    day=D,now=NOW,paged=True,max_pages=61)
  with self.assertRaisesRegex(ValueError,"budget outside"):
   paged.audit(self.source,self.checkpoint,self.ledger,self.lock,
    day=D,now=NOW,paged=True,budget_seconds=181)
  with self.assertRaisesRegex(ValueError,"budget outside"):
   paged.audit(self.source,self.checkpoint,self.ledger,self.lock,
    day=D,now=NOW,paged=False,budget_seconds=90)
if __name__=="__main__":unittest.main()
