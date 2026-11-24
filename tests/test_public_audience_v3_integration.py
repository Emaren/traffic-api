"""V3 production-path fixture qualification. No live source, keys or install."""
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch
from scripts import public_audience_v2_day_admission as witness
from scripts import public_audience_v2_daily_append as append
from scripts import public_audience_v2_forward_ledger as forward
from scripts import public_audience_v3_source_prepare as source
from scripts import rebuild_public_audience_archive as canonical
from tests.test_public_audience_v2_daily_append import AtomicDailyAppendFixture
from tests.test_public_audience_v2_day_admission import TwoWitnessDayTests

DAY = date(2026,11,23)
NOW = datetime(2026,11,24,12,tzinfo=timezone.utc)
START = datetime(2026,11,23,tzinfo=timezone.utc)
COMMIT="a"*40
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
RAW_DDL="""CREATE TABLE traffic_entries(event_id TEXT,timestamp TEXT,ip TEXT,line_offset INTEGER,
raw_path TEXT,normalized_path TEXT,referrer_host TEXT,ua TEXT,host TEXT,ingested_at_utc TEXT);
CREATE INDEX idx_traffic_entries_timestamp_line_offset ON traffic_entries(timestamp,line_offset);"""


class SourceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.raw=sqlite3.connect(":memory:")
        self.ledger=sqlite3.connect(":memory:")
        self.addCleanup(self.raw.close)
        self.addCleanup(self.ledger.close)
        self.raw.row_factory=sqlite3.Row
        self.ledger.row_factory=sqlite3.Row
        self.raw.executescript(RAW_DDL)
        self.ledger.executescript("CREATE TABLE ledger_metadata(key TEXT PRIMARY KEY,value TEXT);"
                                 "CREATE TABLE future_events(source_rowid INTEGER PRIMARY KEY,event_json TEXT,timestamp TEXT);")
        self.ledger.executemany("INSERT INTO ledger_metadata VALUES(?,?)",[("phase","LIVE"),("live_rowid","3")])
        for rid,minute,path in [(1,-5,"/"),(2,5,"/"),(3,20,"/games")]:
            t=START+timedelta(minutes=minute)
            rec=dict(source_rowid=rid,event_id=str(rid),timestamp=t.isoformat(),ip="192.0.2.10",line_offset=rid,
                     raw_path=path,normalized_path=path,referrer_host="",ua=UA,host="aoe2war.com")
            self.assertIsNotNone(canonical.normalize_row(rec,rules=[]))
            self.raw.execute("INSERT INTO traffic_entries(rowid,event_id,timestamp,ip,line_offset,raw_path,normalized_path,referrer_host,ua,host,ingested_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (*rec.values(),(t+timedelta(seconds=1)).isoformat()))
            self.ledger.execute("INSERT INTO future_events VALUES(?,?,?)",(rid,json.dumps(rec),t.isoformat()))
        for db in (self.raw,self.ledger):
            db.commit()
        hosts=["aoe2war.com"]
        policy=source.sha({"hosts":hosts,"hosts_sha256":hashlib.sha256(json.dumps(hosts).encode()).hexdigest(),
                           "rules_sha256":hashlib.sha256(json.dumps([],sort_keys=True,default=str).encode()).hexdigest()})
        self.page={"day":DAY.isoformat(),"source_epoch_sha256":"b"*64,"host_rules_sha256":policy,
                   "snapshot_rowid":3,"forward_prefix_rowid":3,"last_key":[(START+timedelta(minutes=20)).isoformat(),3,3],
                   "pages":1,"total_rows":2,"missing_receipts":0,"invalid_clocks":0,
                   "chain_sha256":"c"*64,"source_prefix_exhausted":True}
        self.deps=dict(schema=source.DEPENDENCY_SCHEMA,day=DAY.isoformat(),
                       as_of_utc=(START+timedelta(days=1)).isoformat(),source_commit_sha=COMMIT,
                       runtime_manifest_sha256="a"*64,geo_dataset_sha256="b"*64,identity_snapshot_sha256="c"*64,
                       host_rules_sha256=policy,hosts=hosts,rules=[],
                       geo_by_ip={"192.0.2.10":{"country":"Canada","country_code":"CA","area":"Fixture","city":"Fixture","geo_resolved":True}},
                       known_by_ip={"192.0.2.10":None})
        self.delivery=dict(schema=source.DELIVERY_SCHEMA,day=DAY.isoformat(),source_prefix_rowid=3,
            upstream_closed_through_utc=(START+timedelta(days=1,minutes=31)).isoformat(),
            writer_closed_through_utc=(START+timedelta(days=1,minutes=31)).isoformat(),
            upstream_eof_evidence_sha256="d"*64,writer_receipt_evidence_sha256="e"*64,
            late_arrival_evidence_sha256="f"*64,carry_delivery_evidence_sha256="1"*64)

    def prepare(self,**changes):
        for db in (self.raw,self.ledger):
            if not db.in_transaction:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
        args=dict(day=DAY,page=self.page,dependencies=self.deps,dependency_sha256=source.sha(self.deps),
            delivery=self.delivery,delivery_sha256=source.sha(self.delivery),reviewed_source_commit=COMMIT,now=NOW)
        args.update(changes)
        return source.prepare(self.raw,self.ledger,**args)

    def test_actual_raw_and_ledger_parity_and_reproducible_model(self):
        a=self.prepare()
        self.assertEqual(a,self.prepare())
        self.assertFalse(a["publication_authorized"])
        self.assertEqual(a["observation"]["accepted_day_events"],2)
        self.assertEqual(a["observation"]["carry_in_slices"],1)
        self.assertEqual(a["observation"]["metrics"][0],1)
        cert=source.certificate_body(a,self.page,self.delivery,now=NOW)
        self.assertEqual(cert["schema"],witness.V3_SCHEMA)
        self.assertEqual(cert["classifier_source_commit_sha"],COMMIT)
        self.assertEqual(witness.check_day_witness(cert,self.page,now=NOW,observation=a["observation"])["candidate_values"],a["observation"]["metrics"])

    def test_missing_snapshot_or_wrong_clock_or_policy_fail(self):
        bad=dict(self.deps,as_of_utc=NOW.isoformat())
        with self.assertRaisesRegex(ValueError,"AS_OF"):
            self.prepare(dependencies=bad,dependency_sha256=source.sha(bad))
        bad=dict(self.deps,geo_by_ip={})
        with self.assertRaisesRegex(ValueError,"LOOKUP_COVERAGE"):
            self.prepare(dependencies=bad,dependency_sha256=source.sha(bad))
        with self.assertRaisesRegex(ValueError,"AS_OF"):
            self.prepare(dependency_sha256="0"*64)
        bad=dict(self.deps,rules=[{"id":1}])
        with self.assertRaisesRegex(ValueError,"HOST_RULE_PREIMAGE"):
            self.prepare(dependencies=bad,dependency_sha256=source.sha(bad))

    def test_backdated_insert_and_raw_ledger_drift_fail(self):
        self.raw.execute("UPDATE traffic_entries SET normalized_path='/other' WHERE rowid=3")
        self.raw.commit()
        with self.assertRaisesRegex(ValueError,"IDENTITY_DRIFT"):
            self.prepare()
        for db in (self.raw,self.ledger):
            db.rollback()
        self.raw.execute("PRAGMA query_only=OFF")
        self.raw.execute("INSERT INTO traffic_entries SELECT event_id||'late',timestamp,ip,line_offset+9,raw_path,normalized_path,referrer_host,ua,host,ingested_at_utc FROM traffic_entries WHERE rowid=3")
        self.raw.commit()
        with self.assertRaisesRegex(ValueError,"LATE_ARRIVAL"):
            self.prepare()


class SignedV3AtomicIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TwoWitnessDayTests.setUpClass()
    @classmethod
    def tearDownClass(cls):
        TwoWitnessDayTests.tearDownClass()

    def setUp(self):
        self.fixture=AtomicDailyAppendFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        db=self.fixture.conn
        db.executescript(RAW_DDL)
        # The actual atomic append core now checks the raw prefix under its write lock.
        db.execute("INSERT INTO traffic_entries(rowid,timestamp) VALUES(?,?)",(3,"2026-11-24T00:01:00+00:00"))
        db.commit()

    def candidate(self, day=DAY):
        fake=TwoWitnessDayTests()
        p=fake.page(day.isoformat())
        p.update(snapshot_rowid=3,forward_prefix_rowid=3,last_key=[day.isoformat()+"T23:59:59+00:00",2,2])
        c=fake.certificate(p,day.isoformat())
        c={k:v for k,v in c.items() if k in witness.V3_FIELDS}
        end=datetime.combine(day+timedelta(days=1),datetime.min.time(),tzinfo=timezone.utc)
        o=dict(schema="traffic.public-audience.v3.daily-observation.review.v1",day=day.isoformat(),
               observation_end_exclusive_utc=end.isoformat(),delivery_floor_utc=(end+timedelta(minutes=31)).isoformat(),
               source_prefix_rowid=3,source_evidence_sha256="1"*64,classifier_dependencies_sha256="2"*64,
               normalized_input_sha256="3"*64,daily_model_sha256="4"*64,carry_sha256="5"*64,
               slice_count=200,carry_in_slices=5,accepted_day_events=250,metrics=[150,40,19],
               upstream_closed_through_utc=c["upstream_log_closed_through_utc"],writer_closed_through_utc=c["writer_receipts_closed_through_utc"])
        c.update(schema=witness.V3_SCHEMA,historical_release_sha256=self.fixture.history_sha,
                 classifier_source_commit_sha=COMMIT,observation_sha256=source.sha(o),
                 **{k:o[k] for k in ("source_evidence_sha256","classifier_dependencies_sha256","normalized_input_sha256","daily_model_sha256","carry_sha256")})
        return fake.envelope(c),p,o

    def call(self, env,p,o, now=NOW, **changes):
        f=self.fixture
        rows=append.public_rows(f.conn)
        expected=append.matrix_sha({r["day"]:[r["total"],r["potential"],r["confirmed"]] for r in rows})
        permit=f.permit(env["certificate"],permitted_public_preimage_sha256=expected)
        args=dict(certificate_envelope=env,page_state=p,observation=o,now=now,
                  upstream_key=f.fake_keys[0][1],classifier_key=f.fake_keys[1][1],
                  upstream_key_sha256=hashlib.sha256(f.fake_keys[0][1]).hexdigest(),
                  classifier_key_sha256=hashlib.sha256(f.fake_keys[1][1]).hexdigest(),
                  independently_admitted_operator_permit=permit,durable_preimage=f.durable,
                  expected_public_sha256=expected,lock_proven=True)
        args.update(changes)
        with patch.object(append,"RELEASE_SHA",f.history_sha),patch.object(witness,"RELEASE_SHA",f.history_sha):
            return append.append_verified_day(f.conn,**args)

    def test_real_dual_signature_atomic_two_days_and_scope(self):
        env,p,o=self.candidate()
        first=self.call(env,p,o)
        self.assertEqual(first["public_write_count"],1)
        self.assertEqual(self.call(env,p,o)["public_write_count"],0)
        env2,p2,o2=self.candidate(DAY+timedelta(days=1))
        self.assertEqual(self.call(env2,p2,o2,now=NOW+timedelta(days=1))["public_write_count"],1)
        db=self.fixture.conn
        self.assertEqual(db.execute("SELECT COUNT(*) FROM traffic_public_daily_audience_rollups").fetchone()[0],133)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM traffic_public_audience_day_certificates_v2 WHERE signed_finality_schema=?",(witness.V3_SCHEMA,)).fetchone()[0],2)
        with patch.object(append,"RELEASE_SHA",self.fixture.history_sha):
            self.assertEqual(append.historical_preimage(db),self.fixture.history)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM traffic_public_daily_audience_rollups WHERE bucket_day BETWEEN '2026-10-20' AND '2026-11-22'").fetchone()[0],0)

    def test_v2_signature_cannot_be_reused_and_companion_required(self):
        env,p,o=self.candidate()
        with self.assertRaisesRegex(ValueError,"OBSERVATION_PREIMAGE"):
            self.call(env,p,None)
        with self.assertRaisesRegex(ValueError,"OBSERVATION_PREIMAGE"):
            self.call(env,p,dict(o,slice_count=201))
        fake=TwoWitnessDayTests()
        old=fake.certificate(p,DAY.isoformat())
        env["upstream_signature"]=fake.sign(old,0)
        with self.assertRaisesRegex(ValueError,"SIGNATURE_REFUSED"):
            self.call(env,p,o)
        self.assertEqual(self.fixture.conn.execute("SELECT COUNT(*) FROM traffic_public_audience_day_certificates_v2").fetchone()[0],0)

    def test_transaction_late_insert_denied_without_history_mutation(self):
        env,p,o=self.candidate()
        self.fixture.conn.execute("INSERT INTO traffic_entries(rowid,timestamp) VALUES(4,'2026-11-22T23:55:00+00:00')")
        self.fixture.conn.commit()
        with self.assertRaisesRegex(ValueError,"LATE_ARRIVAL_IN_WRITE"):
            self.call(env,p,o)
        self.assertEqual(self.fixture.conn.execute("SELECT COUNT(*) FROM traffic_public_daily_audience_rollups").fetchone()[0],131)
        self.assertFalse(self.fixture.conn.in_transaction)


if __name__=="__main__":
    unittest.main()
