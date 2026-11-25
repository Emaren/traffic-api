"""Isolated prospective dependency materializer qualification."""
import unittest
from datetime import date,datetime,timedelta,timezone
from unittest.mock import patch
from scripts import public_audience_v3_dependency_materializer as m
from scripts import public_audience_v3_source_prepare as s
from tests import test_public_audience_v3_integration as fixture

DAY=date(2026,11,25)
START=datetime(2026,11,25,tzinfo=timezone.utc)
END=START+timedelta(days=1)
NOW=END+timedelta(minutes=40)
COMMIT="a"*40

class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.registry={"known_identities":[],"visibility_rules":[]}
        self.receipt=dict(schema=m.SCHEMA,day=DAY.isoformat(),
          effective_from_utc=(START-timedelta(minutes=31)).isoformat(),
          verified_through_utc=END.isoformat(),recorded_at_utc=NOW.isoformat(),
          baseline_receipt_sha256="a"*64,cutoff_receipt_sha256="b"*64,
          registry_sha256=s.sha(self.registry),geo_sha256="c"*64,
          runtime_manifest_sha256="d"*64,source_commit_sha=COMMIT,
          source_authority_evidence_sha256="e"*64,method="source-owned-effective-freeze")

    def check(self,r):
        return m.validate_continuity(DAY,r,expected_sha256=s.sha(r),now=NOW,source_commit=COMMIT)

    def test_boundary_and_clock(self):
        self.assertEqual(self.check(self.receipt),(START,END))
        for k,v in [("effective_from_utc",(START-timedelta(minutes=29)).isoformat()),
                    ("verified_through_utc",(END-timedelta(seconds=1)).isoformat()),
                    ("recorded_at_utc",(NOW+timedelta(seconds=1)).isoformat())]:
            with self.assertRaisesRegex(ValueError,"BOUNDARY"):
                self.check(dict(self.receipt,**{k:v}))

    def test_equal_endpoints_are_not_continuity(self):
        with self.assertRaisesRegex(ValueError,"METHOD"):
            self.check(dict(self.receipt,method="matching-endpoint-hashes"))
        with self.assertRaisesRegex(ValueError,"PREIMAGE"):
            m.validate_continuity(DAY,self.receipt,expected_sha256="0"*64,now=NOW,source_commit=COMMIT)

    def test_private_materialization_exact_adapter_schema(self):
        f=fixture.SourceAdapterTests();f.setUp();self.addCleanup(f.doCleanups)
        # Shift invented complete-day raw fixture to the prospective epoch.
        for r in f.raw.execute("SELECT rowid,timestamp,ingested_at_utc FROM traffic_entries").fetchall():
            clocks=[(datetime.fromisoformat(v)+timedelta(days=2)).isoformat() for v in r[1:]]
            f.raw.execute("UPDATE traffic_entries SET timestamp=?,ingested_at_utc=? WHERE rowid=?",(*clocks,r[0]))
        f.raw.commit();f.raw.execute("PRAGMA query_only=ON");f.raw.execute("BEGIN")
        page=dict(f.page,day=DAY.isoformat(),last_key=[(START+timedelta(minutes=20)).isoformat(),3,3])
        geo=lambda ip:dict(country="Canada",country_code="CA",area="",city="",geo_resolved=True)
        with patch.object(m.canonical,"project_hosts",return_value=["aoe2war.com"]):
            args=dict(day=DAY,page=page,registry=self.registry,receipt=self.receipt,
                      continuity_sha256=s.sha(self.receipt),source_commit=COMMIT,now=NOW,frozen_geo=geo)
            result=m.materialize(f.raw,**args)
            self.assertEqual(result,m.materialize(f.raw,**args))
            self.assertEqual(set(result),s.DEPENDENCY_FIELDS)
            self.assertEqual(result["as_of_utc"],END.isoformat())
            self.assertEqual(len(result["geo_by_ip"]),1)
            self.assertEqual(list(result["known_by_ip"].values()),[None])
            with self.assertRaisesRegex(ValueError,"REGISTRY_DIGEST"):
                m.materialize(f.raw,**dict(args,registry={"known_identities":[{}],"visibility_rules":[]}))
            with self.assertRaisesRegex(ValueError,"PAGE_ROW_COUNT"):
                m.materialize(f.raw,**dict(args,page=dict(page,total_rows=3)))

    def test_geo_unexpected_error_not_silently_unknown(self):
        class Broken:
            def city(self,ip):raise RuntimeError("runtime failure")
        with self.assertRaises(RuntimeError):
            m.strict_geo(Broken(),"192.0.2.10")

if __name__=="__main__":unittest.main()
