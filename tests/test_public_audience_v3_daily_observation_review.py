"""Synthetic private qualification: actual original session and burst functions.

No production DB, keys, network, signer or publisher is used.
"""
from datetime import date, datetime, timedelta, timezone
import sqlite3
import unittest
from unittest.mock import patch

from app.services.traffic import sessions
from scripts import rebuild_public_audience_archive as canonical
from scripts import public_audience_v3_daily_observation_review as review

D = date(2026, 11, 23)
START = datetime(2026, 11, 23, tzinfo=timezone.utc)
BROWSER = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
           "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")


def event(rid, minute, *, path="/", category="human", ua=BROWSER, ip="192.0.2.1",
          seconds=0, referrer=""):
    t = START + timedelta(minutes=minute, seconds=seconds)
    return dict(source_rowid=rid, event_id=str(rid), timestamp=t, timestamp_iso=t.isoformat(),
                line_offset=rid, host="aoe2war.com", ip=ip, ua=ua,
                raw_path=path, normalized_path=path, referrer_host=referrer,
                category=category, route_kind=sessions.detect_route_kind(path))


def observe(rows, day=D, prefix=100000, **changes):
    end = datetime.combine(day + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
    args = dict(source_prefix=prefix, source_evidence_sha256="a"*64,
                classifier_dependencies_sha256="b"*64,
                upstream_closed_through=end+review.DELIVERY_MARGIN,
                writer_closed_through=end+review.DELIVERY_MARGIN)
    args.update(changes)
    return review.observe(day, rows, **args)


class IsolatedObservationTests(unittest.TestCase):
    def setUp(self):
        # Freeze external mutable inputs. Classification and burst algorithms remain real.
        for p in [
            patch.object(sessions, "get_geo_details", return_value={
                "country":"Canada", "country_code":"CA", "city":"Fixture",
                "area":"Fixture", "geo_resolved":True}),
            patch.object(canonical, "apply_known_visitor_confirmation", return_value=None),
        ]:
            p.start()
            self.addCleanup(p.stop)

    def test_indefinite_api_then_next_day_page_does_not_rewrite(self):
        day1 = [event(i+1, m, path="/api/poll") for i,m in enumerate(range(0,1440,10))]
        day2 = [event(1000+i, m, path="/") for i,m in enumerate(range(1440,2880,10))]
        a = observe(day1)
        b = observe(day1[-3:]+day2, D+timedelta(days=1))
        self.assertEqual(a["observation"]["metrics"], [0,0,0])
        self.assertEqual(b["observation"]["metrics"][0], 1)
        self.assertEqual(b["observation"]["carry_in_slices"], 1)
        self.assertEqual(a, observe(list(reversed(day1))))
        self.assertFalse(b["publication_authorized"])

    def test_future_suspicious_activity_cannot_mutate_prior_day(self):
        day1 = [event(i+1,m,path=p) for i,(m,p) in enumerate(
            [(1400,"/"),(1401,"/games"),(1402,"/leaderboard"),(1420,"/games"),(1439,"/")])]
        a = observe(day1)
        day2 = [event(100,1440,category="suspicious"),event(101,1441,category="suspicious")]
        b = observe(day1[-2:]+day2,D+timedelta(days=1))
        self.assertEqual(b["observation"]["metrics"], [1,0,0])
        self.assertEqual(a,observe(day1))
        self.assertNotEqual(a["observation"]["daily_model_sha256"],b["observation"]["daily_model_sha256"])

    def test_midnight_gap_equal_and_greater(self):
        prev = event(1,-10)
        equal = event(2,20)
        greater = event(3,50,seconds=1)
        a = observe([greater,prev,equal])
        self.assertEqual(a["observation"]["slice_count"],2)
        self.assertEqual(a["observation"]["carry_in_slices"],1)
        self.assertEqual(a["observation"]["metrics"][0],2)

    def test_midnight_half_open_and_no_lookahead(self):
        a = observe([event(1,1439,seconds=59)])
        self.assertEqual(a["observation"]["accepted_day_events"],1)
        with self.assertRaisesRegex(ValueError,"OUTSIDE"):
            observe([event(2,1440)])
        b = observe([event(1,1439,seconds=59),event(2,1440)],D+timedelta(days=1))
        self.assertEqual(b["observation"]["accepted_day_events"],1)
        self.assertEqual(b["observation"]["carry_in_slices"],1)

    def test_daily_model_threshold_transitions_both_directions(self):
        paths = ["/","/app","/api/x","/_next/x"]
        first = [event(i+1,i,path=paths[i%4],ua=BROWSER+str(i%4)) for i in range(24)]
        # Original predicate enters spam at the request / distinct-UA / path threshold.
        self.assertFalse(next(iter(sessions.build_ip_behavior_map(first[:23]).values()))["route_bundle_spam"])
        self.assertTrue(next(iter(sessions.build_ip_behavior_map(first).values()))["route_bundle_spam"])
        self.assertFalse(next(iter(sessions.build_ip_behavior_map(first+[event(99,25,path="/other")]).values()))["route_bundle_spam"])
        a = observe(first)
        day2 = [event(100+i,1440+i,path="/other",ua=BROWSER+str(i%4)) for i in range(24)]
        b = observe(day2,D+timedelta(days=1))
        self.assertNotEqual(a["observation"]["daily_model_sha256"],b["observation"]["daily_model_sha256"])
        self.assertEqual(a,observe(first))

    def test_distinct_paths_upper_threshold_and_direct_ratio(self):
        paths=["/","/app","/api/a","/api/b","/api/c","/api/d","/_next/a","/_next/b"]
        first=[event(i+1,i,path=paths[i%8],ua=BROWSER+str(i%4)) for i in range(24)]
        model=lambda rows: next(iter(sessions.build_ip_behavior_map(rows).values()))["route_bundle_spam"]
        self.assertTrue(model(first))
        self.assertFalse(model(first+[event(100,25,path="/api/e")]))
        self.assertFalse(model(first+[event(100+i,25+i,path="/api/a",referrer="example.org") for i in range(3)]))

    def test_no_seal_before_delivery_clocks(self):
        with self.assertRaisesRegex(ValueError,"DELIVERY"):
            observe([],writer_closed_through=START+timedelta(days=1,minutes=30))
        with self.assertRaisesRegex(ValueError,"DELIVERY"):
            observe([],upstream_closed_through=START+timedelta(days=1,minutes=30))

    def test_duplicate_and_prefix_and_future_rows_fail_closed(self):
        row=event(1,0)
        with self.assertRaisesRegex(ValueError,"DUPLICATE"):
            observe([row,row])
        with self.assertRaisesRegex(ValueError,"PREFIX"):
            observe([event(2,0)],prefix=1)
        with self.assertRaisesRegex(ValueError,"OUTSIDE"):
            observe([event(1,-31)])

    def test_late_incident_vs_future_and_observed_zero(self):
        self.assertEqual(review.late_disposition(sealed_day=D,sealed_prefix=10,event=event(11,1439)),
                         "LATE_SEALED_INPUT_INCIDENT")
        self.assertEqual(review.late_disposition(sealed_day=D,sealed_prefix=10,event=event(12,1440)),
                         "FUTURE_DAY_INPUT")
        zero=observe([])
        self.assertEqual(zero["observation"]["metrics"],[0,0,0])
        self.assertFalse(zero["live_finality_certified"])

    def test_two_day_atomic_fixture_not_production_publisher(self):
        db=sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("CREATE TABLE series(day TEXT PRIMARY KEY, total INT, potential INT, confirmed INT);"
                         "CREATE TABLE certificates(day TEXT PRIMARY KEY, digest TEXT NOT NULL);")
        historic=[((date(2026,6,11)+timedelta(days=i)).isoformat(),100+i,10,1) for i in range(131)]
        db.executemany("INSERT INTO series VALUES(?,?,?,?)",historic)
        db.commit()
        def append_fixture(day, result, fail=False):
            self.assertFalse(result["publication_authorized"])
            with db:
                db.execute("INSERT INTO series VALUES(?,?,?,?)",(day,*result["observation"]["metrics"]))
                if fail:
                    raise RuntimeError("fixture crash")
                db.execute("INSERT INTO certificates VALUES(?,?)",(day,result["observation_sha256"]))
        a=observe([event(1,1439)])
        b=observe([event(1,1439),event(2,1440)],D+timedelta(days=1))
        append_fixture(D.isoformat(),a)
        with self.assertRaises(RuntimeError):
            append_fixture("2026-11-24",b,fail=True)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM series").fetchone()[0],132)
        append_fixture("2026-11-24",b)
        with self.assertRaises(sqlite3.IntegrityError):
            append_fixture(D.isoformat(),a)
        self.assertEqual(db.execute("SELECT * FROM series WHERE day<='2026-10-19' ORDER BY day").fetchall(),historic)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM series WHERE day BETWEEN '2026-10-20' AND '2026-11-22'").fetchone()[0],0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0],2)


if __name__ == "__main__":
    unittest.main()
