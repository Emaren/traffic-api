"""Forward private canonical pass-two tests: source and semantic fail-closed.

No production database, Keychain, NGINX logs, or publisher is accessed.
The existing canonical implementation remains byte-for-byte unchanged.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_forward_canonical_candidate as candidate
from scripts import public_audience_v2_checkpoint as checkpoint
from scripts import public_audience_v2_forward_ledger as forward
from scripts import rebuild_public_audience_archive as canonical


def event(rowid: int, when: str, *, line: int = 1, ip: str = "192.0.2.10"):
    return {
        "source_rowid": rowid, "event_id": "id-"+str(rowid),
        "timestamp": when, "ip": ip, "line_offset": line,
        "raw_path": "/", "normalized_path": "/",
        "referrer_host": "", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "host": "aoe2war.com",
    }


class ForwardCanonicalReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(forward.PRIVATE_SCHEMA)
        self.addCleanup(self.db.close)

    def add(self, value):
        self.db.execute(
            "INSERT INTO future_events(source_rowid,event_json,timestamp) VALUES(?,?,?)",
            (value["source_rowid"],
             json.dumps(value,sort_keys=True,separators=(",",":")),
             value["timestamp"]),
        )
        self.db.commit()

    def rows(self, *, cap=100):
        return list(candidate.raw_forward_rows(
            self.db, start="2026-11-22T00:00:00+00:00",
            end="2026-11-24T00:00:00+00:00",
            source_prefix_rowid=forward.FROZEN_WATERMARK+1000,
            max_events=cap, deadline=time.monotonic()+5))

    def test_raw_private_ledger_is_exact_timestamp_line_offset_order(self):
        self.add(event(forward.FROZEN_WATERMARK+1,"2026-11-23T00:00:00+00:00",line=8))
        self.add(event(forward.FROZEN_WATERMARK+2,"2026-11-23T00:00:00+00:00",line=2))
        self.add(event(forward.FROZEN_WATERMARK+3,"2026-11-22T23:59:59+00:00",line=4))
        self.assertEqual([x["line_offset"] for x in self.rows()],[4,2,8])
        self.assertTrue(set(self.rows()[0])==set(checkpoint.RAW_FIELDS))

    def test_original_source_row_identity_mismatch_denied(self):
        a=event(forward.FROZEN_WATERMARK+1,"2026-11-23T01:00:00+00:00")
        self.add(a)
        bad={**a,"source_rowid":a["source_rowid"]+7}
        self.db.execute("UPDATE future_events SET event_json=? WHERE source_rowid=?",
                        (json.dumps(bad),a["source_rowid"]))
        with self.assertRaisesRegex(RuntimeError,"SOURCE_ROW_ID"):
            self.rows()

    def test_oversized_equal_timestamp_group_fails_closed(self):
        first="2026-11-23T01:00:00+00:00"
        for i in range(3):
            self.add(event(forward.FROZEN_WATERMARK+i+1,first))
        with patch.object(candidate,"MAX_EQUAL_TIME_GROUP",2):
            with self.assertRaisesRegex(RuntimeError,"TIMESTAMP_TIE_LIMIT"):
                self.rows()

    def test_bounded_rows_and_seconds_fail_closed(self):
        for i in range(3):
            self.add(event(forward.FROZEN_WATERMARK+i+1,
                           "2026-11-23T01:00:0"+str(i)+"+00:00"))
        with self.assertRaisesRegex(RuntimeError,"EVENT_COUNT_LIMIT"):
            self.rows(cap=2)
        with self.assertRaisesRegex(RuntimeError,"BUDGET_SECONDS"):
            list(candidate.raw_forward_rows(
                self.db,start="2026-11-22T00:00:00+00:00",
                end="2026-11-24T00:00:00+00:00",
                source_prefix_rowid=forward.FROZEN_WATERMARK+1000,
                max_events=5,deadline=time.monotonic()-1))

    def test_real_canonical_engine_cross_midnight_carry(self):
        first=event(forward.FROZEN_WATERMARK+1,
                    "2026-11-22T23:59:40+00:00")
        crossing=event(forward.FROZEN_WATERMARK+2,
                       "2026-11-23T00:01:10+00:00")
        separate=event(forward.FROZEN_WATERMARK+3,
                       "2026-11-23T01:00:00+00:00")
        for row in (first,crossing,separate):self.add(row)
        now=datetime(2026,11,24,0,31,tzinfo=timezone.utc)
        from_utc=datetime(2026,11,22,tzinfo=timezone.utc)
        until=datetime(2026,11,24,tzinfo=timezone.utc)
        behavior={("aoe2war.com","192.0.2.10"): {
            "request_count":3, "unique_uas":1,"unique_paths":1,
            "route_bundle_paths":["/"],"route_bundle_spam":False}}
        # Explicitly use the same ambient policy in both paths; neither
        # test is an admission or historical-source authenticity proof.
        with patch.object(canonical,"safe_list_visibility_rules",return_value=[]):
            private_daily,private_metrics=candidate.canonical_private_replay(
                raw_rows=iter(self.rows()),behavior=behavior,
                from_utc=from_utc,until_utc=until,
                source_prefix_rowid=forward.FROZEN_WATERMARK+1000,
                observed_at_utc=now)
            with patch.object(canonical,"source_rows",return_value=iter(self.rows())):
                historic_daily,historic_metrics=canonical.stream_sessions(
                    start=from_utc,end=until,behavior=behavior,
                    snapshot_max_rowid=forward.FROZEN_WATERMARK+1000)
        self.assertEqual(private_daily,historic_daily)
        self.assertEqual(private_metrics,historic_metrics)
        self.assertEqual(private_metrics["raw_rows"],3)
        self.assertEqual(sum(x[0] for x in private_daily.values()),2)
        self.assertEqual(private_daily["2026-11-22"][0],1)
        self.assertEqual(private_daily["2026-11-23"][0],1)

    def test_two_context_windows_agree_across_midnight(self):
        for row in (
            event(forward.FROZEN_WATERMARK+1,
                  "2026-11-22T23:59:40+00:00"),
            event(forward.FROZEN_WATERMARK+2,
                  "2026-11-23T00:01:10+00:00"),
            event(forward.FROZEN_WATERMARK+3,
                  "2026-11-23T01:00:00+00:00"),
        ):
            self.add(row)
        behavior={("aoe2war.com","192.0.2.10"): {
            "request_count":3,"unique_uas":1,"unique_paths":1,
            "route_bundle_paths":["/"],"route_bundle_spam":False}}
        with patch.object(canonical,"safe_list_visibility_rules",return_value=[]):
            values,metrics=candidate.two_window_private_candidate(
                self.db,behavior,requested=datetime(2026,11,23).date(),
                source_prefix_rowid=forward.FROZEN_WATERMARK+1000,
                max_events=100,deadline=time.monotonic()+10)
        self.assertEqual(values[0],1)
        self.assertGreaterEqual(values[0],values[1])
        self.assertEqual(metrics["raw_rows"],3)

    def test_two_context_disagreement_denies_source_promotion(self):
        def fake(*, from_utc, **kwargs):
            return ({"2026-11-23":
                     [3,2,1] if from_utc.date().isoformat()=="2026-11-21"
                     else [4,2,1]}, {"raw_rows":1})
        with patch.object(candidate,"canonical_private_replay",side_effect=fake):
            with self.assertRaisesRegex(RuntimeError,
                                        "TWO_WINDOW_CROSS_DAY_METRIC_DRIFT"):
                candidate.two_window_private_candidate(
                    self.db,{},requested=datetime(2026,11,23).date(),
                    source_prefix_rowid=forward.FROZEN_WATERMARK+1000,
                    max_events=100,deadline=time.monotonic()+10)

    def test_epoch_boundary_without_two_prior_days_denied(self):
        with self.assertRaisesRegex(RuntimeError,
                                    "HISTORICAL_BOUNDARY_CARRY_UNPROVEN"):
            candidate.two_window_private_candidate(
                self.db,{},requested=datetime(2026,10,21).date(),
                source_prefix_rowid=forward.FROZEN_WATERMARK+1000,
                max_events=100,deadline=time.monotonic()+10)

    def test_immutable_historical_canonical_byte_pin(self):
        import hashlib
        self.assertEqual(
            hashlib.sha256(Path(canonical.__file__).read_bytes()).hexdigest(),
            "1b389839428a2453fa870dfb2f2661087b386b5c5f22782b45de6e6cfe12c321")

    def test_source_qualified_visibility_rules_override_ambient_db(self):
        raw=event(forward.FROZEN_WATERMARK+1,"2026-11-23T10:00:00+00:00")
        old_source=canonical.source_rows
        old_rules=canonical.safe_list_visibility_rules
        def fake_stream(*,start,end,behavior,snapshot_max_rowid):
            self.assertEqual(
                canonical.safe_list_visibility_rules(active_only=True),
                [{"id":17,"active":True}])
            seen=list(canonical.source_rows(
                start=start,end=end,snapshot_max_rowid=snapshot_max_rowid))
            self.assertEqual([x["source_rowid"] for x in seen],
                             [raw["source_rowid"]])
            return {"2026-11-23":[1,1,0]},{"raw_rows":1}
        with patch.object(canonical,"stream_sessions",side_effect=fake_stream):
            day, metrics=candidate.canonical_private_replay(
                raw_rows=iter([raw]),behavior={},
                from_utc=datetime(2026,11,23,tzinfo=timezone.utc),
                until_utc=datetime(2026,11,24,tzinfo=timezone.utc),
                source_prefix_rowid=forward.FROZEN_WATERMARK+2,
                observed_at_utc=datetime.now(timezone.utc),
                source_rules=[{"id":17,"active":True}])
        self.assertEqual(day["2026-11-23"],[1,1,0])
        self.assertEqual(metrics["raw_rows"],1)
        self.assertIs(canonical.source_rows,old_source)
        self.assertIs(canonical.safe_list_visibility_rules,old_rules)

    def test_private_source_function_restored_even_on_error(self):
        original=canonical.source_rows
        def failed_rows():
            raise RuntimeError("EXPECTED_SOURCE_FAILURE")
            yield {}
        with self.assertRaisesRegex(RuntimeError,"EXPECTED_SOURCE_FAILURE"):
            candidate.canonical_private_replay(
                raw_rows=failed_rows(), behavior={},
                from_utc=datetime(2026,11,23,tzinfo=timezone.utc),
                until_utc=datetime(2026,11,24,tzinfo=timezone.utc),
                source_prefix_rowid=forward.FROZEN_WATERMARK+1,
                observed_at_utc=datetime.now(timezone.utc))
        self.assertIs(canonical.source_rows, original)

    def test_private_file_mode_required(self):
        with tempfile.TemporaryDirectory() as directory:
            f=Path(directory)/"evidence.sqlite3"
            f.write_bytes(b"do-not-trust")
            f.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError,"PRIVATE_FILE_INTEGRITY"):
                candidate.regular_private(f)
            f.chmod(0o600)
            candidate.regular_private(f)

    def test_forward_adapter_never_claims_public_release(self):
        text=Path(candidate.__file__).read_text()
        self.assertIn('"publication_authorized": False',text)
        self.assertIn('"historical_epoch_carry_certified": False',text)
        self.assertIn('"nginx_delivery_eof_certified": False',text)
        self.assertIn('"full_day_source_paging_certified": False',text)
        self.assertIn('"daily_classification_ready": False',text)
        self.assertIn("return 2",text)


if __name__ == "__main__":
    unittest.main()
