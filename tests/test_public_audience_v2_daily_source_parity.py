from __future__ import annotations

import sqlite3
import time
import unittest

from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_daily_source_parity as parity


def evt(rowid: int, stamp: str = "2026-10-20T01:00:00+00:00",
        ip: str = "192.0.2.1") -> dict:
    return dict(zip(v2.RAW_FIELDS, [
        rowid, f"fixture-{rowid}", stamp, ip, rowid,
        "/", "/", "", "Mozilla/5.0", "aoe2war.com",
    ]))


class SourceVsLedgerParityTests(unittest.TestCase):
    def verify(self, src, ledger, *, limit=10):
        return parity.compare_event_rows(
            src, ledger, limit=limit, deadline=time.monotonic()+10,
        )

    def test_equal_unsorted_entries_match_identically(self):
        entries = [evt(1), evt(2), evt(3)]
        x = self.verify([entries[2], entries[0], entries[1]], entries)
        self.assertEqual(x["rows_compared"], 3)
        self.assertTrue(x["source_ledger_event_identities_equal"])
        self.assertTrue(x["comparison_database_memory_only"])
        self.assertEqual(x["source_event_identity_sha256"],
                         self.verify(entries, reversed(entries))[
                             "source_event_identity_sha256"])

    def test_original_sqlite_row_key_access(self):
        with sqlite3.connect(":memory:") as db:
            db.row_factory = sqlite3.Row
            columns = ",".join(f"'{name}' AS {name}" for name in v2.RAW_FIELDS)
            # Also verify the real sqlite.Row membership path, not only dicts.
            record = evt(7)
            query = "SELECT " + ",".join(
                "? AS " + k for k in v2.RAW_FIELDS
            )
            row = db.execute(
                query, [record[k] for k in v2.RAW_FIELDS],
            ).fetchone()
            self.assertEqual(parity.event_fingerprint(row),
                             parity.event_fingerprint(record))
            self.assertEqual(self.verify([row], [record])["rows_compared"], 1)

    def test_mismatched_ip_is_detected_not_reported(self):
        with self.assertRaisesRegex(RuntimeError, "event identity mismatch"):
            self.verify([evt(1)], [evt(1, ip="198.51.100.90")])

    def test_missing_source_row_detected(self):
        with self.assertRaisesRegex(RuntimeError, "row count mismatch"):
            self.verify([evt(1)], [evt(1), evt(2)])

    def test_duplicate_captured_rowid_detected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.verify([evt(1), evt(2)], [evt(1), evt(1)])

    def test_out_of_bound_day_stops(self):
        with self.assertRaisesRegex(RuntimeError, "max row cap"):
            self.verify([evt(1),evt(2)], [evt(1),evt(2)], limit=1)

    def test_missing_identity_field_stops(self):
        wrong = evt(1)
        wrong.pop("host")
        with self.assertRaisesRegex(RuntimeError, "missing field"):
            parity.event_fingerprint(wrong)

    def test_noninteger_rowid_stops(self):
        wrong = evt(1)
        wrong["source_rowid"] = "1"
        with self.assertRaisesRegex(RuntimeError, "invalid event rowid"):
            parity.event_fingerprint(wrong)

    def test_no_events_yet_is_comparable_not_implicitly_published(self):
        result = self.verify([], [])
        self.assertEqual(result["rows_compared"], 0)
        self.assertTrue(result["source_ledger_event_identities_equal"])


if __name__ == "__main__":
    unittest.main()
