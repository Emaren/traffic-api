from __future__ import annotations

import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from scripts import public_audience_v2_forward_boundary_audit as boundary
from scripts import public_audience_v2_future_session_preview as preview

B = datetime(2026, 10, 20, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def event(when, ip="actor1", ua="Mozilla", rowid=1):
    return {
        "host": "aoe2war.com", "ip": ip, "ua": ua,
        "timestamp": when, "timestamp_iso": when.isoformat(),
        "source_rowid": rowid, "normalized_path": "/",
        "category": "human", "referrer_host": "",
    }


def builder(items, *, now, ip_behavior):
    return {
        "session_id": str(items[0]["source_rowid"]),
        "first_seen_at": items[0]["timestamp_iso"],
        "route_kind": "page",
        "known_automation": False,
        "suspicious_score": 0,
        "classification_state": "likely_human",
        "human_confirmed": False,
    }


def finalizer(sessions, daily):
    for session in sessions:
        day = session["first_seen_at"][:10]
        triple = daily.setdefault(day, [0, 0, 0])
        triple[0] += 1
        triple[1] += 1
    return len(sessions)


class BoundaryQuarantineTests(unittest.TestCase):
    def setUp(self):
        for attr, replacement in (
            ("build_single_session", builder),
            ("finalize_bucket", finalizer),
        ):
            patcher = patch.object(preview.canonical, attr,
                                   side_effect=replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_preview(self, rows, keys=None):
        return preview.replay(
            rows, behavior=lambda *_: {},
            reference_now=NOW, deadline=time.monotonic()+20,
            inherited_boundary_keys=keys,
        )

    def test_boundary_keys_remain_private(self):
        report, keys = boundary.analyze_boundary(
            [event(B-timedelta(minutes=2))],
            [event(B+timedelta(seconds=3))],
            boundary=B, max_rows=10, include_private_keys=True,
        )
        self.assertEqual(keys, {("aoe2war.com", "actor1", "mozilla")})
        self.assertEqual(report["canonical_session_continuations"], 1)
        self.assertNotIn("actor1", json.dumps(report))
        self.assertFalse(report["publication_authorized"])

    def test_exact_continuation_is_quarantined_only_once(self):
        rows = [
            event(B+timedelta(seconds=5), rowid=1),
            event(B+timedelta(minutes=25), rowid=2),
            event(B+timedelta(minutes=56), rowid=3),
            event(B+timedelta(minutes=57), ip="unrelated", rowid=4),
        ]
        baseline, bstats = self.run_preview(rows)
        adjusted, astats = self.run_preview(
            rows, {("aoe2war.com", "actor1", "mozilla")},
        )
        self.assertEqual(baseline, {"2026-10-20": [3, 3, 0]})
        self.assertEqual(adjusted, {"2026-10-20": [2, 2, 0]})
        self.assertEqual(astats["inherited_continuations_quarantined"], 1)
        self.assertEqual(astats["inherited_continuation_events_quarantined"], 2)
        self.assertEqual(astats["accepted_future_events"], 4)
        self.assertEqual(astats["finalized_sessions"], 2)
        self.assertEqual(bstats["finalized_sessions"], 3)

    def test_new_future_session_after_gap_is_not_ignored(self):
        rows = [
            event(B+timedelta(seconds=5), rowid=1),
            event(B+timedelta(minutes=36), rowid=2),
            event(B+timedelta(minutes=67), rowid=3),
        ]
        values, stats = self.run_preview(
            rows, {("aoe2war.com", "actor1", "mozilla")},
        )
        self.assertEqual(values, {"2026-10-20": [2, 2, 0]})
        self.assertEqual(stats["inherited_continuations_quarantined"], 1)

    def test_unrelated_user_agent_not_quarantined(self):
        rows = [
            event(B+timedelta(seconds=5), ua="Mozilla", rowid=1),
            event(B+timedelta(seconds=6), ua="Other", rowid=2),
        ]
        values, stats = self.run_preview(
            rows, {("aoe2war.com", "actor1", "mozilla")},
        )
        self.assertEqual(values, {"2026-10-20": [1, 1, 0]})
        self.assertEqual(stats["inherited_continuations_quarantined"], 1)

    def test_original_unmodified_without_boundary_keys(self):
        values, stats = self.run_preview(
            [event(B+timedelta(seconds=5), rowid=1)],
        )
        self.assertEqual(values, {"2026-10-20": [1, 1, 0]})
        self.assertEqual(stats["inherited_continuations_quarantined"], 0)


if __name__ == "__main__":
    unittest.main()
