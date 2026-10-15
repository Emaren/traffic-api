"""Live preview regressions for distributed crawlers and visitor safety."""

import unittest
from datetime import datetime, timedelta, timezone

from app.services.traffic.overview import _collapse_nonhuman_preview, _compact_live_session


BASE = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)


def session(index: int, *, state: str = "browser_script", stamp=None, **overrides):
    stamp = stamp or BASE + timedelta(seconds=index)
    item = {
        "session_id": f"s-{index}",
        "visitor_profile_id": f"visitor-{index}",
        "project_slug": "aoe2hdbets",
        "host": "aoe2war.com",
        "country_code": "US",
        "country": "United States",
        "area": "Virginia",
        "city": "Ashburn",
        "ip": f"10.1.0.{index}",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/152.0.0.0",
        "classification_state": state,
        "known_automation": state == "bot",
        "automation_family": "SemrushBot" if state == "bot" else "",
        "route_kind": "page",
        "page_sequence": [f"/players/by-name/warrior-{index}"],
        "entry_page": f"/players/by-name/warrior-{index}",
        "current_page": f"/players/by-name/warrior-{index}",
        "exit_page": f"/players/by-name/warrior-{index}",
        "event_count": 1,
        "started_at": stamp.isoformat(),
        "first_seen_at": stamp.isoformat(),
        "ended_at": stamp.isoformat(),
        "last_seen_at": stamp.isoformat(),
        "human_confidence": 0,
        "human_confirmed": False,
        "live_priority": 0,
    }
    item.update(overrides)
    return item


class NonhumanPreviewTests(unittest.TestCase):
    def test_fleet_is_collapsed_before_eight_row_limit(self):
        items = [session(i) for i in range(200)]
        preview = _collapse_nonhuman_preview(items, limit=8)
        self.assertEqual(len(preview), 1)
        group = preview[0]
        self.assertEqual(group["burst_member_count"], 200)
        self.assertEqual(group["burst_ip_count"], 200)
        self.assertEqual(group["burst_path_count"], 200)
        self.assertEqual(group["event_count"], 200)
        self.assertEqual(group["classification_state"], "browser_script")
        self.assertFalse(group["human_confirmed"])
        self.assertLessEqual(len(group["burst_sample_ips"]), 12)
        compact = _compact_live_session(group)
        self.assertEqual(compact["burst_member_count"], 200)
        self.assertEqual(len(compact["burst_sample_ips"]), 12)
        self.assertEqual(len(compact["burst_paths"]), 12)

    def test_known_bots_group_but_humans_never_group(self):
        items = [session(i, state="bot") for i in range(6)]
        items += [
            session(10, state="human_confirmed"),
            session(11, state="likely_human"),
            session(12, authenticated=True),
            session(13, known_visitor_confirmed=True, known_visitor_kind="known_player"),
        ]
        out = _collapse_nonhuman_preview(items, limit=20)
        groups = [i for i in out if i.get("is_burst_cluster")]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["burst_member_count"], 6)
        self.assertEqual(len(out), 5)

    def test_cross_hour_or_different_country_does_not_merge(self):
        items = [
            session(0), session(1),
            session(2, stamp=BASE + timedelta(hours=1)),
            session(3, stamp=BASE + timedelta(hours=1)),
            session(4, country_code="BR", country="Brazil", city="Manaus"),
            session(5, country_code="BR", country="Brazil", city="Manaus"),
        ]
        out = _collapse_nonhuman_preview(items, limit=8)
        self.assertEqual(len(out), 3)
        self.assertEqual(sorted(i["burst_member_count"] for i in out), [2, 2, 2])

    def test_singleton_remains_inspectable_and_preview_is_bounded(self):
        items = [
            session(i, stamp=BASE + timedelta(hours=i), user_agent=f"bot-{i}")
            for i in range(12)
        ]
        out = _collapse_nonhuman_preview(items, limit=8)
        self.assertEqual(len(out), 8)
        self.assertTrue(all(not i.get("is_burst_cluster") for i in out))
        self.assertTrue(all(i["session_id"].startswith("s-") for i in out))

    def test_existing_cluster_not_grouped_again(self):
        items = [
            session(0, is_burst_cluster=True, burst_member_count=90),
            session(1),
            session(2),
        ]
        out = _collapse_nonhuman_preview(items, limit=8)
        self.assertEqual(len(out), 2)
        self.assertEqual(sorted(i["burst_member_count"] for i in out), [2, 90])


if __name__ == "__main__":
    unittest.main()
