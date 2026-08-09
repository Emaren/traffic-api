from __future__ import annotations

import unittest

from app.services.traffic.browser_events import (
    _prioritize_authenticated_story_events,
)
from app.services.traffic.classify import (
    automation_family,
    classify_request,
    is_known_singapore_cloud_browser,
)


class VisitorTruthTests(unittest.TestCase):
    def test_meta_externalagent_is_known_bot(self) -> None:
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36 "
            "(compatible; meta-externalagent/1.1)"
        )
        self.assertEqual(classify_request(ua, "/game-stats/123"), "bot")
        self.assertEqual(automation_family(ua), "Meta ExternalAgent")

    def test_visionheight_scan_is_known_automation(self) -> None:
        ua = "visionheight.com/scan Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36"
        self.assertEqual(classify_request(ua, "/"), "bot")
        self.assertEqual(automation_family(ua), "VisionHeight Scanner")

    def test_current_singapore_cloud_ranges_are_recognized(self) -> None:
        chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36"
        for ip in ("43.172.1.2", "43.173.4.5", "47.79.10.199", "47.82.51.1"):
            with self.subTest(ip=ip):
                self.assertTrue(is_known_singapore_cloud_browser(ip, "SG", "Singapore", chrome))

    def test_singapore_rule_does_not_match_ordinary_residential_range(self) -> None:
        chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36"
        self.assertFalse(is_known_singapore_cloud_browser("203.0.113.25", "SG", "Singapore", chrome))
        self.assertFalse(is_known_singapore_cloud_browser("47.82.51.1", "US", "United States", chrome))


    def test_authenticated_presence_cannot_be_starved_by_noise(self) -> None:
        noisy = [
            {
                "id": index,
                "received_at": f"2026-08-08T23:59:{59-index:02d}+00:00",
                "event_type": "page_view",
                "session_id": f"noise-{index}",
                "authenticated": False,
            }
            for index in range(1, 11)
        ]

        auth_presence = {
            "id": 100,
            "received_at": "2026-08-08T23:40:00+00:00",
            "event_type": "auth_presence",
            "session_id": "zodiac-session",
            "authenticated": True,
            "authenticated_uid": "zodiac-uid",
        }

        auth_click = {
            "id": 101,
            "received_at": "2026-08-08T23:39:59+00:00",
            "event_type": "click",
            "session_id": "zodiac-session",
            "authenticated": True,
            "authenticated_uid": "zodiac-uid",
        }

        result = _prioritize_authenticated_story_events(
            [
                *noisy,
                auth_presence,
                auth_click,
            ],
            limit=4,
        )

        self.assertEqual(
            len(result),
            4,
        )

        self.assertTrue(
            any(
                event.get("event_type")
                == "auth_presence"
                and event.get("session_id")
                == "zodiac-session"
                for event in result
            )
        )

        self.assertTrue(
            any(
                event.get("event_type")
                == "click"
                and event.get("session_id")
                == "zodiac-session"
                for event in result
            )
        )

    def test_authenticated_sessions_share_reserved_capacity(self) -> None:
        events = [
            {
                "id": 201,
                "received_at": "2026-08-08T23:50:00+00:00",
                "event_type": "auth_presence",
                "session_id": "session-a",
                "authenticated": True,
            },
            {
                "id": 202,
                "received_at": "2026-08-08T23:49:00+00:00",
                "event_type": "auth_presence",
                "session_id": "session-b",
                "authenticated": True,
            },
            {
                "id": 203,
                "received_at": "2026-08-08T23:48:00+00:00",
                "event_type": "click",
                "session_id": "session-a",
                "authenticated": True,
            },
            {
                "id": 204,
                "received_at": "2026-08-08T23:47:00+00:00",
                "event_type": "click",
                "session_id": "session-b",
                "authenticated": True,
            },
        ]

        result = _prioritize_authenticated_story_events(
            events,
            limit=4,
        )

        sessions = {
            str(
                event.get(
                    "session_id"
                )
                or ""
            )
            for event
            in result
            if event.get(
                "authenticated"
            )
        }

        self.assertEqual(
            sessions,
            {
                "session-a",
                "session-b",
            },
        )


if __name__ == "__main__":
    unittest.main()
