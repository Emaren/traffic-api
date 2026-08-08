from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
